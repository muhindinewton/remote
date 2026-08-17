//! Peer connection lifecycle: build, negotiate, open channels, observe.
//!
//! The transport owns exactly one job — get an authenticated, observable bidirectional pipe up
//! between two peers and keep it up. Everything about *what* flows through it lives elsewhere.

use crate::channels::{ChannelSpec, CHANNELS};
use crate::ice::{self, PathKind, RoutingPreference};
use rda_proto::control::{Channel, ControlFrame, DecodeError};
use rda_proto::signaling::{IceCandidate, RelayCredentials};
use rda_telemetry::LinkTelemetry;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info, warn};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::{APIBuilder, API};
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::stats::StatsReportType;

/// Transport-layer failures.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The underlying WebRTC stack failed.
    #[error("webrtc error: {0}")]
    WebRtc(#[from] webrtc::Error),
    /// A control frame arrived that could not be parsed.
    #[error("malformed control frame: {0}")]
    Decode(#[from] DecodeError),
    /// The named channel is not open.
    #[error("channel {0:?} is not open")]
    ChannelClosed(Channel),
    /// The peer exceeded the malformed-frame budget and the session was terminated.
    #[error("peer exceeded the malformed frame budget")]
    MalformedFrameBudget,
    /// The DTLS certificate could not be generated.
    #[error("could not generate a DTLS certificate: {0}")]
    Certificate(String),
}

/// Re-exported so consumers can match on connection state without depending on `webrtc` directly.
pub use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as PeerConnectionState;

/// Which side of the session this peer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// Creates the offer.
    Controller,
    /// Answers.
    Host,
}

/// An event surfaced to the session owner.
#[derive(Debug)]
pub enum TransportEvent {
    /// A locally gathered ICE candidate that must be trickled to the peer via signaling.
    LocalCandidate(IceCandidate),
    /// ICE gathering produced its last candidate.
    GatheringComplete,
    /// The peer connection changed state.
    ConnectionState(RTCPeerConnectionState),
    /// A channel opened.
    ChannelOpen(Channel),
    /// A decoded control frame arrived.
    Frame {
        /// The channel it arrived on.
        channel: Channel,
        /// The decoded frame.
        frame: Box<ControlFrame>,
    },
    /// A frame arrived that could not be decoded. Counted against the malformed budget.
    MalformedFrame {
        /// The channel it arrived on.
        channel: Channel,
        /// Why it failed.
        error: DecodeError,
    },
    /// The session ended.
    Closed,
}

/// A live peer connection with its pre-negotiated channels.
pub struct Session {
    /// Our own DTLS certificate, retained so its fingerprint can be signed.
    certificate: webrtc::peer_connection::certificate::RTCCertificate,
    pc: Arc<RTCPeerConnection>,
    channels: Arc<RwLock<HashMap<Channel, Arc<RTCDataChannel>>>>,
    telemetry: Arc<Mutex<LinkTelemetry>>,
    role: SessionRole,
    /// Events for the session owner to drive the application state machine.
    pub events: mpsc::UnboundedReceiver<TransportEvent>,
}

impl Session {
    /// Builds a peer connection and opens every channel in the topology.
    pub async fn new(
        role: SessionRole,
        creds: &RelayCredentials,
        preference: RoutingPreference,
    ) -> Result<Self, TransportError> {
        let api = build_api()?;
        let mut config = ice::build_configuration(creds, preference);

        // Generate our own certificate rather than letting the stack do it, so the fingerprint we
        // sign in the identity binding is the fingerprint we actually present
        // (`docs/PROTOCOL.md` §4.3). Without this there is no way to obtain it.
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| TransportError::Certificate(e.to_string()))?;
        let certificate =
            webrtc::peer_connection::certificate::RTCCertificate::from_key_pair(key_pair)?;
        config.certificates = vec![certificate.clone()];

        let pc = Arc::new(api.new_peer_connection(config).await?);

        let (events_tx, events) = mpsc::unbounded_channel();
        let channels = Arc::new(RwLock::new(HashMap::new()));
        let telemetry = Arc::new(Mutex::new(LinkTelemetry::new()));

        // Both peers create every channel locally with a fixed stream id. Because they are
        // pre-negotiated, this costs no round trips and both sides agree on the mapping without
        // any in-band exchange.
        for spec in CHANNELS {
            let dc = pc
                .create_data_channel(spec.label(), Some(spec.to_init()))
                .await?;
            wire_channel(&dc, spec, events_tx.clone());
            channels.write().await.insert(spec.channel, dc);
        }

        wire_peer_connection(&pc, events_tx);

        Ok(Self {
            certificate,
            pc,
            channels,
            telemetry,
            role,
            events,
        })
    }

    /// This peer's role.
    #[must_use]
    pub fn role(&self) -> SessionRole {
        self.role
    }

    /// The SHA-256 fingerprint of our own DTLS certificate.
    ///
    /// This is what goes into the identity binding, and it is taken from the certificate object
    /// rather than from the SDP so the two cannot disagree.
    pub fn local_fingerprint(&self) -> Option<[u8; 32]> {
        self.certificate
            .get_fingerprints()
            .into_iter()
            .find(|f| f.algorithm == "sha-256")
            .and_then(|f| parse_hex_fingerprint(&f.value))
    }

    /// The SHA-256 fingerprint of the certificate the peer **actually presented** in the completed
    /// DTLS handshake.
    ///
    /// Deliberately not the value copied from the SDP: a malicious signaling server can rewrite
    /// that, and comparing against it would defeat the entire binding mechanism. Returns `None`
    /// until the handshake has completed.
    pub async fn remote_fingerprint(&self) -> Option<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let der = self.pc.dtls_transport().get_remote_certificate().await;
        if der.is_empty() {
            return None;
        }
        let mut hasher = Sha256::new();
        hasher.update(&der);
        Some(hasher.finalize().into())
    }

    /// Creates the SDP offer. Controller side only.
    pub async fn create_offer(&self) -> Result<String, TransportError> {
        let offer = self.pc.create_offer(None).await?;
        self.pc.set_local_description(offer.clone()).await?;
        Ok(offer.sdp)
    }

    /// Applies a remote offer and produces an answer. Host side only.
    pub async fn accept_offer(&self, sdp: &str) -> Result<String, TransportError> {
        self.pc
            .set_remote_description(RTCSessionDescription::offer(sdp.to_string())?)
            .await?;
        let answer = self.pc.create_answer(None).await?;
        self.pc.set_local_description(answer.clone()).await?;
        Ok(answer.sdp)
    }

    /// Applies a remote answer. Controller side only.
    pub async fn accept_answer(&self, sdp: &str) -> Result<(), TransportError> {
        self.pc
            .set_remote_description(RTCSessionDescription::answer(sdp.to_string())?)
            .await?;
        Ok(())
    }

    /// Applies a trickled remote ICE candidate.
    pub async fn add_remote_candidate(&self, cand: &IceCandidate) -> Result<(), TransportError> {
        if cand.is_end_of_candidates() {
            debug!("remote end-of-candidates");
            return Ok(());
        }
        self.pc
            .add_ice_candidate(RTCIceCandidateInit {
                candidate: cand.candidate.clone(),
                sdp_mid: cand.sdp_mid.clone(),
                sdp_mline_index: cand.sdp_mline_index,
                username_fragment: cand.username_fragment.clone(),
            })
            .await?;
        Ok(())
    }

    /// Sends a control frame on the channel its message type dictates.
    ///
    /// Routing by message type rather than by caller choice means a caller cannot accidentally put
    /// pointer motion on a reliable channel — the decision lives in one place.
    pub async fn send(&self, frame: &ControlFrame) -> Result<(), TransportError> {
        let channel = frame
            .header
            .typed()
            .map(rda_proto::control::MessageType::channel)
            .unwrap_or(Channel::Control);
        self.send_on(channel, frame).await
    }

    /// Sends a control frame on an explicit channel.
    pub async fn send_on(
        &self,
        channel: Channel,
        frame: &ControlFrame,
    ) -> Result<(), TransportError> {
        let channels = self.channels.read().await;
        let dc = channels
            .get(&channel)
            .ok_or(TransportError::ChannelClosed(channel))?;
        dc.send(&frame.encode().into()).await?;
        Ok(())
    }

    /// Sends pre-encoded bytes on a channel.
    ///
    /// Used by the handshake, which frames its own CBOR bodies, and by the video path, which has
    /// already encoded a frame it does not want to clone.
    pub async fn send_bytes(&self, channel: Channel, bytes: &[u8]) -> Result<(), TransportError> {
        let channels = self.channels.read().await;
        let dc = channels
            .get(&channel)
            .ok_or(TransportError::ChannelClosed(channel))?;
        dc.send(&bytes.to_vec().into()).await?;
        Ok(())
    }

    /// A snapshot of current link telemetry.
    pub async fn telemetry(&self) -> LinkTelemetry {
        self.telemetry.lock().await.clone()
    }

    /// Polls WebRTC statistics once and folds them into the telemetry state.
    ///
    /// Reads the *nominated* candidate pair specifically. Non-nominated pairs are still being
    /// probed, and their RTT describes a path that is not carrying traffic.
    pub async fn poll_stats(&self, now_ms: u64) {
        let report = self.pc.get_stats().await;
        let mut candidate_types: HashMap<String, String> = HashMap::new();
        // `ICECandidatePairStats` is not `Clone`, so the fields we need are lifted out during the
        // single pass rather than the struct being retained.
        let mut pair: Option<NominatedPair> = None;

        for value in report.reports.values() {
            match value {
                StatsReportType::CandidatePair(p) if p.nominated => {
                    pair = Some(NominatedPair {
                        rtt_s: p.current_round_trip_time,
                        outgoing_bitrate: p.available_outgoing_bitrate,
                        local_id: p.local_candidate_id.clone(),
                        remote_id: p.remote_candidate_id.clone(),
                    });
                }
                StatsReportType::LocalCandidate(c) | StatsReportType::RemoteCandidate(c) => {
                    candidate_types.insert(c.id.clone(), format!("{:?}", c.candidate_type));
                }
                _ => {}
            }
        }

        let Some(pair) = pair else { return };
        let mut telemetry = self.telemetry.lock().await;

        // current_round_trip_time is in seconds. A zero means "not yet measured", not "0 ms" —
        // feeding that into the estimator would poison the windowed minimum permanently.
        if pair.rtt_s > 0.0 {
            telemetry
                .rtt
                .sample((pair.rtt_s * 1000.0).round() as u32, now_ms);
        }
        if pair.outgoing_bitrate > 0.0 {
            telemetry.bwe_bps = pair.outgoing_bitrate as u32;
        }

        let local = candidate_types
            .get(&pair.local_id)
            .map(String::as_str)
            .unwrap_or("");
        let remote = candidate_types
            .get(&pair.remote_id)
            .map(String::as_str)
            .unwrap_or("");
        telemetry.relayed = PathKind::classify(
            &normalise_candidate_type(local),
            &normalise_candidate_type(remote),
        )
        .is_relayed();
    }

    /// Runs the telemetry loop until the session ends, logging one line per interval.
    ///
    /// This is the "continuously display RTT, packet loss and frame drop rates" requirement. It
    /// runs from session start rather than being switched on for debugging, because the numbers
    /// that matter here are the ones from real sessions on real paths.
    pub async fn run_telemetry_loop(self: Arc<Self>, interval_ms: u64) {
        let mut ticker = tokio::time::interval(std::time::Duration::from_millis(interval_ms));
        loop {
            ticker.tick().await;
            if self.pc.connection_state() == RTCPeerConnectionState::Closed {
                break;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            self.poll_stats(now).await;
            info!(target: "rda::telemetry", "{}", self.telemetry().await.summary());
        }
    }

    /// The current peer connection state.
    #[must_use]
    pub fn connection_state(&self) -> RTCPeerConnectionState {
        self.pc.connection_state()
    }

    /// Closes the session.
    pub async fn close(&self) -> Result<(), TransportError> {
        self.pc.close().await?;
        Ok(())
    }
}

/// The fields we need from the nominated candidate pair.
struct NominatedPair {
    /// Round-trip time in seconds, as WebRTC reports it.
    rtt_s: f64,
    outgoing_bitrate: f64,
    local_id: String,
    remote_id: String,
}

/// Parses a colon-separated lowercase hex fingerprint into raw bytes.
fn parse_hex_fingerprint(value: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let mut n = 0;
    for part in value.split(':') {
        if n >= 32 || part.len() != 2 {
            return None;
        }
        out[n] = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    (n == 32).then_some(out)
}

/// Maps webrtc-rs `CandidateType` debug names onto the ICE spec's candidate type strings.
fn normalise_candidate_type(debug_name: &str) -> String {
    match debug_name {
        "Host" => "host",
        "ServerReflexive" => "srflx",
        "PeerReflexive" => "prflx",
        "Relay" => "relay",
        other => other,
    }
    .to_string()
}

fn build_api() -> Result<API, TransportError> {
    let mut media = MediaEngine::default();
    media.register_default_codecs()?;
    let registry = register_default_interceptors(Registry::new(), &mut media)?;
    Ok(APIBuilder::new()
        .with_media_engine(media)
        .with_interceptor_registry(registry)
        .build())
}

fn wire_channel(
    dc: &Arc<RTCDataChannel>,
    spec: ChannelSpec,
    events: mpsc::UnboundedSender<TransportEvent>,
) {
    let channel = spec.channel;

    let open_events = events.clone();
    dc.on_open(Box::new(move || {
        let _ = open_events.send(TransportEvent::ChannelOpen(channel));
        Box::pin(async {})
    }));

    dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let events = events.clone();
        Box::pin(async move {
            let event = match ControlFrame::decode(&msg.data) {
                Ok(frame) => TransportEvent::Frame {
                    channel,
                    frame: Box::new(frame),
                },
                Err(error) => {
                    // Never fatal here. The malformed-frame budget is enforced by the session
                    // owner, so genuine version skew degrades gracefully while a parser-probing
                    // attacker still gets cut off.
                    debug!(?channel, %error, "malformed control frame");
                    TransportEvent::MalformedFrame { channel, error }
                }
            };
            let _ = events.send(event);
        })
    }));
}

fn wire_peer_connection(
    pc: &Arc<RTCPeerConnection>,
    events: mpsc::UnboundedSender<TransportEvent>,
) {
    let cand_events = events.clone();
    pc.on_ice_candidate(Box::new(move |candidate| {
        let events = cand_events.clone();
        Box::pin(async move {
            let event = match candidate {
                Some(c) => match c.to_json() {
                    Ok(json) => TransportEvent::LocalCandidate(IceCandidate {
                        candidate: json.candidate,
                        sdp_mid: json.sdp_mid,
                        sdp_mline_index: json.sdp_mline_index,
                        username_fragment: json.username_fragment,
                    }),
                    Err(e) => {
                        warn!(error = %e, "could not serialise local candidate");
                        return;
                    }
                },
                // A None candidate is the end-of-gathering marker.
                None => TransportEvent::GatheringComplete,
            };
            let _ = events.send(event);
        })
    }));

    pc.on_peer_connection_state_change(Box::new(move |state| {
        let events = events.clone();
        Box::pin(async move {
            info!(?state, "peer connection state changed");
            let _ = events.send(TransportEvent::ConnectionState(state));
            if matches!(
                state,
                RTCPeerConnectionState::Closed | RTCPeerConnectionState::Failed
            ) {
                let _ = events.send(TransportEvent::Closed);
            }
        })
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stun_only() -> RelayCredentials {
        RelayCredentials {
            ice_servers: vec![rda_proto::signaling::IceServer {
                urls: vec!["stun:stun.l.google.com:19302".into()],
                username: None,
                credential: None,
            }],
            ttl_s: 3600,
            preferred_order: vec![],
        }
    }

    #[test]
    fn candidate_type_names_map_to_ice_strings() {
        assert_eq!(normalise_candidate_type("Host"), "host");
        assert_eq!(normalise_candidate_type("ServerReflexive"), "srflx");
        assert_eq!(normalise_candidate_type("PeerReflexive"), "prflx");
        assert_eq!(normalise_candidate_type("Relay"), "relay");
    }

    #[tokio::test]
    async fn a_session_opens_every_channel_in_the_topology() {
        let session = Session::new(
            SessionRole::Controller,
            &stun_only(),
            RoutingPreference::PreferDirect,
        )
        .await
        .expect("peer connection must build");
        assert_eq!(session.channels.read().await.len(), CHANNELS.len());
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn offer_contains_the_datachannel_media_line() {
        let session = Session::new(
            SessionRole::Controller,
            &stun_only(),
            RoutingPreference::PreferDirect,
        )
        .await
        .unwrap();
        let offer = session.create_offer().await.unwrap();
        assert!(
            offer.contains("m=application"),
            "offer must carry the SCTP m-line"
        );
        assert!(offer.contains("webrtc-datachannel"));
        assert!(
            offer.contains("a=fingerprint:"),
            "DTLS fingerprint must be present to bind"
        );
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn sending_on_a_closed_session_errors_rather_than_panicking() {
        let session = Session::new(
            SessionRole::Controller,
            &stun_only(),
            RoutingPreference::PreferDirect,
        )
        .await
        .unwrap();
        session.close().await.unwrap();
        let frame = ControlFrame::new(rda_proto::control::Payload::Ping { token: 1 }, 0, 0);
        // The channel exists but the transport is gone; this must surface as an error.
        assert!(session.send(&frame).await.is_err());
    }
}
