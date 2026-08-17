//! Driving a peer connection to `Connected` over the signaling server.
//!
//! This is the seam Phases 2 and 3 each tested from their own side and neither one crossed: the
//! signaling client knows how to exchange SDP, the transport knows how to consume it, and something
//! has to pump messages between them until ICE settles.
//!
//! Two details here are specific to a 220 ms path:
//!
//! **Candidates are trickled, and applied the moment they arrive.** Waiting for gathering to
//! complete before sending the offer costs a full extra round trip, which on this corridor is a
//! visible fifth of a second added to every connection.
//!
//! **A candidate that arrives before the remote description is buffered, not dropped.** With
//! trickle ICE the peer starts sending candidates as soon as it has them, which is routinely before
//! its answer has come back through the server. Dropping those is the classic cause of a connection
//! that works on a LAN and fails across an ocean, because on a LAN the race never happens.

use rda_proto::signaling::{
    ConnectRequest, ConnectResponse, ConnectStatus, IceCandidate, Message, RelayCredentials,
    SdpPayload,
};
use rda_signal_client::SignalConnection;
use rda_transport::PeerConnectionState;
use rda_transport::{RoutingPreference, Session, SessionRole, TransportEvent};
use std::time::Duration;
use tracing::{debug, info, warn};

/// How long to wait for the whole negotiation before giving up.
///
/// Generous: at 250 ms RTT the signaling exchange alone is several round trips before ICE even
/// starts, and a user would rather wait than be told to try again.
pub const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the channels get to open once the peer connection is up.
///
/// Separate from [`NEGOTIATION_TIMEOUT`] because it measures something else. ICE may legitimately
/// take twenty seconds to find a path; SCTP, once DTLS is done, opens its streams in milliseconds.
/// Holding a failed open against the full negotiation budget makes the user wait half a minute to
/// learn about something that was decided almost immediately.
pub const CHANNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a negotiation failed.
#[derive(Debug, thiserror::Error)]
pub enum NegotiateError {
    /// The signaling connection failed.
    #[error("signaling error: {0}")]
    Signaling(String),
    /// The transport failed.
    #[error("transport error: {0}")]
    Transport(#[from] rda_transport::TransportError),
    /// The peer refused, or was not reachable.
    #[error("peer refused the connection: {0:?}")]
    Refused(ConnectStatus),
    /// Nothing completed within [`NEGOTIATION_TIMEOUT`].
    #[error("negotiation timed out after {}s", NEGOTIATION_TIMEOUT.as_secs())]
    TimedOut,
    /// ICE could not find a working path.
    #[error("ICE failed to establish a path")]
    IceFailed,
    /// The signaling connection closed mid-negotiation.
    #[error("signaling connection closed during negotiation")]
    Closed,
    /// The peer connection came up but some data channels never opened.
    #[error(
        "the data channels did not all open ({0:?} still closed); this session cannot proceed"
    )]
    ChannelsNotOpen(Vec<rda_proto::control::Channel>),
}

impl NegotiateError {
    /// Whether retrying the whole negotiation is likely to succeed.
    ///
    /// The channel-open race and a lost ICE path are both timing accidents rather than
    /// misconfiguration, and both usually clear on a second attempt. A refusal is a decision, and
    /// repeating it only wastes the user's time.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            NegotiateError::ChannelsNotOpen(_)
                | NegotiateError::TimedOut
                | NegotiateError::IceFailed
                | NegotiateError::Closed
        )
    }
}

/// A negotiated session, with the identifiers the handshake needs.
pub struct Negotiated {
    /// The connected transport.
    pub session: Session,
    /// The session identifier the server assigned.
    pub session_id: String,
}

/// Dials a host and negotiates a connected session. Controller side.
pub async fn connect_to_host(
    signal: &mut SignalConnection,
    target: &rda_proto::ids::DeviceId,
    our_pubkey_b64: String,
    label: Option<String>,
) -> Result<Negotiated, NegotiateError> {
    signal
        .send(
            None,
            Message::ConnectRequest(ConnectRequest {
                target: target.clone(),
                from_pubkey: our_pubkey_b64,
                from_label: label,
                auth_mode: rda_proto::signaling::AuthMode::Pin,
                token: None,
                requested_caps: vec!["view".into(), "input".into()],
            }),
        )
        .map_err(|e| NegotiateError::Signaling(e.to_string()))?;

    // The server answers with relay credentials and the host answers with an acceptance. Both are
    // needed before a peer connection can be built, and they can arrive in either order.
    let mut credentials: Option<RelayCredentials> = None;
    let mut session_id: Option<String> = None;

    let deadline = tokio::time::Instant::now() + NEGOTIATION_TIMEOUT;
    while credentials.is_none() || session_id.is_none() {
        let envelope = next_envelope(signal, deadline).await?;
        if let Some(sid) = envelope.sid.clone() {
            session_id.get_or_insert(sid);
        }
        match envelope.msg {
            Message::RelayCredentials(c) => credentials = Some(c),
            Message::ConnectResponse(r) if r.status != ConnectStatus::Accepted => {
                return Err(NegotiateError::Refused(r.status));
            }
            Message::ConnectResponse(r) => {
                if let Some(sid) = r.session_id {
                    session_id = Some(sid);
                }
            }
            other => debug!(?other, "ignoring a message while waiting to negotiate"),
        }
    }

    let session_id = session_id.expect("loop exits only once set");
    let credentials = credentials.expect("loop exits only once set");
    info!(%session_id, "building the peer connection");

    let mut session = Session::new(
        SessionRole::Controller,
        &credentials,
        RoutingPreference::PreferDirect,
    )
    .await?;

    let offer = session.create_offer().await?;
    signal
        .send(
            Some(session_id.clone()),
            Message::Offer(SdpPayload::plain(offer)),
        )
        .map_err(|e| NegotiateError::Signaling(e.to_string()))?;

    pump(signal, &mut session, &session_id, deadline, false).await?;
    Ok(Negotiated {
        session,
        session_id,
    })
}

/// Accepts an incoming connection and negotiates a session. Host side.
///
/// The caller has already seen the `connect_request` and decided to accept; this takes it from
/// there.
pub async fn accept_connection(
    signal: &mut SignalConnection,
    session_id: String,
    credentials: RelayCredentials,
    granted: rda_proto::caps::SessionCaps,
) -> Result<Negotiated, NegotiateError> {
    signal
        .send(
            Some(session_id.clone()),
            Message::ConnectResponse(ConnectResponse::accept(
                session_id.clone(),
                &granted
                    .to_names()
                    .into_iter()
                    .map(String::from)
                    .collect::<Vec<_>>(),
                granted,
            )),
        )
        .map_err(|e| NegotiateError::Signaling(e.to_string()))?;

    let mut session = Session::new(
        SessionRole::Host,
        &credentials,
        RoutingPreference::PreferDirect,
    )
    .await?;

    let deadline = tokio::time::Instant::now() + NEGOTIATION_TIMEOUT;
    pump(signal, &mut session, &session_id, deadline, true).await?;
    Ok(Negotiated {
        session,
        session_id,
    })
}

/// Pumps signaling and transport events until the peer connection is up.
///
/// `expect_offer` distinguishes the two sides: the host waits for an offer and replies with an
/// answer, the controller waits for the answer to the offer it already sent.
async fn pump(
    signal: &mut SignalConnection,
    session: &mut Session,
    session_id: &str,
    deadline: tokio::time::Instant,
    expect_offer: bool,
) -> Result<(), NegotiateError> {
    // Candidates that arrived before the remote description was set. Applying one early is an error
    // in every WebRTC stack, and dropping it is the bug that only shows up over a slow link.
    let mut pending: Vec<IceCandidate> = Vec::new();
    let mut remote_described = !expect_offer;
    let mut connected = false;

    // `Connected` means ICE and DTLS are up, not that anything is sendable yet: the SCTP
    // association still has to come up underneath, and pre-negotiated channels report open only
    // then. Returning on `Connected` alone races the handshake against SCTP and loses often enough
    // to look like a flaky network.
    //
    // Every channel is waited for, not just the control channel. A channel that failed to open is
    // dead for the session ([`Session::unopened_channels`] explains how that happens), and finding
    // that out when the first video frame vanishes is far worse than finding out here.
    let mut all_open = false;
    let mut connected_at: Option<tokio::time::Instant> = None;

    while !(connected && all_open) {
        // Once the transport is up, the channels are a separate and much shorter deadline.
        if let Some(since) = connected_at {
            if since.elapsed() >= CHANNEL_OPEN_TIMEOUT {
                let pending = session.unopened_channels().await;
                if !pending.is_empty() {
                    return Err(NegotiateError::ChannelsNotOpen(pending));
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            // Name the actual problem. "Timed out" sent one investigation after the PIN and another
            // after a stuck session, when the truth was that a data channel never opened.
            let pending = session.unopened_channels().await;
            return Err(if connected && !pending.is_empty() {
                NegotiateError::ChannelsNotOpen(pending)
            } else {
                NegotiateError::TimedOut
            });
        }

        tokio::select! {
            biased;

            envelope = signal.inbox.recv() => {
                let Some(envelope) = envelope else { return Err(NegotiateError::Closed) };
                match envelope.msg {
                    Message::Offer(sdp) if expect_offer => {
                        let Some(sdp) = sdp.sdp else { continue };
                        let answer = session.accept_offer(&sdp).await?;
                        signal
                            .send(Some(session_id.to_string()), Message::Answer(SdpPayload::plain(answer)))
                            .map_err(|e| NegotiateError::Signaling(e.to_string()))?;
                        remote_described = true;
                        drain_pending(session, &mut pending).await;
                    }
                    Message::Answer(sdp) if !expect_offer => {
                        let Some(sdp) = sdp.sdp else { continue };
                        session.accept_answer(&sdp).await?;
                        remote_described = true;
                        drain_pending(session, &mut pending).await;
                    }
                    Message::IceCandidate(candidate) => {
                        if remote_described {
                            debug!(candidate = %candidate.candidate, "remote candidate");
                            if let Err(e) = session.add_remote_candidate(&candidate).await {
                                debug!(error = %e, "discarding an unusable remote candidate");
                            }
                        } else {
                            // Buffered rather than dropped: with trickle ICE the peer starts
                            // sending candidates before its description has come back through the
                            // server, and that race is routine on a slow path.
                            pending.push(candidate);
                        }
                    }
                    Message::PeerGone(reason) => {
                        warn!(?reason, "peer left during negotiation");
                        return Err(NegotiateError::Closed);
                    }
                    other => debug!(?other, "ignoring a message during negotiation"),
                }
            }

            event = session.events.recv() => {
                match event {
                    Some(TransportEvent::LocalCandidate(candidate)) => {
                        debug!(candidate = %candidate.candidate, "local candidate");
                        signal
                            .send(Some(session_id.to_string()), Message::IceCandidate(candidate))
                            .map_err(|e| NegotiateError::Signaling(e.to_string()))?;
                    }
                    Some(TransportEvent::GatheringComplete) => {
                        debug!("local gathering complete");
                    }
                    Some(TransportEvent::ChannelOpen(channel)) => {
                        debug!(?channel, "channel open");
                        all_open = session.unopened_channels().await.is_empty();
                    }
                    Some(TransportEvent::ConnectionState(state)) => {
                        info!(?state, "peer connection state");
                        match state {
                            PeerConnectionState::Connected => {
                                connected = true;
                                connected_at.get_or_insert_with(tokio::time::Instant::now);
                            }
                            PeerConnectionState::Failed => return Err(NegotiateError::IceFailed),
                            _ => {}
                        }
                    }
                    Some(_) => {}
                    None => return Err(NegotiateError::Closed),
                }
            }

            // Also the fallback for the swallowed-open case: webrtc-rs emits no event when a
            // channel fails to open, so the only way to notice is to look.
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                if connected {
                    all_open = session.unopened_channels().await.is_empty();
                }
            }
        }
    }
    Ok(())
}

async fn drain_pending(session: &mut Session, pending: &mut Vec<IceCandidate>) {
    for candidate in pending.drain(..) {
        if let Err(e) = session.add_remote_candidate(&candidate).await {
            debug!(error = %e, "discarding a buffered candidate");
        }
    }
}

/// Reads the next signaling envelope, respecting the deadline.
async fn next_envelope(
    signal: &mut SignalConnection,
    deadline: tokio::time::Instant,
) -> Result<rda_proto::signaling::Envelope, NegotiateError> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err(NegotiateError::TimedOut);
    }
    match tokio::time::timeout(remaining, signal.inbox.recv()).await {
        Ok(Some(envelope)) => Ok(envelope),
        Ok(None) => Err(NegotiateError::Closed),
        Err(_) => Err(NegotiateError::TimedOut),
    }
}
