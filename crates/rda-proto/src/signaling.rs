//! Signaling protocol over WebSocket — `docs/PROTOCOL.md` §3.
//!
//! JSON rather than a compact binary format: signaling is low-volume and one-shot per session, and
//! being able to read a trace in a terminal is worth more than the bytes. The hot path is binary
//! already ([`crate::control`]).
//!
//! The server is **untrusted** with session content. It routes these messages; it cannot forge a
//! session, because the DTLS fingerprint binding in §4.3 is verified peer-to-peer after the
//! transport is up.

use crate::caps::{Capabilities, SessionCaps};
use crate::ids::DeviceId;
use serde::{Deserialize, Serialize};

/// Domain separator for the registration challenge signature.
pub const REGISTER_DOMAIN: &[u8] = b"RDA-v1-register";

/// Length of the server-issued registration nonce, in bytes.
pub const NONCE_LEN: usize = 16;

/// The envelope every signaling message shares — `docs/PROTOCOL.md` §3.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Protocol major version. Must be [`crate::PROTO_VERSION`].
    pub v: u8,
    /// Message identifier, unique per connection. Correlates an `error` with what caused it.
    pub id: String,
    /// Sender's Unix time in milliseconds. Advisory: never used for a security decision, because
    /// it is entirely attacker-controlled.
    pub ts: u64,
    /// Session identifier, absent for pre-session messages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// The message itself. `#[serde(flatten)]` puts `t` and `p` at the envelope level.
    #[serde(flatten)]
    pub msg: Message,
}

impl Envelope {
    /// Wraps a message with a fresh id and the supplied timestamp.
    #[must_use]
    pub fn new(id: impl Into<String>, ts_ms: u64, sid: Option<String>, msg: Message) -> Self {
        Self {
            v: crate::PROTO_VERSION,
            id: id.into(),
            ts: ts_ms,
            sid,
            msg,
        }
    }

    /// Parses an envelope, rejecting anything above the size cap before deserialising.
    ///
    /// The cap is checked here rather than only at the transport so that every entry point gets it.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SignalingError> {
        if bytes.len() > crate::MAX_SIGNALING_MESSAGE {
            return Err(SignalingError::TooLarge(bytes.len()));
        }
        let env: Envelope = serde_json::from_slice(bytes)?;
        if env.v != crate::PROTO_VERSION {
            return Err(SignalingError::BadVersion(env.v));
        }
        Ok(env)
    }

    /// Serialises to JSON bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, SignalingError> {
        Ok(serde_json::to_vec(self)?)
    }
}

/// Signaling layer failures.
#[derive(Debug, thiserror::Error)]
pub enum SignalingError {
    /// Message exceeded [`crate::MAX_SIGNALING_MESSAGE`].
    #[error("signaling message of {0} bytes exceeds the size cap")]
    TooLarge(usize),
    /// Unsupported protocol major version.
    #[error("unsupported signaling protocol version {0}")]
    BadVersion(u8),
    /// Malformed JSON or unknown message shape.
    #[error("malformed signaling message: {0}")]
    Json(#[from] serde_json::Error),
}

/// Every signaling message — `docs/PROTOCOL.md` §3.3.
///
/// Tagged by `t` with the body under `p`, matching the wire format exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", content = "p", rename_all = "snake_case")]
pub enum Message {
    /// Server → client, sent immediately on connect and before any client message is accepted.
    Challenge(Challenge),
    /// Client → server.
    Register(Register),
    /// Server → client.
    RegisterAck(RegisterAck),
    /// Client → server, keepalive.
    Heartbeat,
    /// Server → client, keepalive response.
    HeartbeatAck,
    /// Controller → server → host.
    ConnectRequest(ConnectRequest),
    /// Host → server → controller.
    ConnectResponse(ConnectResponse),
    /// SDP offer.
    Offer(SdpPayload),
    /// SDP answer.
    Answer(SdpPayload),
    /// Trickled ICE candidate.
    IceCandidate(IceCandidate),
    /// Request a fresh offer/answer with new ICE credentials.
    IceRestart,
    /// This peer has opened all of its pre-negotiated DataChannels and can be sent to.
    ///
    /// Pre-negotiated channels have fixed stream ids, and SCTP creates a stream implicitly when
    /// data arrives on an id it does not know. A peer that sends before the other has opened its
    /// end therefore *destroys* that channel: the far side's own open fails with "there already
    /// exists a stream with identifier", and nothing is ever wired to it. The failure is silent —
    /// the sender sees a healthy connection and the receiver never gets a byte.
    ///
    /// Signaling is a separate, already-established, reliable channel, so announcing readiness
    /// there settles the ordering with no race. It costs one signaling hop, which on a 220 ms
    /// corridor is the price of a session that works.
    ChannelsReady,
    /// Server → both peers: STUN/TURN servers and short-lived credentials.
    RelayCredentials(RelayCredentials),
    /// The other peer went away.
    PeerGone(PeerGone),
    /// Something failed.
    Error(ErrorPayload),
}

/// Server-issued registration challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// 16 random bytes, base64url. Single-use, expires in 60 seconds.
    pub nonce: String,
    /// Server's Unix time in milliseconds, so a client can detect gross clock skew.
    pub server_time: u64,
    /// Clients below this version should warn their user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_client_version: Option<String>,
}

/// The role a device is registering as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Shares its screen and accepts input.
    Host,
    /// Views and controls.
    Controller,
    /// Both, depending on the session.
    Both,
}

impl Role {
    /// Returns `true` if a device in this role can be dialled as a connection target.
    #[must_use]
    pub fn is_dialable(self) -> bool {
        matches!(self, Role::Host | Role::Both)
    }
}

/// Client registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Register {
    /// Identifier derived from `pubkey`. The server re-derives and compares.
    pub device_id: DeviceId,
    /// Ed25519 public key, base64url, 32 bytes.
    pub pubkey: String,
    /// Ed25519 signature over the challenge, base64url, 64 bytes.
    pub sig: String,
    /// What this device is registering as.
    pub role: Role,
    /// Advertised capabilities.
    #[serde(default)]
    pub caps: Capabilities,
    /// Free-form agent string for diagnostics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// PoP code → median RTT in milliseconds, from the client's own probes. Feeds relay selection.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub pop_rtt: std::collections::BTreeMap<String, u32>,
}

impl Register {
    /// Rebuilds the exact byte string the signature covers.
    ///
    /// `"RDA-v1-register" ‖ 0x00 ‖ nonce ‖ device_id ‖ role`. The nonce binds the signature to one
    /// server-issued challenge, so a captured registration cannot be replayed.
    #[must_use]
    pub fn signing_input(nonce: &[u8], device_id: &DeviceId, role: Role) -> Vec<u8> {
        let role_str = match role {
            Role::Host => "host",
            Role::Controller => "controller",
            Role::Both => "both",
        };
        let mut buf = Vec::with_capacity(REGISTER_DOMAIN.len() + 1 + nonce.len() + 24);
        buf.extend_from_slice(REGISTER_DOMAIN);
        buf.push(0x00);
        buf.extend_from_slice(nonce);
        buf.extend_from_slice(device_id.as_str().as_bytes());
        buf.extend_from_slice(role_str.as_bytes());
        buf
    }
}

/// Successful registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAck {
    /// Confirmed device identifier.
    pub device_id: DeviceId,
    /// How often the client must heartbeat.
    pub heartbeat_interval_s: u32,
    /// How long the registration survives without a heartbeat.
    pub session_ttl_s: u32,
}

/// How the controller intends to authenticate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// Attended: a human at the host reads a PIN aloud. SPAKE2 over the PIN.
    Pin,
    /// Unattended: a signed token bound to the controller's identity key.
    Token,
}

/// A controller asking to connect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectRequest {
    /// Host device to dial.
    pub target: DeviceId,
    /// Controller's identity key, so the host can consult its address book before prompting a human.
    pub from_pubkey: String,
    /// Human-readable label. Attacker-controlled: display it as untrusted text, never interpolate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_label: Option<String>,
    /// Attended or unattended.
    pub auth_mode: AuthMode,
    /// Unattended token, required when `auth_mode` is [`AuthMode::Token`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Capabilities the controller would like. The host grants a subset, never a superset.
    #[serde(default)]
    pub requested_caps: Vec<String>,
}

/// Outcome of a connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectStatus {
    /// The host accepted; proceed to SDP exchange.
    Accepted,
    /// A human at the host declined.
    Rejected,
    /// The host is already in a session and does not permit concurrency.
    Busy,
    /// No such device, or it is not connected.
    Offline,
    /// The caller is not permitted to connect to this host.
    Unauthorized,
    /// No human responded within the consent window.
    Timeout,
}

impl ConnectStatus {
    /// Returns `true` if this outcome must be indistinguishable from [`ConnectStatus::Offline`]
    /// to an unknown caller.
    ///
    /// Leaking "this device exists but you may not have it" turns the ID space into an oracle an
    /// attacker can enumerate.
    #[must_use]
    pub fn is_existence_sensitive(self) -> bool {
        matches!(self, ConnectStatus::Offline | ConnectStatus::Unauthorized)
    }
}

/// The host's answer to a [`ConnectRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectResponse {
    /// Outcome.
    pub status: ConnectStatus,
    /// Session identifier, present when accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Capabilities actually granted. Always a subset of what was requested.
    #[serde(default)]
    pub granted_caps: Vec<String>,
    /// Short machine-readable reason when not accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ConnectResponse {
    /// Builds an acceptance, clamping the request against what the host permits.
    #[must_use]
    pub fn accept(
        session_id: impl Into<String>,
        requested: &[String],
        allowed: SessionCaps,
    ) -> Self {
        let granted = SessionCaps::from_names(requested).clamp_to(allowed);
        Self {
            status: ConnectStatus::Accepted,
            session_id: Some(session_id.into()),
            granted_caps: granted.to_names().into_iter().map(String::from).collect(),
            reason: None,
        }
    }

    /// Builds a refusal.
    #[must_use]
    pub fn refuse(status: ConnectStatus, reason: Option<&str>) -> Self {
        Self {
            status,
            session_id: None,
            granted_caps: Vec::new(),
            reason: reason.map(str::to_owned),
        }
    }
}

/// An SDP offer or answer, in plaintext or sealed to the peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdpPayload {
    /// Plaintext SDP. Present unless `sealed` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdp: Option<String>,
    /// SDP encrypted to the peer's key, so the signaling server routes ciphertext it cannot read.
    /// Only usable between peers that already know each other's identity keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<SealedSdp>,
}

impl SdpPayload {
    /// Wraps a plaintext SDP.
    #[must_use]
    pub fn plain(sdp: impl Into<String>) -> Self {
        Self {
            sdp: Some(sdp.into()),
            sealed: None,
        }
    }
}

/// SDP sealed to the recipient's X25519 key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedSdp {
    /// Algorithm identifier, currently `x25519-chacha20poly1305`.
    pub alg: String,
    /// Ephemeral public key, base64url.
    pub epk: String,
    /// Ciphertext, base64url.
    pub ct: String,
    /// AEAD nonce, base64url.
    pub nonce: String,
}

/// A trickled ICE candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidate {
    /// Candidate line. An empty string signals end-of-candidates.
    pub candidate: String,
    /// Media stream identification.
    #[serde(default, rename = "sdpMid", skip_serializing_if = "Option::is_none")]
    pub sdp_mid: Option<String>,
    /// Media line index.
    #[serde(
        default,
        rename = "sdpMLineIndex",
        skip_serializing_if = "Option::is_none"
    )]
    pub sdp_mline_index: Option<u16>,
    /// ICE ufrag this candidate belongs to, so a candidate from a superseded gathering round is
    /// not applied after an ICE restart.
    #[serde(
        default,
        rename = "usernameFragment",
        skip_serializing_if = "Option::is_none"
    )]
    pub username_fragment: Option<String>,
}

impl IceCandidate {
    /// Returns `true` if this is the end-of-candidates marker.
    #[must_use]
    pub fn is_end_of_candidates(&self) -> bool {
        self.candidate.is_empty()
    }
}

/// One ICE server entry, matching the WebRTC `RTCIceServer` shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceServer {
    /// STUN/TURN URLs.
    pub urls: Vec<String>,
    /// TURN username: `"<unix_expiry>:<session_id>"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// TURN credential: base64 HMAC-SHA1 of the username under the shared secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

/// STUN/TURN configuration and short-lived credentials for one session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayCredentials {
    /// Servers to use, in the order the oracle recommends.
    pub ice_servers: Vec<IceServer>,
    /// Credential lifetime in seconds. Never more than one hour.
    pub ttl_s: u32,
    /// PoP codes ranked best-first for this specific pair of peers.
    #[serde(default)]
    pub preferred_order: Vec<String>,
}

/// Maximum number of relay PoPs a client may gather candidates from.
///
/// Every extra relay candidate multiplies the ICE connectivity-check matrix, and on a 220 ms path
/// each check round costs a fifth of a second. Two is the budget (`docs/PROTOCOL.md` §3.3).
pub const MAX_RELAY_POPS: usize = 2;

/// Why the peer disappeared.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerGone {
    /// One of `disconnected`, `replaced`, `evicted`, `shutdown`.
    pub reason: String,
}

/// An error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    /// Numeric code from `docs/PROTOCOL.md` Appendix B.
    pub code: u16,
    /// Human-readable detail. Diagnostics only; never parse it.
    pub message: String,
    /// The `id` of the message that caused this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    /// Seconds to wait before retrying, for rate-limit responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u32>,
}

/// Error codes — `docs/PROTOCOL.md` Appendix B.
#[allow(missing_docs)]
pub mod error_code {
    pub const BAD_REQUEST: u16 = 4000;
    pub const UNSUPPORTED_VERSION: u16 = 4001;
    pub const MESSAGE_TOO_LARGE: u16 = 4002;
    pub const NOT_REGISTERED: u16 = 4100;
    pub const BAD_SIGNATURE: u16 = 4101;
    pub const BAD_NONCE: u16 = 4102;
    pub const UNKNOWN_TARGET: u16 = 4103;
    pub const TARGET_BUSY: u16 = 4104;
    pub const REJECTED: u16 = 4105;
    pub const CONSENT_TIMEOUT: u16 = 4106;
    pub const AUTH_FAILED: u16 = 4200;
    pub const AUTH_ATTEMPTS_EXCEEDED: u16 = 4201;
    pub const TOKEN_EXPIRED: u16 = 4202;
    pub const TOKEN_REVOKED: u16 = 4203;
    /// DTLS fingerprint binding invalid — a possible MITM. Must be surfaced to the user as a
    /// security warning, never as a generic connection failure.
    pub const BINDING_FAILED: u16 = 4204;
    pub const CAPABILITY_DENIED: u16 = 4300;
    pub const RATE_LIMITED: u16 = 4301;
    pub const MALFORMED_FRAME_LIMIT: u16 = 4302;
    pub const INTERNAL: u16 = 5000;
    pub const RELAY_UNAVAILABLE: u16 = 5001;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps;

    fn envelope(msg: Message) -> Envelope {
        Envelope::new("01J8XKQ7ZP3M4N5R6S7T8V9W0X", 1_755_244_800_123, None, msg)
    }

    #[test]
    fn envelope_uses_the_documented_wire_shape() {
        let env = envelope(Message::Heartbeat);
        let json: serde_json::Value = serde_json::from_slice(&env.to_vec().unwrap()).unwrap();
        assert_eq!(json["v"], 1);
        assert_eq!(json["t"], "heartbeat");
        assert!(
            json.get("sid").is_none(),
            "absent sid must not serialise as null"
        );
    }

    #[test]
    fn message_types_round_trip() {
        let msgs = vec![
            Message::Challenge(Challenge {
                nonce: "c3RhdGljLW5vbmNlLTE2Qg".into(),
                server_time: 1,
                min_client_version: None,
            }),
            Message::Heartbeat,
            Message::IceRestart,
            Message::Offer(SdpPayload::plain("v=0\r\n")),
            Message::IceCandidate(IceCandidate {
                candidate: "candidate:1 1 udp 1 10.0.0.1 1 typ host".into(),
                sdp_mid: Some("0".into()),
                sdp_mline_index: Some(0),
                username_fragment: Some("Xy7Q".into()),
            }),
            Message::PeerGone(PeerGone {
                reason: "disconnected".into(),
            }),
        ];
        for m in msgs {
            let bytes = envelope(m).to_vec().unwrap();
            Envelope::from_slice(&bytes).expect("must round trip");
        }
    }

    #[test]
    fn ice_candidate_keeps_its_webrtc_field_names() {
        // These names cross into JavaScript-shaped APIs; renaming them silently breaks interop.
        let c = IceCandidate {
            candidate: "x".into(),
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
            username_fragment: None,
        };
        let json = serde_json::to_value(&c).unwrap();
        assert!(json.get("sdpMid").is_some());
        assert!(json.get("sdpMLineIndex").is_some());
    }

    #[test]
    fn oversized_messages_are_rejected_before_parsing() {
        let big = vec![b'x'; crate::MAX_SIGNALING_MESSAGE + 1];
        assert!(matches!(
            Envelope::from_slice(&big),
            Err(SignalingError::TooLarge(_))
        ));
    }

    #[test]
    fn wrong_version_is_rejected() {
        let raw = br#"{"v":9,"id":"a","ts":0,"t":"heartbeat"}"#;
        assert!(matches!(
            Envelope::from_slice(raw),
            Err(SignalingError::BadVersion(9))
        ));
    }

    #[test]
    fn unknown_fields_are_tolerated() {
        // Forward compatibility: a newer peer's extra fields must not be fatal.
        let raw = br#"{"v":1,"id":"a","ts":0,"t":"heartbeat","future_field":42}"#;
        assert!(Envelope::from_slice(raw).is_ok());
    }

    #[test]
    fn signing_input_is_bound_to_nonce_and_role() {
        let id = crate::ids::device_id_from_pubkey(&[3u8; 32]);
        let a = Register::signing_input(b"nonce-a", &id, Role::Host);
        let b = Register::signing_input(b"nonce-b", &id, Role::Host);
        let c = Register::signing_input(b"nonce-a", &id, Role::Controller);
        assert_ne!(
            a, b,
            "a captured registration must not replay under a new nonce"
        );
        assert_ne!(a, c, "role must be covered by the signature");
        assert!(a.starts_with(REGISTER_DOMAIN));
    }

    #[test]
    fn accepting_a_connection_clamps_the_request() {
        let requested = vec!["view".to_string(), "input".to_string(), "file".to_string()];
        let allowed = caps::SessionCaps {
            view: true,
            input: true,
            ..Default::default()
        };
        let resp = ConnectResponse::accept("sess_1", &requested, allowed);
        assert_eq!(resp.status, ConnectStatus::Accepted);
        assert!(resp.granted_caps.contains(&"input".to_string()));
        assert!(
            !resp.granted_caps.contains(&"file".to_string()),
            "a host must never grant more than it permits"
        );
    }

    #[test]
    fn offline_and_unauthorized_are_both_existence_sensitive() {
        assert!(ConnectStatus::Offline.is_existence_sensitive());
        assert!(ConnectStatus::Unauthorized.is_existence_sensitive());
        assert!(!ConnectStatus::Busy.is_existence_sensitive());
    }
}
