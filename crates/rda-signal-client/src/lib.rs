//! Signaling client: connects, answers the registration challenge, and stays connected.
//!
//! Reconnection is a first-class concern rather than an afterthought. On the corridor this system
//! targets, residential and mobile Kenyan connections change NAT bindings and drop sockets
//! routinely; a client that treats disconnection as exceptional spends most of its life in the
//! exceptional path.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod backoff;

use base64::Engine as _;
pub use ed25519_dalek::SigningKey;

use ed25519_dalek::Signer;
use futures_util::{SinkExt, StreamExt};
use rda_proto::caps::Capabilities;
use rda_proto::ids::{device_id_from_pubkey, DeviceId};
use rda_proto::signaling::{Envelope, Message, Register, Role, NONCE_LEN};
use std::collections::BTreeMap;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{debug, info, warn};

pub use backoff::Backoff;

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// Client-side failures.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Transport failure.
    ///
    /// Boxed: tungstenite's error type is large, and an unboxed variant would inflate every
    /// `Result` on the hot send path.
    #[error("websocket error: {0}")]
    WebSocket(#[from] Box<tokio_tungstenite::tungstenite::Error>),
    /// Protocol framing failure.
    #[error("signaling error: {0}")]
    Signaling(#[from] rda_proto::signaling::SignalingError),
    /// The server closed the connection.
    #[error("connection closed by server")]
    Closed,
    /// The server did not open with a challenge, so it is not speaking this protocol.
    #[error("expected a challenge, got something else")]
    NoChallenge,
    /// The challenge nonce was malformed.
    #[error("server sent a malformed challenge nonce")]
    BadChallenge,
    /// The server refused registration.
    #[error("registration refused: code {code}, {message}")]
    Refused {
        /// Error code from `docs/PROTOCOL.md` Appendix B.
        code: u16,
        /// Server-supplied detail.
        message: String,
    },
}

/// A device's long-term signing identity.
///
/// The private key never leaves this struct, and in production is loaded from the OS keystore
/// rather than constructed from bytes.
pub struct Identity {
    signing_key: SigningKey,
    device_id: DeviceId,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never derive Debug on anything holding a private key: it ends up in a log eventually.
        f.debug_struct("Identity")
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Wraps an existing signing key.
    #[must_use]
    pub fn new(signing_key: SigningKey) -> Self {
        let device_id = device_id_from_pubkey(&signing_key.verifying_key().to_bytes());
        Self {
            signing_key,
            device_id,
        }
    }

    /// Generates a fresh identity from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        Self::new(SigningKey::generate(&mut rand::rngs::OsRng))
    }

    /// This device's identifier.
    #[must_use]
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// This device's public key, base64url encoded.
    #[must_use]
    pub fn pubkey_b64(&self) -> String {
        b64().encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Signs a registration challenge.
    #[must_use]
    pub fn sign_registration(&self, nonce: &[u8], role: Role) -> String {
        let message = Register::signing_input(nonce, &self.device_id, role);
        b64().encode(self.signing_key.sign(&message).to_bytes())
    }
}

/// What the client advertises at registration.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Role to register as.
    pub role: Role,
    /// Advertised capabilities.
    pub caps: Capabilities,
    /// Agent string for diagnostics.
    pub agent: Option<String>,
    /// PoP probe results: code → median RTT in milliseconds.
    pub pop_rtt: BTreeMap<String, u32>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            role: Role::Both,
            caps: Capabilities::from_iter([
                rda_proto::caps::VIDEO_H264,
                rda_proto::caps::INPUT_HID,
            ]),
            agent: Some(format!("rda/{}", env!("CARGO_PKG_VERSION"))),
            pop_rtt: BTreeMap::new(),
        }
    }
}

/// A live, registered signaling connection.
pub struct SignalConnection {
    /// Messages received from the server.
    pub inbox: mpsc::UnboundedReceiver<Envelope>,
    outbox: mpsc::UnboundedSender<Envelope>,
    device_id: DeviceId,
    heartbeat_interval_s: u32,
}

impl SignalConnection {
    /// This device's confirmed identifier.
    #[must_use]
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// The heartbeat interval the server requires.
    #[must_use]
    pub fn heartbeat_interval_s(&self) -> u32 {
        self.heartbeat_interval_s
    }

    /// Queues a message to the server.
    pub fn send(&self, sid: Option<String>, msg: Message) -> Result<(), ClientError> {
        let env = Envelope::new(ulid::Ulid::new().to_string(), now_ms(), sid, msg);
        self.outbox.send(env).map_err(|_| ClientError::Closed)
    }

    /// Returns a handle that can send without borrowing the connection.
    #[must_use]
    pub fn sender(&self) -> mpsc::UnboundedSender<Envelope> {
        self.outbox.clone()
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Connects to a signaling server and completes registration.
///
/// Returns once `register_ack` arrives; the connection then runs until dropped or the server closes
/// it. Heartbeats are the caller's responsibility, driven off
/// [`SignalConnection::heartbeat_interval_s`].
pub async fn connect(
    url: &str,
    identity: &Identity,
    config: &ClientConfig,
) -> Result<SignalConnection, ClientError> {
    let (stream, _) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(Box::new)?;
    let (mut sink, mut source) = stream.split();

    // The server speaks first. Anything else means we are not talking to a signaling server.
    let challenge = match next_envelope(&mut source).await? {
        Some(env) => match env.msg {
            Message::Challenge(c) => c,
            _ => return Err(ClientError::NoChallenge),
        },
        None => return Err(ClientError::Closed),
    };

    let nonce = b64()
        .decode(&challenge.nonce)
        .ok()
        .filter(|v| v.len() == NONCE_LEN)
        .ok_or(ClientError::BadChallenge)?;

    let register = Message::Register(Register {
        device_id: identity.device_id().clone(),
        pubkey: identity.pubkey_b64(),
        sig: identity.sign_registration(&nonce, config.role),
        role: config.role,
        caps: config.caps.clone(),
        agent: config.agent.clone(),
        pop_rtt: config.pop_rtt.clone(),
    });
    let env = Envelope::new(ulid::Ulid::new().to_string(), now_ms(), None, register);
    sink.send(WsMessage::Text(
        String::from_utf8(env.to_vec()?).unwrap_or_default(),
    ))
    .await
    .map_err(Box::new)?;

    let ack = match next_envelope(&mut source).await? {
        Some(env) => env,
        None => return Err(ClientError::Closed),
    };
    let (device_id, heartbeat_interval_s) = match ack.msg {
        Message::RegisterAck(a) => (a.device_id, a.heartbeat_interval_s),
        Message::Error(e) => {
            return Err(ClientError::Refused {
                code: e.code,
                message: e.message,
            })
        }
        _ => return Err(ClientError::NoChallenge),
    };

    info!(%device_id, "registered with signaling server");

    let (inbox_tx, inbox) = mpsc::unbounded_channel();
    let (outbox, mut outbox_rx) = mpsc::unbounded_channel::<Envelope>();

    tokio::spawn(async move {
        while let Some(env) = outbox_rx.recv().await {
            let Ok(bytes) = env.to_vec() else { continue };
            let Ok(text) = String::from_utf8(bytes) else {
                continue;
            };
            if sink.send(WsMessage::Text(text)).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    tokio::spawn(async move {
        loop {
            match next_envelope(&mut source).await {
                Ok(Some(env)) => {
                    if inbox_tx.send(env).is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    debug!("signaling connection closed");
                    break;
                }
                Err(e) => {
                    warn!(error = %e, "signaling receive failed");
                    break;
                }
            }
        }
    });

    Ok(SignalConnection {
        inbox,
        outbox,
        device_id,
        heartbeat_interval_s,
    })
}

async fn next_envelope<S>(source: &mut S) -> Result<Option<Envelope>, ClientError>
where
    S: futures_util::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    while let Some(frame) = source.next().await {
        match frame.map_err(Box::new)? {
            WsMessage::Text(t) => return Ok(Some(Envelope::from_slice(t.as_bytes())?)),
            WsMessage::Close(_) => return Ok(None),
            // Binary, Ping, Pong and Frame carry nothing at this layer.
            _ => continue,
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_derives_a_stable_device_id() {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let a = Identity::new(key.clone());
        let b = Identity::new(key);
        assert_eq!(a.device_id(), b.device_id());
        assert_eq!(a.pubkey_b64(), b.pubkey_b64());
    }

    #[test]
    fn generated_identities_are_distinct() {
        assert_ne!(
            Identity::generate().device_id(),
            Identity::generate().device_id()
        );
    }

    #[test]
    fn debug_output_never_contains_the_private_key() {
        // A private key that reaches a log file is a full compromise, and Debug output is the
        // most common way it gets there.
        let identity = Identity::new(SigningKey::from_bytes(&[7u8; 32]));
        let rendered = format!("{identity:?}");
        assert!(rendered.contains("device_id"));
        assert!(!rendered.contains("signing_key"));
        assert!(
            !rendered.contains('7'),
            "no raw key material in Debug output"
        );
    }

    #[test]
    fn signatures_are_bound_to_the_nonce() {
        let identity = Identity::generate();
        let a = identity.sign_registration(b"nonce-aaaaaaaaaa", Role::Host);
        let b = identity.sign_registration(b"nonce-bbbbbbbbbb", Role::Host);
        assert_ne!(a, b);
    }

    #[test]
    fn default_config_advertises_the_required_capabilities() {
        assert!(ClientConfig::default().caps.meets_required());
    }
}
