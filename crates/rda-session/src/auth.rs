//! The PIN handshake, run over the control channel once the transport is up.
//!
//! This is where the machinery built in Phase 3 finally gets used: SPAKE2 over a six-digit PIN, key
//! confirmation, and a signature binding each peer's identity key to the DTLS certificate it
//! **actually presented** — read from the completed handshake, not copied from the SDP a signaling
//! server could have rewritten.
//!
//! Handshake bodies are CBOR carried inside the control-frame envelope. The framing layer treats
//! them as opaque (`rda_proto::control` decodes them as `Unknown`), which is exactly the split the
//! protocol intends: the byte-level codec owns framing, this owns meaning.
//!
//! The flow is three round trips, which at 220 ms costs about 0.7 s. That is the price of a PAKE
//! plus confirmation and there is no way to shorten it without weakening it.
//!
//! ```text
//!   controller                                  host
//!       |------------- Hello (pubkey, nonce, fp) ->|
//!       |<---------- HelloAck (pubkey, nonce, fp) -|
//!       |------------- AuthRequest (SPAKE2 msg) -->|
//!       |<-- AuthResponse (SPAKE2 msg, host tag) --|
//!       |--- AuthConfirm (tag, binding signature)->|
//!       |<------------ SessionReady (caps, SAS) ---|
//! ```

use rda_crypto::binding::{BindingProof, BindingVerifier, Fingerprint, PeerRole};
use rda_crypto::identity::{Identity, PublicIdentity};
use rda_crypto::pake::{self, PinAuth, PinVerifier, SessionPin};
use rda_proto::caps::SessionCaps;
use rda_proto::control::{ControlFrame, MessageType, Payload};
use rda_transport::{Session, TransportEvent};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info, warn};

/// How long to wait for each handshake step.
///
/// Three round trips at 250 ms is under a second; twenty seconds allows for a human typing the PIN
/// on the other end without ever being the thing that fails.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(20);

/// Why the handshake failed.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The transport failed.
    #[error("transport error: {0}")]
    Transport(#[from] rda_transport::TransportError),
    /// A handshake message was malformed.
    #[error("malformed handshake message: {0}")]
    Malformed(String),
    /// The peer sent something unexpected for this stage.
    #[error("unexpected handshake message")]
    Unexpected,
    /// The PIN did not match.
    ///
    /// Deliberately indistinguishable from a protocol error to the peer: telling an attacker which
    /// of the two happened lets them separate a wrong guess from a malformed message and probe
    /// more efficiently.
    #[error("PIN authentication failed")]
    BadPin,
    /// The DTLS fingerprint binding did not verify.
    ///
    /// **The man-in-the-middle signal.** Must be surfaced as a security warning, never as a generic
    /// connection failure, and never with an option to continue.
    #[error("fingerprint binding failed: a man-in-the-middle may be present")]
    BindingFailed,
    /// The DTLS handshake had not completed, so there was no certificate to bind to.
    #[error("no DTLS certificate available to bind")]
    NoCertificate,
    /// Nothing arrived within [`STEP_TIMEOUT`].
    #[error("handshake timed out")]
    TimedOut,
    /// The session ended mid-handshake.
    #[error("session closed during the handshake")]
    Closed,
}

/// The CBOR bodies carried inside the control-frame envelope.
#[derive(Debug, Serialize, Deserialize)]
struct HelloBody {
    pubkey: Vec<u8>,
    nonce: Vec<u8>,
    fingerprint: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PakeBody {
    message: Vec<u8>,
    /// Present only on the host's response.
    confirm: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ConfirmBody {
    confirm: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReadyBody {
    caps: Vec<String>,
    sas: Vec<String>,
}

/// What a completed handshake produced.
#[derive(Debug, Clone)]
pub struct Authenticated {
    /// The peer's verified identity.
    pub peer: PublicIdentity,
    /// Capabilities the host granted.
    pub caps: SessionCaps,
    /// The short authentication string both ends derived.
    ///
    /// Two humans comparing these defeats a man-in-the-middle even on first contact, where there is
    /// no pinned key to check against.
    pub sas: Vec<String>,
}

fn encode(kind: MessageType, body: &impl Serialize, sequence: u16) -> Result<Vec<u8>, AuthError> {
    let mut cbor = Vec::new();
    ciborium::into_writer(body, &mut cbor).map_err(|e| AuthError::Malformed(e.to_string()))?;
    Ok(ControlFrame::new(
        Payload::Unknown {
            msg_type: kind as u8,
            body: cbor,
        },
        sequence,
        0,
    )
    .encode())
}

fn decode<T: for<'de> Deserialize<'de>>(
    frame: &ControlFrame,
    expect: MessageType,
) -> Result<T, AuthError> {
    let Payload::Unknown { msg_type, body } = &frame.payload else {
        return Err(AuthError::Unexpected);
    };
    if *msg_type != expect as u8 {
        return Err(AuthError::Unexpected);
    }
    ciborium::from_reader(body.as_slice()).map_err(|e| AuthError::Malformed(e.to_string()))
}

/// Waits for the next control-channel frame.
async fn next_frame(session: &mut Session) -> Result<ControlFrame, AuthError> {
    let deadline = tokio::time::Instant::now() + STEP_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(AuthError::TimedOut);
        }
        match tokio::time::timeout(remaining, session.events.recv()).await {
            Ok(Some(TransportEvent::Frame {
                channel: rda_proto::control::Channel::Control,
                frame,
            })) => {
                return Ok(*frame);
            }
            Ok(Some(TransportEvent::Closed)) => return Err(AuthError::Closed),
            Ok(Some(_)) => continue,
            Ok(None) => return Err(AuthError::Closed),
            Err(_) => return Err(AuthError::TimedOut),
        }
    }
}

/// Reads both fingerprints, failing if the DTLS handshake has not produced a certificate.
async fn fingerprints(session: &Session) -> Result<(Fingerprint, Fingerprint), AuthError> {
    let local = session
        .local_fingerprint()
        .ok_or(AuthError::NoCertificate)?;
    let remote = session
        .remote_fingerprint()
        .await
        .ok_or(AuthError::NoCertificate)?;
    Ok((
        Fingerprint::from_bytes(local),
        Fingerprint::from_bytes(remote),
    ))
}

/// Runs the controller side of the handshake.
pub async fn authenticate_as_controller(
    session: &mut Session,
    session_id: &str,
    identity: &Identity,
    pin: &str,
) -> Result<Authenticated, AuthError> {
    let (local_fp, remote_fp) = fingerprints(session).await?;
    let nonce = BindingVerifier::generate_nonce();

    // 1. Hello.
    let hello = HelloBody {
        pubkey: identity.public().to_bytes().to_vec(),
        nonce: nonce.to_vec(),
        fingerprint: local_fp.as_bytes().to_vec(),
    };
    session
        .send_bytes(
            rda_proto::control::Channel::Control,
            &encode(MessageType::Hello, &hello, 0)?,
        )
        .await?;

    // 2. HelloAck.
    let ack: HelloBody = decode(&next_frame(session).await?, MessageType::HelloAck)?;
    let host_identity = parse_identity(&ack.pubkey)?;
    let host_nonce = parse_nonce(&ack.nonce)?;

    // The fingerprint the host *claims* is checked against the one it actually presented. A
    // mismatch here means the DTLS session is not the one the host thinks it is.
    if ack.fingerprint.as_slice() != remote_fp.as_bytes() {
        warn!("host advertised a different fingerprint than it presented");
        return Err(AuthError::BindingFailed);
    }

    let binding = BindingVerifier::new(
        session_id,
        PeerRole::Controller,
        nonce,
        host_nonce,
        local_fp,
        remote_fp,
    );

    // 3. SPAKE2.
    let auth = PinAuth::start(session_id, pin).map_err(|_| AuthError::BadPin)?;
    let request = PakeBody {
        message: auth.message().to_vec(),
        confirm: None,
    };
    session
        .send_bytes(
            rda_proto::control::Channel::Control,
            &encode(MessageType::AuthRequest, &request, 1)?,
        )
        .await?;

    // 4. The host's SPAKE2 message and its confirmation tag.
    let response: PakeBody = decode(&next_frame(session).await?, MessageType::AuthResponse)?;
    let key = auth
        .finish(&response.message)
        .map_err(|_| AuthError::BadPin)?;

    // Check the host before proving ourselves: a client that skips this will happily complete a
    // handshake with anything that answers.
    let host_tag = response.confirm.ok_or(AuthError::Unexpected)?;
    let expected_host = pake::confirm(&key, "host", session_id);
    if host_tag.len() != 32 || !pake::confirm_matches(&expected_host, &to_array(&host_tag)?) {
        return Err(AuthError::BadPin);
    }

    // 5. Our confirmation plus the binding signature.
    let proof = binding.prove(identity);
    let confirm = ConfirmBody {
        confirm: pake::confirm(&key, "controller", session_id).to_vec(),
        signature: proof.signature.to_vec(),
    };
    session
        .send_bytes(
            rda_proto::control::Channel::Control,
            &encode(MessageType::AuthConfirm, &confirm, 2)?,
        )
        .await?;

    // 6. The grant.
    let ready: ReadyBody = decode(&next_frame(session).await?, MessageType::SessionReady)?;
    let sas = rda_crypto::sas::short_authentication_string(&binding.transcript_hash(), session_id);

    info!(peer = %host_identity.device_id(), "session authenticated");
    Ok(Authenticated {
        peer: host_identity,
        caps: SessionCaps::from_names(&ready.caps),
        sas: sas.into_iter().map(String::from).collect(),
    })
}

/// Runs the host side of the handshake.
///
/// `pin` is displayed to the local user, who reads it to whoever is connecting.
pub async fn authenticate_as_host(
    session: &mut Session,
    session_id: &str,
    identity: &Identity,
    pin: &SessionPin,
    granted: SessionCaps,
    now_ms: u64,
) -> Result<Authenticated, AuthError> {
    let (local_fp, remote_fp) = fingerprints(session).await?;
    let nonce = BindingVerifier::generate_nonce();

    // 1. Hello.
    let hello: HelloBody = decode(&next_frame(session).await?, MessageType::Hello)?;
    let peer_identity = parse_identity(&hello.pubkey)?;
    let peer_nonce = parse_nonce(&hello.nonce)?;
    if hello.fingerprint.as_slice() != remote_fp.as_bytes() {
        warn!("controller advertised a different fingerprint than it presented");
        return Err(AuthError::BindingFailed);
    }

    // 2. HelloAck.
    let ack = HelloBody {
        pubkey: identity.public().to_bytes().to_vec(),
        nonce: nonce.to_vec(),
        fingerprint: local_fp.as_bytes().to_vec(),
    };
    session
        .send_bytes(
            rda_proto::control::Channel::Control,
            &encode(MessageType::HelloAck, &ack, 0)?,
        )
        .await?;

    let binding = BindingVerifier::new(
        session_id,
        PeerRole::Host,
        nonce,
        peer_nonce,
        local_fp,
        remote_fp,
    );

    // 3. The controller's SPAKE2 message.
    let request: PakeBody = decode(&next_frame(session).await?, MessageType::AuthRequest)?;
    let mut verifier = PinVerifier::new(session_id.to_string(), pin.clone());
    let (our_message, key) = verifier
        .respond(&request.message, now_ms)
        .map_err(|_| AuthError::BadPin)?;

    // 4. Our SPAKE2 message and confirmation.
    let response = PakeBody {
        message: our_message,
        confirm: Some(pake::confirm(&key, "host", session_id).to_vec()),
    };
    session
        .send_bytes(
            rda_proto::control::Channel::Control,
            &encode(MessageType::AuthResponse, &response, 1)?,
        )
        .await?;

    // 5. The controller's confirmation and binding signature. Both must check out.
    let confirm: ConfirmBody = decode(&next_frame(session).await?, MessageType::AuthConfirm)?;
    let expected = pake::confirm(&key, "controller", session_id);
    if confirm.confirm.len() != 32
        || !pake::confirm_matches(&expected, &to_array(&confirm.confirm)?)
    {
        debug!("controller confirmation did not match; wrong PIN");
        return Err(AuthError::BadPin);
    }

    let proof = BindingProof {
        role: PeerRole::Controller,
        identity: peer_identity.clone(),
        signature: to_array64(&confirm.signature)?,
    };
    binding.verify(&proof, None).map_err(|e| {
        warn!(error = %e, "fingerprint binding failed");
        AuthError::BindingFailed
    })?;
    verifier.consume();

    // 6. The grant.
    let sas = rda_crypto::sas::short_authentication_string(&binding.transcript_hash(), session_id);
    let ready = ReadyBody {
        caps: granted.to_names().into_iter().map(String::from).collect(),
        sas: sas.iter().map(|s| (*s).to_string()).collect(),
    };
    session
        .send_bytes(
            rda_proto::control::Channel::Control,
            &encode(MessageType::SessionReady, &ready, 2)?,
        )
        .await?;

    info!(peer = %peer_identity.device_id(), ?granted, "session authenticated");
    Ok(Authenticated {
        peer: peer_identity,
        caps: granted,
        sas: sas.into_iter().map(String::from).collect(),
    })
}

fn parse_identity(bytes: &[u8]) -> Result<PublicIdentity, AuthError> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AuthError::Malformed("identity key is not 32 bytes".into()))?;
    PublicIdentity::from_bytes(&array).map_err(|e| AuthError::Malformed(e.to_string()))
}

fn parse_nonce(bytes: &[u8]) -> Result<[u8; 32], AuthError> {
    bytes
        .try_into()
        .map_err(|_| AuthError::Malformed("nonce is not 32 bytes".into()))
}

fn to_array(bytes: &[u8]) -> Result<[u8; 32], AuthError> {
    bytes
        .try_into()
        .map_err(|_| AuthError::Malformed("expected 32 bytes".into()))
}

fn to_array64(bytes: &[u8]) -> Result<[u8; 64], AuthError> {
    bytes
        .try_into()
        .map_err(|_| AuthError::Malformed("signature is not 64 bytes".into()))
}
