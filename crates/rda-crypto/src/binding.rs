//! DTLS fingerprint binding — `docs/PROTOCOL.md` §4.3.
//!
//! WebRTC's DTLS protects the media path, but the certificate fingerprint that anchors it travels
//! through the signaling server inside the SDP. A malicious server can substitute its own
//! fingerprint, terminate DTLS itself, and relay a re-encrypted stream in both directions. Both
//! peers see a green padlock. This is the standard and widely-underestimated WebRTC weakness.
//!
//! The fix: each peer signs, with its long-term identity key, a structure binding **its own DTLS
//! fingerprint** to the session and both nonces. The verifier compares that against the fingerprint
//! of the certificate **actually presented in the completed handshake** — never the copy from the
//! SDP. A substituted fingerprint cannot be signed by the legitimate peer, so the session aborts.
//!
//! This is what makes it acceptable to run rendezvous and TURN infrastructure in places you do not
//! control, which is what makes a geo-distributed PoP fleet affordable.

use crate::identity::{Identity, IdentityError, PublicIdentity};
use rda_proto::ids::DeviceId;

/// Domain separator. Every signature in this protocol is domain-separated so a signature produced
/// in one context can never be replayed into another.
pub const BINDING_DOMAIN: &[u8] = b"RDA-v1-binding";

/// Length of a session nonce, in bytes.
pub const NONCE_LEN: usize = 32;

/// Which end of the session a peer is. Encoded into the signed structure so a proof produced by
/// the controller cannot be replayed as the host's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerRole {
    /// The peer that views and controls.
    Controller = 0x01,
    /// The peer that shares its screen and accepts input.
    Host = 0x02,
}

impl PeerRole {
    /// The opposite role.
    #[must_use]
    pub fn peer(self) -> Self {
        match self {
            PeerRole::Controller => PeerRole::Host,
            PeerRole::Host => PeerRole::Controller,
        }
    }
}

/// A SHA-256 DTLS certificate fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Wraps raw digest bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Computes the fingerprint of a DER-encoded certificate.
    #[must_use]
    pub fn of_certificate(der: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(der);
        Self(h.finalize().into())
    }

    /// Parses the colon-separated hex form used in SDP `a=fingerprint:sha-256 ...` lines.
    ///
    /// Returns `None` for anything malformed. This parses attacker-supplied text, so it allocates
    /// nothing beyond the fixed output and never panics.
    #[must_use]
    pub fn parse_sdp(s: &str) -> Option<Self> {
        let hex = s.trim().strip_prefix("sha-256 ").unwrap_or(s.trim());
        let mut out = [0u8; 32];
        let mut n = 0;
        for part in hex.split(':') {
            if n >= 32 || part.len() != 2 {
                return None;
            }
            out[n] = u8::from_str_radix(part, 16).ok()?;
            n += 1;
        }
        (n == 32).then_some(Self(out))
    }

    /// The raw digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Renders the SDP colon-separated hex form.
    #[must_use]
    pub fn to_sdp(&self) -> String {
        self.0
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// Builds the exact byte string both peers sign and verify.
///
/// Fingerprints appear in fixed **role order**, not sorted, so both ends construct an identical
/// structure with no ambiguity about which is which.
///
/// ```text
/// "RDA-v1-binding" ‖ 0x00 ‖ session_id ‖ nonce_controller ‖ nonce_host
///                        ‖ fp_controller ‖ fp_host ‖ role
/// ```
#[must_use]
pub fn binding_input(
    session_id: &str,
    nonce_controller: &[u8; NONCE_LEN],
    nonce_host: &[u8; NONCE_LEN],
    fp_controller: &Fingerprint,
    fp_host: &Fingerprint,
    role: PeerRole,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(BINDING_DOMAIN.len() + 1 + session_id.len() + 32 * 4 + 1);
    buf.extend_from_slice(BINDING_DOMAIN);
    buf.push(0x00);
    buf.extend_from_slice(session_id.as_bytes());
    buf.extend_from_slice(nonce_controller);
    buf.extend_from_slice(nonce_host);
    buf.extend_from_slice(fp_controller.as_bytes());
    buf.extend_from_slice(fp_host.as_bytes());
    buf.push(role as u8);
    buf
}

/// A peer's signed claim over its own DTLS fingerprint.
#[derive(Debug, Clone)]
pub struct BindingProof {
    /// Who produced this proof.
    pub role: PeerRole,
    /// The signer's identity.
    pub identity: PublicIdentity,
    /// Ed25519 signature over [`binding_input`].
    pub signature: [u8; 64],
}

/// Why a binding failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BindingError {
    /// The signature did not verify against the peer's identity key.
    ///
    /// **This is the MITM signal.** It must be surfaced to the user as a security warning, never
    /// as a generic connection failure, and must never offer a "continue anyway" option.
    #[error("fingerprint binding signature is invalid: possible man-in-the-middle")]
    InvalidSignature,
    /// The peer signed a fingerprint that is not the one it presented in the DTLS handshake.
    #[error("peer signed a different fingerprint than it presented: possible man-in-the-middle")]
    FingerprintMismatch,
    /// The proof was produced for the wrong role.
    #[error("binding proof has the wrong role")]
    WrongRole,
    /// The identity key does not derive the device id we dialled.
    #[error("peer identity does not match the device id")]
    IdentityMismatch,
    /// Underlying key or signature problem.
    #[error(transparent)]
    Identity(#[from] IdentityError),
}

/// Everything one side needs to produce and check a binding.
#[derive(Debug, Clone)]
pub struct BindingVerifier {
    session_id: String,
    nonce_controller: [u8; NONCE_LEN],
    nonce_host: [u8; NONCE_LEN],
    fp_controller: Fingerprint,
    fp_host: Fingerprint,
    local_role: PeerRole,
}

impl BindingVerifier {
    /// Assembles the session context.
    ///
    /// `fp_local` must be the fingerprint of our own DTLS certificate; `fp_remote` must be the
    /// fingerprint of the certificate the peer **actually presented in the completed handshake**.
    /// Passing the value copied from the SDP here defeats the entire mechanism.
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        local_role: PeerRole,
        nonce_local: [u8; NONCE_LEN],
        nonce_remote: [u8; NONCE_LEN],
        fp_local: Fingerprint,
        fp_remote: Fingerprint,
    ) -> Self {
        let (nonce_controller, nonce_host, fp_controller, fp_host) = match local_role {
            PeerRole::Controller => (nonce_local, nonce_remote, fp_local, fp_remote),
            PeerRole::Host => (nonce_remote, nonce_local, fp_remote, fp_local),
        };
        Self {
            session_id: session_id.into(),
            nonce_controller,
            nonce_host,
            fp_controller,
            fp_host,
            local_role,
        }
    }

    /// Generates a fresh session nonce.
    #[must_use]
    pub fn generate_nonce() -> [u8; NONCE_LEN] {
        use rand::RngCore;
        let mut n = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut n);
        n
    }

    /// Produces our own proof.
    #[must_use]
    pub fn prove(&self, identity: &Identity) -> BindingProof {
        let message = binding_input(
            &self.session_id,
            &self.nonce_controller,
            &self.nonce_host,
            &self.fp_controller,
            &self.fp_host,
            self.local_role,
        );
        BindingProof {
            role: self.local_role,
            identity: identity.public(),
            signature: identity.sign(&message),
        }
    }

    /// Verifies the peer's proof.
    ///
    /// `expected_device_id` is the id we dialled (or that dialled us). Checking it here binds the
    /// whole chain together: the id we intended → the identity key → the DTLS certificate actually
    /// in use. Break any link and the session aborts.
    pub fn verify(
        &self,
        proof: &BindingProof,
        expected_device_id: Option<&DeviceId>,
    ) -> Result<(), BindingError> {
        let expected_role = self.local_role.peer();
        if proof.role != expected_role {
            return Err(BindingError::WrongRole);
        }

        if let Some(id) = expected_device_id {
            proof
                .identity
                .check_claims(id)
                .map_err(|_| BindingError::IdentityMismatch)?;
        }

        let message = binding_input(
            &self.session_id,
            &self.nonce_controller,
            &self.nonce_host,
            &self.fp_controller,
            &self.fp_host,
            expected_role,
        );
        proof
            .identity
            .verify(&message, &proof.signature)
            .map_err(|_| BindingError::InvalidSignature)
    }

    /// The transcript hash, used to derive the short authentication string.
    #[must_use]
    pub fn transcript_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"RDA-v1-transcript");
        h.update([0x00]);
        h.update(self.session_id.as_bytes());
        h.update(self.nonce_controller);
        h.update(self.nonce_host);
        h.update(self.fp_controller.as_bytes());
        h.update(self.fp_host.as_bytes());
        h.finalize().into()
    }

    /// The session identifier.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(seed: u8) -> Fingerprint {
        Fingerprint::from_bytes([seed; 32])
    }

    /// Builds both ends of a session that agree on everything.
    fn matched_pair(
        session: &str,
        fp_ctrl: Fingerprint,
        fp_host: Fingerprint,
    ) -> (BindingVerifier, BindingVerifier) {
        let n_c = [1u8; NONCE_LEN];
        let n_h = [2u8; NONCE_LEN];
        (
            BindingVerifier::new(session, PeerRole::Controller, n_c, n_h, fp_ctrl, fp_host),
            BindingVerifier::new(session, PeerRole::Host, n_h, n_c, fp_host, fp_ctrl),
        )
    }

    #[test]
    fn an_honest_session_verifies_both_ways() {
        let controller = Identity::generate();
        let host = Identity::generate();
        let (cv, hv) = matched_pair("sess_1", fp(0xAA), fp(0xBB));

        let controller_proof = cv.prove(&controller);
        let host_proof = hv.prove(&host);

        assert!(hv
            .verify(&controller_proof, Some(controller.device_id()))
            .is_ok());
        assert!(cv.verify(&host_proof, Some(host.device_id())).is_ok());
    }

    #[test]
    fn both_ends_derive_the_same_transcript() {
        let (cv, hv) = matched_pair("sess_1", fp(0xAA), fp(0xBB));
        assert_eq!(cv.transcript_hash(), hv.transcript_hash());
    }

    /// The attack this module exists to stop, played out end to end.
    #[test]
    fn a_signaling_server_substituting_a_fingerprint_is_detected() {
        let controller = Identity::generate();
        let host = Identity::generate();

        // The honest controller signs over its real fingerprint.
        let (cv, _) = matched_pair("sess_1", fp(0xAA), fp(0xBB));
        let honest_proof = cv.prove(&controller);

        // A malicious server terminates DTLS itself, so the host sees the attacker's certificate
        // (0xEE) where the controller's (0xAA) should be. The server forwards the real signature,
        // because it cannot produce a new one without the controller's identity key.
        let mitm_host_view = BindingVerifier::new(
            "sess_1",
            PeerRole::Host,
            [2u8; 32],
            [1u8; 32],
            fp(0xBB),
            fp(0xEE),
        );

        assert_eq!(
            mitm_host_view.verify(&honest_proof, Some(controller.device_id())),
            Err(BindingError::InvalidSignature),
            "a substituted fingerprint must be caught"
        );
        let _ = host;
    }

    #[test]
    fn a_proof_from_one_session_does_not_replay_into_another() {
        let controller = Identity::generate();
        let (cv1, _) = matched_pair("sess_1", fp(0xAA), fp(0xBB));
        let (_, hv2) = matched_pair("sess_2", fp(0xAA), fp(0xBB));
        let proof = cv1.prove(&controller);
        assert_eq!(
            hv2.verify(&proof, Some(controller.device_id())),
            Err(BindingError::InvalidSignature)
        );
    }

    #[test]
    fn a_proof_with_stale_nonces_is_rejected() {
        // Replaying a captured proof into a fresh session with the same fingerprints.
        let controller = Identity::generate();
        let (cv, _) = matched_pair("sess_1", fp(0xAA), fp(0xBB));
        let proof = cv.prove(&controller);

        let fresh_host = BindingVerifier::new(
            "sess_1",
            PeerRole::Host,
            [9u8; 32], // new host nonce
            [1u8; 32],
            fp(0xBB),
            fp(0xAA),
        );
        assert_eq!(
            fresh_host.verify(&proof, Some(controller.device_id())),
            Err(BindingError::InvalidSignature)
        );
    }

    #[test]
    fn a_controller_proof_cannot_be_replayed_as_the_host_proof() {
        let controller = Identity::generate();
        let (cv, hv) = matched_pair("sess_1", fp(0xAA), fp(0xBB));

        // Relabelling a controller proof as a host proof gets past the cheap role check, because
        // the label is just a field — but the role byte is also *inside* the signed structure, so
        // the signature no longer matches what the verifier reconstructs.
        let mut relabelled = cv.prove(&controller);
        relabelled.role = PeerRole::Host;
        assert_eq!(
            cv.verify(&relabelled, Some(controller.device_id())),
            Err(BindingError::InvalidSignature),
            "the signed role byte must catch a relabelled proof"
        );

        // And a correctly-labelled proof presented to the wrong side is caught earlier and more
        // cheaply, without spending a signature verification.
        let honest = cv.prove(&controller);
        assert_eq!(
            cv.verify(&honest, Some(controller.device_id())),
            Err(BindingError::WrongRole),
            "a controller must not accept a controller-role proof"
        );
        assert!(hv.verify(&honest, Some(controller.device_id())).is_ok());
    }

    #[test]
    fn a_proof_from_an_unexpected_device_is_rejected() {
        let controller = Identity::generate();
        let someone_else = Identity::generate();
        let (cv, hv) = matched_pair("sess_1", fp(0xAA), fp(0xBB));
        let proof = cv.prove(&controller);
        assert_eq!(
            hv.verify(&proof, Some(someone_else.device_id())),
            Err(BindingError::IdentityMismatch)
        );
    }

    #[test]
    fn fingerprint_parses_and_renders_the_sdp_form() {
        let f = fp(0xAB);
        let rendered = f.to_sdp();
        assert!(rendered.starts_with("AB:AB:"));
        assert_eq!(Fingerprint::parse_sdp(&rendered), Some(f));
        assert_eq!(
            Fingerprint::parse_sdp(&format!("sha-256 {rendered}")),
            Some(f)
        );
    }

    #[test]
    fn malformed_fingerprints_are_rejected_without_panicking() {
        for s in [
            "",
            "AB",
            "AB:CD",
            "ZZ:".repeat(32).as_str(),
            &"AB:".repeat(64),
            "AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB",
        ] {
            assert_eq!(Fingerprint::parse_sdp(s), None, "accepted {s:?}");
        }
    }

    #[test]
    fn certificate_fingerprints_are_distinct_per_certificate() {
        let a = Fingerprint::of_certificate(b"cert-a");
        let b = Fingerprint::of_certificate(b"cert-b");
        assert_ne!(a, b);
        assert_eq!(a, Fingerprint::of_certificate(b"cert-a"));
    }
}
