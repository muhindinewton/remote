//! Registration challenge issuance and signature verification — `docs/PROTOCOL.md` §3.3.
//!
//! This is pre-authentication code reachable by anyone who can open a socket, so it is written to
//! the rules in `docs/ARCHITECTURE.md` §5.5: fixed-size decoding, explicit length checks, no
//! allocation driven by attacker-supplied lengths, and no trust in any field until the signature
//! over it verifies.

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use rand::RngCore;
use rda_proto::ids::DeviceId;
use rda_proto::signaling::{Register, Role, NONCE_LEN};

/// How long a challenge nonce remains usable.
pub const NONCE_TTL_MS: u64 = 60_000;

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// Reasons a registration is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// The public key was not 32 valid base64url bytes.
    #[error("malformed public key")]
    BadPubkey,
    /// The signature was not 64 valid base64url bytes.
    #[error("malformed signature")]
    BadSignatureEncoding,
    /// The signature did not verify against the key and challenge.
    #[error("signature verification failed")]
    BadSignature,
    /// The device identifier was not derived from the supplied key.
    #[error("device id does not match public key")]
    IdMismatch,
    /// No challenge was issued, it was already consumed, or it expired.
    #[error("challenge nonce is unknown, spent or expired")]
    BadNonce,
}

/// A challenge issued to one connection.
///
/// Held per connection rather than in a shared map: a nonce is only ever valid on the socket it was
/// issued to, which removes an entire class of cross-connection replay without needing any shared
/// state or expiry sweeper.
#[derive(Debug, Clone)]
pub struct Challenge {
    nonce: [u8; NONCE_LEN],
    issued_ms: u64,
    spent: bool,
}

impl Challenge {
    /// Generates a fresh challenge from the OS CSPRNG.
    pub fn issue(now_ms: u64) -> Self {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Self {
            nonce,
            issued_ms: now_ms,
            spent: false,
        }
    }

    /// The nonce in the base64url form sent on the wire.
    #[must_use]
    pub fn nonce_b64(&self) -> String {
        b64().encode(self.nonce)
    }

    /// Verifies a registration against this challenge and consumes it.
    ///
    /// On success returns the verified 32-byte public key. The challenge is marked spent whether or
    /// not verification succeeded, so a failed attempt cannot be retried against the same nonce.
    pub fn verify(&mut self, reg: &Register, now_ms: u64) -> Result<[u8; 32], AuthError> {
        if self.spent || now_ms.saturating_sub(self.issued_ms) > NONCE_TTL_MS {
            return Err(AuthError::BadNonce);
        }
        self.spent = true;

        let pubkey: [u8; 32] = b64()
            .decode(&reg.pubkey)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(AuthError::BadPubkey)?;
        let sig_bytes: [u8; 64] = b64()
            .decode(&reg.sig)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(AuthError::BadSignatureEncoding)?;

        let verifying_key = VerifyingKey::from_bytes(&pubkey).map_err(|_| AuthError::BadPubkey)?;
        let signature = Signature::from_bytes(&sig_bytes);
        let message = Register::signing_input(&self.nonce, &reg.device_id, reg.role);

        // verify_strict rejects small-order and torsion-component public keys, which
        // plain `verify` accepts. Those are exactly the keys that make signatures non-unique.
        verifying_key
            .verify_strict(&message, &signature)
            .map_err(|_| AuthError::BadSignature)?;

        // Only now is the key trusted, so only now can the claimed identifier be checked.
        reg.device_id
            .verify_against(&pubkey)
            .map_err(|_| AuthError::IdMismatch)?;

        Ok(pubkey)
    }
}

/// Builds a registration signature. Used by clients and by tests.
#[must_use]
pub fn sign_registration(
    signing_key: &ed25519_dalek::SigningKey,
    nonce: &[u8],
    device_id: &DeviceId,
    role: Role,
) -> String {
    use ed25519_dalek::Signer;
    let message = Register::signing_input(nonce, device_id, role);
    b64().encode(signing_key.sign(&message).to_bytes())
}

/// Encodes a public key for the wire.
#[must_use]
pub fn encode_pubkey(key: &VerifyingKey) -> String {
    b64().encode(key.to_bytes())
}

/// Decodes a base64url nonce back to bytes. Used by clients answering a challenge.
#[must_use]
pub fn decode_nonce(s: &str) -> Option<Vec<u8>> {
    b64().decode(s).ok().filter(|v| v.len() == NONCE_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rda_proto::caps::Capabilities;
    use rda_proto::ids::device_id_from_pubkey;

    fn registration(key: &SigningKey, nonce: &[u8], role: Role) -> Register {
        let vk = key.verifying_key();
        let device_id = device_id_from_pubkey(&vk.to_bytes());
        Register {
            sig: sign_registration(key, nonce, &device_id, role),
            device_id,
            pubkey: encode_pubkey(&vk),
            role,
            caps: Capabilities::new(),
            agent: None,
            pop_rtt: Default::default(),
        }
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn a_correct_registration_verifies() {
        let mut ch = Challenge::issue(0);
        let nonce = decode_nonce(&ch.nonce_b64()).unwrap();
        let reg = registration(&key(1), &nonce, Role::Host);
        assert_eq!(
            ch.verify(&reg, 100).unwrap(),
            key(1).verifying_key().to_bytes()
        );
    }

    #[test]
    fn a_nonce_cannot_be_used_twice() {
        let mut ch = Challenge::issue(0);
        let nonce = decode_nonce(&ch.nonce_b64()).unwrap();
        let reg = registration(&key(1), &nonce, Role::Host);
        assert!(ch.verify(&reg, 0).is_ok());
        assert_eq!(ch.verify(&reg, 0), Err(AuthError::BadNonce));
    }

    #[test]
    fn a_failed_attempt_still_burns_the_nonce() {
        // Otherwise an attacker gets unlimited attempts against one challenge.
        let mut ch = Challenge::issue(0);
        let wrong = registration(&key(1), b"some-other-nonce", Role::Host);
        assert_eq!(ch.verify(&wrong, 0), Err(AuthError::BadSignature));
        let nonce = decode_nonce(&ch.nonce_b64()).unwrap();
        let right = registration(&key(1), &nonce, Role::Host);
        assert_eq!(ch.verify(&right, 0), Err(AuthError::BadNonce));
    }

    #[test]
    fn an_expired_nonce_is_refused() {
        let mut ch = Challenge::issue(0);
        let nonce = decode_nonce(&ch.nonce_b64()).unwrap();
        let reg = registration(&key(1), &nonce, Role::Host);
        assert_eq!(ch.verify(&reg, NONCE_TTL_MS + 1), Err(AuthError::BadNonce));
    }

    #[test]
    fn a_signature_from_another_nonce_is_refused() {
        // The replay case: a registration captured from an earlier session.
        let mut ch = Challenge::issue(0);
        let old = Challenge::issue(0);
        let old_nonce = decode_nonce(&old.nonce_b64()).unwrap();
        let reg = registration(&key(1), &old_nonce, Role::Host);
        assert_eq!(ch.verify(&reg, 0), Err(AuthError::BadSignature));
    }

    #[test]
    fn claiming_someone_elses_device_id_is_refused() {
        // Registering under another device's advertised ID would let an attacker intercept
        // connections intended for it. The derivation check is what stops that.
        let mut ch = Challenge::issue(0);
        let nonce = decode_nonce(&ch.nonce_b64()).unwrap();
        let mut reg = registration(&key(1), &nonce, Role::Host);
        reg.device_id = device_id_from_pubkey(&key(2).verifying_key().to_bytes());
        // The signature covers the device_id, so tampering breaks the signature first.
        assert_eq!(ch.verify(&reg, 0), Err(AuthError::BadSignature));
    }

    #[test]
    fn a_signature_over_a_different_role_is_refused() {
        let mut ch = Challenge::issue(0);
        let nonce = decode_nonce(&ch.nonce_b64()).unwrap();
        let mut reg = registration(&key(1), &nonce, Role::Controller);
        reg.role = Role::Host;
        assert_eq!(ch.verify(&reg, 0), Err(AuthError::BadSignature));
    }

    #[test]
    fn malformed_encodings_are_rejected_without_panicking() {
        for (pubkey, sig) in [
            ("not base64!!", "also bad"),
            ("", ""),
            ("AAAA", "AAAA"),              // valid base64, wrong length
            (&"A".repeat(10_000), "AAAA"), // oversized
        ] {
            let mut ch = Challenge::issue(0);
            let mut reg = registration(&key(1), b"n", Role::Host);
            reg.pubkey = pubkey.to_string();
            reg.sig = sig.to_string();
            assert!(ch.verify(&reg, 0).is_err());
        }
    }

    #[test]
    fn nonces_differ_between_challenges() {
        let a = Challenge::issue(0);
        let b = Challenge::issue(0);
        assert_ne!(a.nonce_b64(), b.nonce_b64());
        assert_eq!(decode_nonce(&a.nonce_b64()).unwrap().len(), NONCE_LEN);
    }
}
