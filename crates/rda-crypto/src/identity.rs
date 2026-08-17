//! Device identity — `docs/PROTOCOL.md` §4.1.
//!
//! A device id is derived from its Ed25519 public key rather than assigned by a server. That single
//! property is what lets a peer verify that the id it dialled and the key that answered belong
//! together, without ever trusting the rendezvous server to tell the truth.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rda_proto::ids::{device_id_from_pubkey, DeviceId};

/// Failures involving identity keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// The key material was not a valid Ed25519 point.
    #[error("malformed identity key")]
    MalformedKey,
    /// The signature was not 64 bytes or did not verify.
    #[error("signature verification failed")]
    BadSignature,
    /// The device id did not match the key presented.
    #[error("device id does not match the identity key")]
    IdMismatch,
    /// Stored key material was the wrong length.
    #[error("stored key material is {0} bytes, expected 32")]
    BadKeyLength(usize),
}

/// A device's long-term signing identity, including its private key.
///
/// Deliberately not `Clone`, not `Serialize`, and with a hand-written [`std::fmt::Debug`]: every
/// one of those would be a plausible route for the private key to reach a log or a crash dump.
pub struct Identity {
    signing_key: SigningKey,
    device_id: DeviceId,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Generates a new identity from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        Self::from_signing_key(SigningKey::generate(&mut rand::rngs::OsRng))
    }

    /// Wraps an existing signing key.
    #[must_use]
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let device_id = device_id_from_pubkey(&signing_key.verifying_key().to_bytes());
        Self {
            signing_key,
            device_id,
        }
    }

    /// Restores an identity from stored key bytes.
    ///
    /// In production these come from the OS keystore: DPAPI/CNG on Windows, Keychain on macOS,
    /// Secret Service on Linux, with a `0600` file as the last resort.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| IdentityError::BadKeyLength(bytes.len()))?;
        Ok(Self::from_signing_key(SigningKey::from_bytes(&arr)))
    }

    /// Exposes the private key for storage.
    ///
    /// The only legitimate caller is the keystore layer. Named to be conspicuous in review — a call
    /// to this anywhere else is a finding.
    #[must_use]
    pub fn secret_bytes_for_keystore(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// This device's identifier.
    #[must_use]
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// The public half.
    #[must_use]
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            key: self.signing_key.verifying_key(),
            device_id: self.device_id.clone(),
        }
    }

    /// Signs a message with this identity.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
}

/// The public half of a device identity: what a peer learns and pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    key: VerifyingKey,
    device_id: DeviceId,
}

impl PublicIdentity {
    /// Reconstructs a public identity from wire bytes, deriving and checking the device id.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, IdentityError> {
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| IdentityError::MalformedKey)?;
        Ok(Self {
            key,
            device_id: device_id_from_pubkey(bytes),
        })
    }

    /// Reconstructs from a base64url string.
    pub fn from_b64(s: &str) -> Result<Self, IdentityError> {
        let bytes = crate::decode_b64_array::<32>(s).ok_or(IdentityError::MalformedKey)?;
        Self::from_bytes(&bytes)
    }

    /// The raw public key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    /// Base64url form for the wire.
    #[must_use]
    pub fn to_b64(&self) -> String {
        crate::encode_b64(&self.to_bytes())
    }

    /// The device id this key derives.
    #[must_use]
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Verifies a signature made by the corresponding private key.
    ///
    /// Uses `verify_strict`, which rejects small-order and torsion-component keys. Plain `verify`
    /// accepts them, and those are exactly the keys for which a signature is not unique — a
    /// property an attacker can use to make one signature validate under two different keys.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), IdentityError> {
        let sig = Signature::from_bytes(signature);
        self.key
            .verify_strict(message, &sig)
            .map_err(|_| IdentityError::BadSignature)
    }

    /// Confirms this key belongs to the claimed device id.
    pub fn check_claims(&self, claimed: &DeviceId) -> Result<(), IdentityError> {
        if &self.device_id == claimed {
            Ok(())
        } else {
            Err(IdentityError::IdMismatch)
        }
    }
}

/// A peer we have seen before, and the key we pinned for it.
///
/// Trust-on-first-use: the first key seen for a device id is remembered, and a later mismatch is a
/// hard failure rather than a prompt. Prompting on key change trains users to click through the one
/// alert that actually matters.
#[derive(Debug, Clone, Default)]
pub struct AddressBook {
    entries: std::collections::BTreeMap<DeviceId, [u8; 32]>,
}

/// The outcome of looking a peer up in the address book.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTrust {
    /// Never seen before. The key is now pinned; the humans should compare the short
    /// authentication string ([`crate::sas`]) before doing anything sensitive.
    FirstContact,
    /// Seen before, and the key matches.
    Known,
    /// Seen before with a *different* key. Either the device was reinstalled, or someone is
    /// impersonating it. Must abort, never prompt-to-continue.
    KeyChanged,
}

impl AddressBook {
    /// An empty address book.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks a peer's key, pinning it on first contact.
    pub fn check_and_pin(&mut self, peer: &PublicIdentity) -> PeerTrust {
        let key = peer.to_bytes();
        match self.entries.get(peer.device_id()) {
            None => {
                self.entries.insert(peer.device_id().clone(), key);
                PeerTrust::FirstContact
            }
            Some(pinned) if *pinned == key => PeerTrust::Known,
            Some(_) => PeerTrust::KeyChanged,
        }
    }

    /// Checks without pinning.
    #[must_use]
    pub fn check(&self, peer: &PublicIdentity) -> PeerTrust {
        match self.entries.get(peer.device_id()) {
            None => PeerTrust::FirstContact,
            Some(pinned) if *pinned == peer.to_bytes() => PeerTrust::Known,
            Some(_) => PeerTrust::KeyChanged,
        }
    }

    /// Deliberately re-pins a peer after a legitimate reinstall.
    ///
    /// Requires an explicit user action at the UI; there is no automatic path to here.
    pub fn repin(&mut self, peer: &PublicIdentity) {
        self.entries
            .insert(peer.device_id().clone(), peer.to_bytes());
    }

    /// Forgets a peer.
    pub fn forget(&mut self, device_id: &DeviceId) -> bool {
        self.entries.remove(device_id).is_some()
    }

    /// Number of pinned peers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if nothing is pinned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_round_trips_through_storage() {
        let original = Identity::generate();
        let restored = Identity::from_secret_bytes(&original.secret_bytes_for_keystore()).unwrap();
        assert_eq!(original.device_id(), restored.device_id());
        assert_eq!(original.public(), restored.public());
    }

    #[test]
    fn restoring_from_wrong_length_fails_cleanly() {
        assert_eq!(
            Identity::from_secret_bytes(&[0u8; 16]).unwrap_err(),
            IdentityError::BadKeyLength(16)
        );
        assert_eq!(
            Identity::from_secret_bytes(&[]).unwrap_err(),
            IdentityError::BadKeyLength(0)
        );
    }

    #[test]
    fn debug_never_leaks_the_private_key() {
        let identity = Identity::from_signing_key(SigningKey::from_bytes(&[0xAB; 32]));
        let rendered = format!("{identity:?}");
        assert!(rendered.contains("device_id"));
        assert!(
            !rendered.to_lowercase().contains("ab"),
            "key bytes must not appear: {rendered}"
        );
    }

    #[test]
    fn signatures_verify_and_tampering_is_caught() {
        let identity = Identity::generate();
        let public = identity.public();
        let sig = identity.sign(b"authorize this");

        assert!(public.verify(b"authorize this", &sig).is_ok());
        assert_eq!(
            public.verify(b"authorize THAT", &sig),
            Err(IdentityError::BadSignature)
        );

        let mut tampered = sig;
        tampered[0] ^= 0x01;
        assert_eq!(
            public.verify(b"authorize this", &tampered),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn another_identitys_signature_is_rejected() {
        let a = Identity::generate();
        let b = Identity::generate();
        let sig = b.sign(b"message");
        assert_eq!(
            a.public().verify(b"message", &sig),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn public_identity_round_trips_through_base64() {
        let identity = Identity::generate();
        let public = identity.public();
        let restored = PublicIdentity::from_b64(&public.to_b64()).unwrap();
        assert_eq!(restored, public);
        assert_eq!(restored.device_id(), identity.device_id());
    }

    #[test]
    fn malformed_public_keys_are_rejected_without_panicking() {
        for s in ["", "!!!!", "AAAA", &"A".repeat(10_000)] {
            assert!(PublicIdentity::from_b64(s).is_err(), "accepted {s:?}");
        }
    }

    #[test]
    fn a_key_cannot_claim_another_devices_id() {
        let a = Identity::generate();
        let b = Identity::generate();
        assert!(a.public().check_claims(a.device_id()).is_ok());
        assert_eq!(
            a.public().check_claims(b.device_id()),
            Err(IdentityError::IdMismatch)
        );
    }

    #[test]
    fn address_book_pins_on_first_contact_and_recognises_afterwards() {
        let mut book = AddressBook::new();
        let peer = Identity::generate().public();
        assert_eq!(book.check_and_pin(&peer), PeerTrust::FirstContact);
        assert_eq!(book.check_and_pin(&peer), PeerTrust::Known);
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn address_book_detects_a_substituted_key() {
        // The impersonation case: something answers for a device id we know, with a key we have
        // not seen. This must be detectable without any user judgement involved.
        let mut book = AddressBook::new();
        let real = Identity::generate();
        book.check_and_pin(&real.public());

        // Force a collision on the device id to isolate the key comparison from the id comparison.
        let impostor_key = Identity::generate().public();
        let forged = PublicIdentity {
            key: ed25519_dalek::VerifyingKey::from_bytes(&impostor_key.to_bytes()).unwrap(),
            device_id: real.device_id().clone(),
        };
        assert_eq!(book.check(&forged), PeerTrust::KeyChanged);
    }

    #[test]
    fn repinning_is_possible_but_explicit() {
        let mut book = AddressBook::new();
        let old = Identity::generate();
        book.check_and_pin(&old.public());
        let reinstalled = PublicIdentity {
            key: ed25519_dalek::VerifyingKey::from_bytes(&Identity::generate().public().to_bytes())
                .unwrap(),
            device_id: old.device_id().clone(),
        };
        assert_eq!(book.check(&reinstalled), PeerTrust::KeyChanged);
        book.repin(&reinstalled);
        assert_eq!(book.check(&reinstalled), PeerTrust::Known);
    }

    #[test]
    fn forgetting_a_peer_returns_it_to_first_contact() {
        let mut book = AddressBook::new();
        let peer = Identity::generate().public();
        book.check_and_pin(&peer);
        assert!(book.forget(peer.device_id()));
        assert_eq!(book.check(&peer), PeerTrust::FirstContact);
        assert!(!book.forget(peer.device_id()));
    }
}
