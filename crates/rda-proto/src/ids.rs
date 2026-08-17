//! Device identity and identifier derivation — `docs/PROTOCOL.md` §4.1.
//!
//! A device ID is not a random string handed out by a server: it is derived from the device's
//! Ed25519 public key. That property is what lets a peer verify that the ID it dialled and the key
//! that answered belong together, without trusting the signaling server to tell the truth.

use data_encoding::Encoding;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Domain separator for device ID derivation. Every hash in this protocol is domain-separated so
/// that a signature or digest from one context can never be replayed into another.
const DEVID_DOMAIN: &[u8] = b"RDA-v1-devid";

/// Number of characters in a device ID, excluding grouping hyphens.
pub const DEVICE_ID_LEN: usize = 12;

/// Crockford base32: no `I`, `L`, `O` or `U`, so a user reading an ID over the phone cannot
/// confuse it with `1`, `0`, or produce an accidental obscenity.
fn crockford() -> &'static Encoding {
    static ENC: OnceLock<Encoding> = OnceLock::new();
    ENC.get_or_init(|| {
        let mut spec = data_encoding::Specification::new();
        spec.symbols.push_str("0123456789ABCDEFGHJKMNPQRSTVWXYZ");
        spec.encoding()
            .expect("crockford base32 specification is valid")
    })
}

/// Errors from parsing or validating a device identifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    /// The identifier was not 12 significant characters.
    #[error("device id must be {DEVICE_ID_LEN} characters, got {0}")]
    BadLength(usize),
    /// The identifier contained a character outside the Crockford alphabet.
    #[error("device id contains invalid character {0:?}")]
    BadCharacter(char),
    /// The identifier did not match the key it claims to represent.
    #[error("device id does not match the supplied public key")]
    KeyMismatch,
}

/// A device identifier, stored canonically without grouping hyphens.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId(String);

impl DeviceId {
    /// Parses a device ID, accepting hyphens and lower case, normalising both away.
    ///
    /// Crockford's digit aliases are applied: `I` and `L` read as `1`, `O` reads as `0`. Users
    /// transcribe these IDs from a screen to a phone call, and rejecting a human's reasonable
    /// reading of an ambiguous glyph is a support burden with no security benefit.
    pub fn parse(s: &str) -> Result<Self, IdError> {
        let mut out = String::with_capacity(DEVICE_ID_LEN);
        for ch in s.chars() {
            if ch == '-' || ch == ' ' {
                continue;
            }
            let up = ch.to_ascii_uppercase();
            let normalised = match up {
                'I' | 'L' => '1',
                'O' => '0',
                'A'..='H' | 'J' | 'K' | 'M' | 'N' | 'P'..='T' | 'V'..='Z' | '0'..='9' => up,
                other => return Err(IdError::BadCharacter(other)),
            };
            out.push(normalised);
        }
        if out.len() != DEVICE_ID_LEN {
            return Err(IdError::BadLength(out.len()));
        }
        Ok(DeviceId(out))
    }

    /// The canonical form: 12 characters, no hyphens.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The display form: `XXXX-XXXX-XXXX`.
    #[must_use]
    pub fn grouped(&self) -> String {
        let b = self.0.as_bytes();
        format!(
            "{}-{}-{}",
            std::str::from_utf8(&b[0..4]).unwrap_or("????"),
            std::str::from_utf8(&b[4..8]).unwrap_or("????"),
            std::str::from_utf8(&b[8..12]).unwrap_or("????"),
        )
    }

    /// Verifies that this identifier was derived from `pubkey`.
    ///
    /// The signaling server calls this on every registration. Without it, a device could register
    /// under someone else's advertised ID and intercept connections intended for them.
    pub fn verify_against(&self, pubkey: &[u8; 32]) -> Result<(), IdError> {
        if *self == device_id_from_pubkey(pubkey) {
            Ok(())
        } else {
            Err(IdError::KeyMismatch)
        }
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.grouped())
    }
}

impl serde::Serialize for DeviceId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.grouped())
    }
}

impl<'de> serde::Deserialize<'de> for DeviceId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        DeviceId::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Derives the device identifier for an Ed25519 public key.
///
/// `crockford_base32(SHA-256("RDA-v1-devid" ‖ 0x00 ‖ pubkey)[0..8])[0..12]` — 60 bits of entropy,
/// which is enough to make targeting a specific device impractical while staying transcribable.
#[must_use]
pub fn device_id_from_pubkey(pubkey: &[u8; 32]) -> DeviceId {
    let mut hasher = Sha256::new();
    hasher.update(DEVID_DOMAIN);
    hasher.update([0x00]);
    hasher.update(pubkey);
    let digest = hasher.finalize();

    let encoded = crockford().encode(&digest[..8]);
    DeviceId(encoded.chars().take(DEVICE_ID_LEN).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn derivation_is_deterministic_and_well_formed() {
        let id = device_id_from_pubkey(&key(1));
        assert_eq!(id, device_id_from_pubkey(&key(1)));
        assert_eq!(id.as_str().len(), DEVICE_ID_LEN);
        assert!(id.as_str().chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(!id.as_str().contains(['I', 'L', 'O', 'U']));
    }

    #[test]
    fn different_keys_give_different_ids() {
        assert_ne!(
            device_id_from_pubkey(&key(1)),
            device_id_from_pubkey(&key(2))
        );
    }

    #[test]
    fn grouping_round_trips() {
        let id = device_id_from_pubkey(&key(7));
        let grouped = id.grouped();
        assert_eq!(grouped.len(), 14);
        assert_eq!(DeviceId::parse(&grouped).unwrap(), id);
    }

    #[test]
    fn parsing_is_forgiving_about_human_transcription() {
        let id = DeviceId::parse("K7M2-9QXR-4TVB").unwrap();
        assert_eq!(DeviceId::parse("k7m2 9qxr 4tvb").unwrap(), id);
        assert_eq!(DeviceId::parse("K7M29QXR4TVB").unwrap(), id);
        // Crockford aliases: O reads as 0, I and L read as 1.
        assert_eq!(
            DeviceId::parse("O123-4567-89AB").unwrap(),
            DeviceId::parse("0123-4567-89AB").unwrap()
        );
        assert_eq!(
            DeviceId::parse("I123-4567-89AB").unwrap(),
            DeviceId::parse("1123-4567-89AB").unwrap()
        );
    }

    #[test]
    fn parsing_rejects_bad_input() {
        assert!(matches!(
            DeviceId::parse("TOO-SHORT"),
            Err(IdError::BadLength(_))
        ));
        assert!(matches!(
            DeviceId::parse("K7M2-9QXR-4TV!"),
            Err(IdError::BadCharacter('!'))
        ));
    }

    #[test]
    fn verification_catches_a_mismatched_key() {
        let real = device_id_from_pubkey(&key(1));
        assert!(real.verify_against(&key(1)).is_ok());
        // This is the check that stops a device registering under someone else's ID.
        assert_eq!(real.verify_against(&key(2)), Err(IdError::KeyMismatch));
    }
}
