//! Identity, authentication and access control — `docs/PROTOCOL.md` §4.
//!
//! Four mechanisms, each closing a specific attack:
//!
//! | Module | Closes |
//! |---|---|
//! | [`identity`] | Impersonating a device id you do not hold the key for |
//! | [`binding`] | A malicious signaling server or TURN operator MITM-ing the media |
//! | [`pake`] | A network observer or the server learning a session PIN |
//! | [`token`] | An unattended credential being replayed, or outliving its revocation |
//!
//! The [`binding`] one is load-bearing for the whole system's threat model: it is what makes it
//! acceptable to run rendezvous and relay infrastructure you do not fully trust, which in turn is
//! what makes a geo-distributed PoP fleet affordable.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod binding;
pub mod identity;
pub mod keystore;
pub mod pake;
pub mod sas;
pub mod token;

pub use binding::{BindingProof, BindingVerifier, Fingerprint, PeerRole};
pub use identity::{Identity, IdentityError, PublicIdentity};
pub use keystore::{EphemeralKeystore, FileKeystore, Keystore, KeystoreError};
pub use pake::{PakeError, PinAuth, PinVerifier, SessionPin};
pub use sas::short_authentication_string;
pub use token::{AccessToken, TokenError, TokenIssuer, TokenStore};

use base64::Engine as _;

/// Base64url without padding, used for every key, signature and token on the wire.
pub(crate) fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// Encodes bytes for the wire.
#[must_use]
pub fn encode_b64(bytes: &[u8]) -> String {
    b64().encode(bytes)
}

/// Decodes wire bytes, returning `None` on malformed input.
///
/// Never panics and never allocates more than the input warrants — this is called on
/// attacker-supplied strings before authentication.
#[must_use]
pub fn decode_b64(s: &str) -> Option<Vec<u8>> {
    b64().decode(s).ok()
}

/// Decodes into a fixed-size array, rejecting anything of the wrong length.
#[must_use]
pub fn decode_b64_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    decode_b64(s).and_then(|v| v.try_into().ok())
}
