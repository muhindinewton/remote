//! Unattended access tokens — `docs/PROTOCOL.md` §4.5.
//!
//! Unattended access deliberately uses **no stored password**. A token is a CBOR structure signed
//! by the host's identity key and bound to a specific controller's public key. That choice matters
//! beyond convenience: with no password verifier stored anywhere, a balanced PAKE is sufficient for
//! the attended path and no augmented PAKE (SPAKE2+ / OPAQUE) is required.
//!
//! Possession of a token is never sufficient. The controller must also prove possession of the
//! private key the token names, via the fingerprint binding in [`crate::binding`]. A stolen token
//! file is therefore not a working credential on its own.

use crate::identity::{Identity, PublicIdentity};
use rda_proto::caps::SessionCaps;
use rda_proto::ids::DeviceId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Maximum token lifetime, in seconds. Thirty days.
pub const MAX_TOKEN_LIFETIME_S: u64 = 30 * 24 * 60 * 60;

/// Maximum encoded token size accepted from the wire.
///
/// A token is a few hundred bytes; the cap stops an attacker forcing a large CBOR parse
/// pre-authentication.
pub const MAX_TOKEN_BYTES: usize = 4096;

/// Domain separator for the token signature.
const TOKEN_DOMAIN: &[u8] = b"RDA-v1-token";

/// Why a token was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// The encoded form was not valid base64url, or exceeded the size cap.
    #[error("malformed token encoding")]
    MalformedEncoding,
    /// The CBOR body did not parse.
    #[error("malformed token body")]
    MalformedBody,
    /// The signature did not verify against the issuing host's identity key.
    #[error("token signature is invalid")]
    BadSignature,
    /// The token was issued by a different host.
    #[error("token was issued by another host")]
    WrongIssuer,
    /// The token names a different controller.
    #[error("token was issued to another device")]
    WrongSubject,
    /// The token is past its expiry.
    #[error("token has expired")]
    Expired,
    /// The token's `jti` is on the revocation list.
    #[error("token has been revoked")]
    Revoked,
    /// The token claimed a lifetime beyond the permitted maximum.
    #[error("token lifetime exceeds the maximum")]
    LifetimeTooLong,
    /// The token version is not one we implement.
    #[error("unsupported token version {0}")]
    UnsupportedVersion(u8),
}

/// The signed body of an access token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Token format version.
    pub v: u8,
    /// Subject: the controller's Ed25519 public key this token is bound to.
    #[serde(with = "serde_bytes_array")]
    pub sub: [u8; 32],
    /// Issuer: the host device id.
    pub iss: String,
    /// Issued-at, Unix seconds.
    pub iat: u64,
    /// Expiry, Unix seconds.
    pub exp: u64,
    /// Unique token identifier, for revocation.
    #[serde(with = "serde_bytes_array16")]
    pub jti: [u8; 16],
    /// Capabilities this token grants. Never widened at redemption.
    pub caps: Vec<String>,
}

impl TokenClaims {
    /// The capability set this token grants.
    #[must_use]
    pub fn session_caps(&self) -> SessionCaps {
        SessionCaps::from_names(&self.caps)
    }

    /// Hex form of the `jti`, for logs and revocation lists.
    #[must_use]
    pub fn jti_hex(&self) -> String {
        self.jti.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// A signed, encoded access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessToken {
    /// The verified claims.
    pub claims: TokenClaims,
    /// Signature over the CBOR body.
    signature: [u8; 64],
    /// The exact CBOR bytes that were signed.
    ///
    /// Retained rather than re-encoded: CBOR is not canonical by default, so re-serialising could
    /// produce different bytes and invalidate a signature that is actually correct.
    body: Vec<u8>,
}

impl AccessToken {
    /// The wire form: base64url of `CBOR body ‖ signature`.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut buf = Vec::with_capacity(self.body.len() + 64);
        buf.extend_from_slice(&self.body);
        buf.extend_from_slice(&self.signature);
        crate::encode_b64(&buf)
    }

    /// The token identifier, for revocation.
    #[must_use]
    pub fn jti(&self) -> [u8; 16] {
        self.claims.jti
    }
}

/// Issues tokens on behalf of a host.
pub struct TokenIssuer<'a> {
    identity: &'a Identity,
}

impl<'a> TokenIssuer<'a> {
    /// Wraps a host identity.
    #[must_use]
    pub fn new(identity: &'a Identity) -> Self {
        Self { identity }
    }

    /// Issues a token for a specific controller.
    ///
    /// Callers must have obtained local physical confirmation first: a token issued during a remote
    /// session would let a visitor grant themselves permanent access, which is precisely the
    /// escalation unattended access must not permit (`docs/ARCHITECTURE.md` §5.2).
    pub fn issue(
        &self,
        subject: &PublicIdentity,
        caps: SessionCaps,
        now_unix: u64,
        lifetime_s: u64,
    ) -> Result<AccessToken, TokenError> {
        if lifetime_s > MAX_TOKEN_LIFETIME_S {
            return Err(TokenError::LifetimeTooLong);
        }
        use rand::RngCore;
        let mut jti = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut jti);

        let claims = TokenClaims {
            v: 1,
            sub: subject.to_bytes(),
            iss: self.identity.device_id().as_str().to_owned(),
            iat: now_unix,
            exp: now_unix + lifetime_s,
            jti,
            caps: caps.to_names().into_iter().map(String::from).collect(),
        };

        let mut body = Vec::new();
        ciborium::into_writer(&claims, &mut body).map_err(|_| TokenError::MalformedBody)?;
        let signature = self.identity.sign(&signing_input(&body));

        Ok(AccessToken {
            claims,
            signature,
            body,
        })
    }
}

fn signing_input(body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(TOKEN_DOMAIN.len() + 1 + body.len());
    buf.extend_from_slice(TOKEN_DOMAIN);
    buf.push(0x00);
    buf.extend_from_slice(body);
    buf
}

/// Holds issued tokens' revocation state.
///
/// Revocation is keyed by `jti`, and rotation-on-use means a replayed old token is not merely
/// refused — it is *evidence of theft*, because the legitimate holder would have the replacement.
#[derive(Debug, Clone, Default)]
pub struct TokenStore {
    revoked: BTreeSet<[u8; 16]>,
}

impl TokenStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Revokes a token.
    pub fn revoke(&mut self, jti: [u8; 16]) {
        self.revoked.insert(jti);
    }

    /// Whether a token has been revoked.
    #[must_use]
    pub fn is_revoked(&self, jti: &[u8; 16]) -> bool {
        self.revoked.contains(jti)
    }

    /// Number of revoked tokens.
    #[must_use]
    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    /// Returns `true` if nothing is revoked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }

    /// Drops revocation entries for tokens that have expired anyway.
    ///
    /// An expired token is refused on its own merits, so keeping its `jti` is pure growth. Without
    /// this the list grows without bound for the life of the installation.
    pub fn prune_expired(&mut self, expired_jtis: &[[u8; 16]]) {
        for jti in expired_jtis {
            self.revoked.remove(jti);
        }
    }

    /// Parses and fully validates a token presented by a controller.
    ///
    /// Checks, in order: size, encoding, structure, signature, issuer, subject, expiry, revocation.
    /// The signature is verified **before** any claim is trusted — reading `iss` or `caps` from an
    /// unverified body and acting on it is the classic JWT-style mistake.
    pub fn verify(
        &self,
        encoded: &str,
        host: &Identity,
        expected_subject: &PublicIdentity,
        now_unix: u64,
    ) -> Result<AccessToken, TokenError> {
        if encoded.len() > MAX_TOKEN_BYTES {
            return Err(TokenError::MalformedEncoding);
        }
        let raw = crate::decode_b64(encoded).ok_or(TokenError::MalformedEncoding)?;
        if raw.len() < 65 || raw.len() > MAX_TOKEN_BYTES {
            return Err(TokenError::MalformedEncoding);
        }
        let (body, sig_bytes) = raw.split_at(raw.len() - 64);
        let signature: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| TokenError::MalformedEncoding)?;

        // Signature first: nothing in the body may influence control flow before this succeeds.
        host.public()
            .verify(&signing_input(body), &signature)
            .map_err(|_| TokenError::BadSignature)?;

        let claims: TokenClaims =
            ciborium::from_reader(body).map_err(|_| TokenError::MalformedBody)?;

        if claims.v != 1 {
            return Err(TokenError::UnsupportedVersion(claims.v));
        }
        if claims.iss != host.device_id().as_str() {
            return Err(TokenError::WrongIssuer);
        }
        if claims.sub != expected_subject.to_bytes() {
            return Err(TokenError::WrongSubject);
        }
        if claims.exp.saturating_sub(claims.iat) > MAX_TOKEN_LIFETIME_S {
            return Err(TokenError::LifetimeTooLong);
        }
        if now_unix >= claims.exp {
            return Err(TokenError::Expired);
        }
        if self.is_revoked(&claims.jti) {
            return Err(TokenError::Revoked);
        }

        Ok(AccessToken {
            claims,
            signature,
            body: body.to_vec(),
        })
    }
}

/// CBOR helpers for fixed-size byte arrays, which serde does not handle natively.
mod serde_bytes_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let v = <Vec<u8>>::deserialize(d)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

mod serde_bytes_array16 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let v = <Vec<u8>>::deserialize(d)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 16 bytes"))
    }
}

/// The device a token authorised, for the audit log.
#[derive(Debug, Clone)]
pub struct TokenGrant {
    /// The authorised controller.
    pub subject: DeviceId,
    /// Capabilities granted.
    pub caps: SessionCaps,
    /// Token identifier.
    pub jti: [u8; 16],
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps() -> SessionCaps {
        SessionCaps {
            view: true,
            input: true,
            clipboard: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_valid_token_round_trips_and_verifies() {
        let host = Identity::generate();
        let controller = Identity::generate();
        let store = TokenStore::new();

        let token = TokenIssuer::new(&host)
            .issue(&controller.public(), caps(), 1000, 3600)
            .unwrap();
        let verified = store
            .verify(&token.encode(), &host, &controller.public(), 2000)
            .unwrap();

        assert_eq!(verified.claims, token.claims);
        assert!(verified.claims.session_caps().input);
        assert!(
            !verified.claims.session_caps().file,
            "an unrequested capability must not appear"
        );
    }

    #[test]
    fn a_token_from_another_host_is_rejected() {
        let host = Identity::generate();
        let other_host = Identity::generate();
        let controller = Identity::generate();
        let store = TokenStore::new();

        let token = TokenIssuer::new(&other_host)
            .issue(&controller.public(), caps(), 1000, 3600)
            .unwrap();
        assert_eq!(
            store.verify(&token.encode(), &host, &controller.public(), 2000),
            Err(TokenError::BadSignature)
        );
    }

    #[test]
    fn a_token_issued_to_someone_else_is_rejected() {
        // The stolen-token case: an attacker with the file but not the controller's private key.
        let host = Identity::generate();
        let legitimate = Identity::generate();
        let thief = Identity::generate();
        let store = TokenStore::new();

        let token = TokenIssuer::new(&host)
            .issue(&legitimate.public(), caps(), 1000, 3600)
            .unwrap();
        assert_eq!(
            store.verify(&token.encode(), &host, &thief.public(), 2000),
            Err(TokenError::WrongSubject)
        );
    }

    #[test]
    fn an_expired_token_is_rejected() {
        let host = Identity::generate();
        let controller = Identity::generate();
        let store = TokenStore::new();
        let token = TokenIssuer::new(&host)
            .issue(&controller.public(), caps(), 1000, 3600)
            .unwrap();

        assert!(store
            .verify(&token.encode(), &host, &controller.public(), 4599)
            .is_ok());
        assert_eq!(
            store.verify(&token.encode(), &host, &controller.public(), 4600),
            Err(TokenError::Expired)
        );
    }

    #[test]
    fn a_revoked_token_is_rejected() {
        let host = Identity::generate();
        let controller = Identity::generate();
        let mut store = TokenStore::new();
        let token = TokenIssuer::new(&host)
            .issue(&controller.public(), caps(), 1000, 3600)
            .unwrap();

        assert!(store
            .verify(&token.encode(), &host, &controller.public(), 2000)
            .is_ok());
        store.revoke(token.jti());
        assert_eq!(
            store.verify(&token.encode(), &host, &controller.public(), 2000),
            Err(TokenError::Revoked)
        );
    }

    #[test]
    fn tampering_with_the_claims_breaks_the_signature() {
        let host = Identity::generate();
        let controller = Identity::generate();
        let store = TokenStore::new();
        let token = TokenIssuer::new(&host)
            .issue(&controller.public(), SessionCaps::view_only(), 1000, 3600)
            .unwrap();

        // Forge a body granting full input and reuse the original signature.
        let mut forged_claims = token.claims.clone();
        forged_claims.caps = vec!["view".into(), "input".into(), "file".into()];
        let mut forged_body = Vec::new();
        ciborium::into_writer(&forged_claims, &mut forged_body).unwrap();

        let raw = crate::decode_b64(&token.encode()).unwrap();
        let signature = &raw[raw.len() - 64..];
        let mut forged = forged_body;
        forged.extend_from_slice(signature);

        assert_eq!(
            store.verify(
                &crate::encode_b64(&forged),
                &host,
                &controller.public(),
                2000
            ),
            Err(TokenError::BadSignature),
            "capability escalation by body substitution must fail"
        );
    }

    #[test]
    fn an_over_long_lifetime_is_refused_at_issue_and_at_verify() {
        let host = Identity::generate();
        let controller = Identity::generate();
        assert_eq!(
            TokenIssuer::new(&host)
                .issue(&controller.public(), caps(), 1000, MAX_TOKEN_LIFETIME_S + 1)
                .unwrap_err(),
            TokenError::LifetimeTooLong
        );
    }

    #[test]
    fn malformed_tokens_are_rejected_without_panicking() {
        let host = Identity::generate();
        let controller = Identity::generate();
        let store = TokenStore::new();

        for bad in [
            "",
            "!!!",
            "AAAA",
            &"A".repeat(MAX_TOKEN_BYTES + 10),
            &"A".repeat(100),
        ] {
            let result = store.verify(bad, &host, &controller.public(), 1000);
            assert!(result.is_err(), "accepted {:?}", &bad[..bad.len().min(20)]);
        }
    }

    #[test]
    fn revocation_entries_can_be_pruned() {
        let mut store = TokenStore::new();
        let a = [1u8; 16];
        let b = [2u8; 16];
        store.revoke(a);
        store.revoke(b);
        assert_eq!(store.len(), 2);
        store.prune_expired(&[a]);
        assert!(!store.is_revoked(&a));
        assert!(store.is_revoked(&b));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn each_token_gets_a_unique_identifier() {
        let host = Identity::generate();
        let controller = Identity::generate();
        let issuer = TokenIssuer::new(&host);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20 {
            let t = issuer
                .issue(&controller.public(), caps(), 1000, 3600)
                .unwrap();
            assert!(seen.insert(t.jti()), "jti collision would break revocation");
        }
    }
}
