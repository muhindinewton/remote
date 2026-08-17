//! PIN authentication via SPAKE2 — `docs/PROTOCOL.md` §4.4.
//!
//! A six-digit PIN carries about 20 bits of entropy. Sending it — even hashed — would let anyone
//! who captures the exchange grind it offline in under a second. SPAKE2 is a balanced
//! password-authenticated key exchange: both sides prove they know the PIN without either the
//! network or the rendezvous server learning anything that permits an offline guess. An attacker
//! gets exactly one online guess per exchange.
//!
//! **The attempt cap, not the entropy, is what makes a six-digit PIN safe.** [`PinVerifier`]
//! enforces it, and that enforcement is normative, not advisory.

use rda_proto::ids::DeviceId;
use spake2::{Ed25519Group, Identity as PakeIdentity, Password, Spake2};

/// Domain separator for deriving the PAKE password from the PIN.
const PIN_DOMAIN: &[u8] = b"RDA-v1-pin";

/// Identity string for the controller side of the exchange.
const ID_CONTROLLER: &[u8] = b"RDA-v1-controller";
/// Identity string for the host side.
const ID_HOST: &[u8] = b"RDA-v1-host";

/// Number of digits in a session PIN.
pub const PIN_DIGITS: usize = 6;

/// How many attempts a PIN survives before it is invalidated.
///
/// Three online guesses against 10^6 possibilities is a 3-in-a-million chance. Raising this
/// materially weakens the scheme; it is a security parameter, not a usability knob.
pub const MAX_PIN_ATTEMPTS: u32 = 3;

/// How long a PIN remains valid, in milliseconds.
pub const PIN_TTL_MS: u64 = 5 * 60 * 1000;

/// Errors from the PAKE exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PakeError {
    /// The peer's SPAKE2 message was malformed or the exchange failed.
    ///
    /// Indistinguishable from a wrong PIN by design: revealing which occurred would let an
    /// attacker separate "wrong guess" from "protocol error" and probe more efficiently.
    #[error("PIN authentication failed")]
    Failed,
    /// The PIN was not exactly [`PIN_DIGITS`] decimal digits.
    #[error("PIN must be {PIN_DIGITS} digits")]
    MalformedPin,
    /// The PIN expired, was already used, or ran out of attempts.
    #[error("PIN is no longer valid")]
    Expired,
    /// The attempt cap was reached; the PIN has been invalidated.
    #[error("too many PIN attempts")]
    AttemptsExceeded,
}

/// A single-use session PIN held by the host.
#[derive(Clone)]
pub struct SessionPin {
    digits: String,
    issued_ms: u64,
    attempts: u32,
    consumed: bool,
}

impl std::fmt::Debug for SessionPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The PIN itself is a credential; keep it out of logs and crash dumps.
        f.debug_struct("SessionPin")
            .field("attempts", &self.attempts)
            .field("consumed", &self.consumed)
            .finish_non_exhaustive()
    }
}

impl SessionPin {
    /// Generates a uniformly random PIN from the OS CSPRNG.
    ///
    /// Uniform sampling matters: a modulo-biased generator would concentrate probability on some
    /// PINs and cut the effective entropy an attacker has to search.
    #[must_use]
    pub fn generate(now_ms: u64) -> Self {
        use rand::Rng;
        let value: u32 = rand::rngs::OsRng.gen_range(0..1_000_000);
        Self {
            digits: format!("{value:06}"),
            issued_ms: now_ms,
            attempts: 0,
            consumed: false,
        }
    }

    /// Wraps a specific PIN. Test and manual-entry use only.
    pub fn from_digits(digits: &str, now_ms: u64) -> Result<Self, PakeError> {
        if digits.len() != PIN_DIGITS || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(PakeError::MalformedPin);
        }
        Ok(Self {
            digits: digits.to_owned(),
            issued_ms: now_ms,
            attempts: 0,
            consumed: false,
        })
    }

    /// The digits, for display to the local user who will read them aloud.
    #[must_use]
    pub fn display(&self) -> &str {
        &self.digits
    }

    /// Whether the PIN can still be used.
    #[must_use]
    pub fn is_usable(&self, now_ms: u64) -> bool {
        !self.consumed
            && self.attempts < MAX_PIN_ATTEMPTS
            && now_ms.saturating_sub(self.issued_ms) <= PIN_TTL_MS
    }

    /// Attempts made so far.
    #[must_use]
    pub fn attempts(&self) -> u32 {
        self.attempts
    }
}

/// Derives the PAKE password from a PIN and session id.
///
/// Binding the session id in means a PIN captured from one session cannot be replayed into
/// another, even within its five-minute lifetime.
fn pake_password(session_id: &str, pin: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(PIN_DOMAIN);
    h.update([0x00]);
    h.update(session_id.as_bytes());
    h.update(pin.as_bytes());
    h.finalize().to_vec()
}

/// The controller's half of the exchange.
///
/// Consumed by [`PinAuth::finish`]: SPAKE2 state is single-use, and the type system enforces that
/// rather than leaving it to discipline.
pub struct PinAuth {
    state: Spake2<Ed25519Group>,
    outbound: Vec<u8>,
}

impl std::fmt::Debug for PinAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinAuth").finish_non_exhaustive()
    }
}

impl PinAuth {
    /// Starts the controller side, returning the state and the message to send.
    pub fn start(session_id: &str, pin: &str) -> Result<Self, PakeError> {
        if pin.len() != PIN_DIGITS || !pin.bytes().all(|b| b.is_ascii_digit()) {
            return Err(PakeError::MalformedPin);
        }
        let (state, outbound) = Spake2::<Ed25519Group>::start_a(
            &Password::new(pake_password(session_id, pin)),
            &PakeIdentity::new(ID_CONTROLLER),
            &PakeIdentity::new(ID_HOST),
        );
        Ok(Self { state, outbound })
    }

    /// The SPAKE2 message to send to the host.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.outbound
    }

    /// Completes the exchange, yielding the shared key.
    ///
    /// Both sides derive the same key only if both knew the PIN. A mismatch surfaces as
    /// [`PakeError::Failed`] here or as differing keys — which is why callers must confirm the key
    /// with [`confirm`] rather than assuming success.
    pub fn finish(self, peer_message: &[u8]) -> Result<[u8; 32], PakeError> {
        let key = self
            .state
            .finish(peer_message)
            .map_err(|_| PakeError::Failed)?;
        key.try_into().map_err(|_| PakeError::Failed)
    }
}

/// The host's half: holds the PIN, enforces the attempt cap.
pub struct PinVerifier {
    session_id: String,
    pin: SessionPin,
}

impl std::fmt::Debug for PinVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinVerifier")
            .field("session_id", &self.session_id)
            .field("attempts", &self.pin.attempts)
            .finish_non_exhaustive()
    }
}

impl PinVerifier {
    /// Binds a PIN to a session.
    #[must_use]
    pub fn new(session_id: impl Into<String>, pin: SessionPin) -> Self {
        Self {
            session_id: session_id.into(),
            pin,
        }
    }

    /// The PIN for local display.
    #[must_use]
    pub fn pin_display(&self) -> &str {
        self.pin.display()
    }

    /// Attempts remaining before the PIN is invalidated.
    #[must_use]
    pub fn attempts_remaining(&self) -> u32 {
        MAX_PIN_ATTEMPTS.saturating_sub(self.pin.attempts)
    }

    /// Responds to a controller's SPAKE2 message.
    ///
    /// Counts the attempt **before** doing any cryptography, so an attacker cannot spend attempts
    /// for free by aborting mid-exchange.
    pub fn respond(
        &mut self,
        peer_message: &[u8],
        now_ms: u64,
    ) -> Result<(Vec<u8>, [u8; 32]), PakeError> {
        if !self.pin.is_usable(now_ms) {
            return Err(if self.pin.attempts >= MAX_PIN_ATTEMPTS {
                PakeError::AttemptsExceeded
            } else {
                PakeError::Expired
            });
        }
        self.pin.attempts += 1;

        let (state, outbound) = Spake2::<Ed25519Group>::start_b(
            &Password::new(pake_password(&self.session_id, self.pin.display())),
            &PakeIdentity::new(ID_CONTROLLER),
            &PakeIdentity::new(ID_HOST),
        );
        let key: [u8; 32] = state
            .finish(peer_message)
            .map_err(|_| PakeError::Failed)?
            .try_into()
            .map_err(|_| PakeError::Failed)?;

        Ok((outbound, key))
    }

    /// Marks the PIN as spent after a confirmed-successful exchange.
    pub fn consume(&mut self) {
        self.pin.consumed = true;
    }
}

/// Derives a key confirmation tag.
///
/// SPAKE2 alone leaves both sides with a key that only *matches* if both knew the PIN — it does not
/// tell you whether it matched. Exchanging and comparing these tags is what turns "we each have a
/// key" into "we have the *same* key", and it must happen before any capability is granted.
#[must_use]
pub fn confirm(key: &[u8; 32], role: &str, session_id: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"RDA-v1-pin-confirm");
    h.update([0x00]);
    h.update(key);
    h.update(role.as_bytes());
    h.update(session_id.as_bytes());
    h.finalize().into()
}

/// Compares two confirmation tags in constant time.
///
/// A variable-time comparison here leaks how many leading bytes matched, which turns a 256-bit tag
/// into a byte-at-a-time guessing game.
#[must_use]
pub fn confirm_matches(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Which device a PIN exchange authorised, for the caller's audit log.
#[derive(Debug, Clone)]
pub struct PinOutcome {
    /// The authenticated peer.
    pub peer: DeviceId,
    /// Shared key, usable for further key derivation.
    pub shared_key: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs a full exchange and returns both derived keys.
    fn exchange(
        session: &str,
        host_pin: &str,
        controller_pin: &str,
        now_ms: u64,
    ) -> Result<([u8; 32], [u8; 32]), PakeError> {
        let mut verifier = PinVerifier::new(session, SessionPin::from_digits(host_pin, 0).unwrap());
        let auth = PinAuth::start(session, controller_pin)?;
        let (host_msg, host_key) = verifier.respond(auth.message(), now_ms)?;
        let controller_key = auth.finish(&host_msg)?;
        Ok((controller_key, host_key))
    }

    #[test]
    fn matching_pins_derive_the_same_key() {
        let (a, b) = exchange("sess_1", "314159", "314159", 0).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn a_wrong_pin_derives_a_different_key() {
        // SPAKE2 does not error on a wrong password; it yields a different key. This is exactly why
        // the confirmation step below is mandatory rather than optional.
        let (a, b) = exchange("sess_1", "314159", "271828", 0).unwrap();
        assert_ne!(a, b, "a wrong PIN must not produce the shared key");
    }

    #[test]
    fn confirmation_tags_catch_a_wrong_pin() {
        let (controller_key, host_key) = exchange("sess_1", "314159", "271828", 0).unwrap();
        let controller_tag = confirm(&controller_key, "controller", "sess_1");
        let host_expectation = confirm(&host_key, "controller", "sess_1");
        assert!(
            !confirm_matches(&controller_tag, &host_expectation),
            "a wrong PIN must fail confirmation"
        );
    }

    #[test]
    fn confirmation_tags_agree_on_the_right_pin() {
        let (controller_key, host_key) = exchange("sess_1", "314159", "314159", 0).unwrap();
        assert!(confirm_matches(
            &confirm(&controller_key, "controller", "sess_1"),
            &confirm(&host_key, "controller", "sess_1")
        ));
        // Role separation: the two directions must not produce interchangeable tags, or a
        // reflection attack replays the host's confirmation back at it.
        assert!(!confirm_matches(
            &confirm(&controller_key, "controller", "sess_1"),
            &confirm(&host_key, "host", "sess_1")
        ));
    }

    #[test]
    fn the_same_pin_in_another_session_does_not_authenticate() {
        // The session id is mixed into the PAKE password, so a captured PIN cannot be replayed
        // into a different session even inside its five-minute window.
        let mut verifier =
            PinVerifier::new("sess_2", SessionPin::from_digits("314159", 0).unwrap());
        let auth = PinAuth::start("sess_1", "314159").unwrap();
        let (host_msg, host_key) = verifier.respond(auth.message(), 0).unwrap();
        let controller_key = auth.finish(&host_msg).unwrap();
        assert_ne!(controller_key, host_key);
    }

    #[test]
    fn attempts_are_capped_and_then_the_pin_dies() {
        let mut verifier =
            PinVerifier::new("sess_1", SessionPin::from_digits("314159", 0).unwrap());
        for i in 0..MAX_PIN_ATTEMPTS {
            let wrong = PinAuth::start("sess_1", "000000").unwrap();
            assert!(
                verifier.respond(wrong.message(), 0).is_ok(),
                "attempt {i} should run"
            );
        }
        assert_eq!(verifier.attempts_remaining(), 0);

        // Even the correct PIN is refused now — the credential is burned, not merely rate-limited.
        let right = PinAuth::start("sess_1", "314159").unwrap();
        assert_eq!(
            verifier.respond(right.message(), 0),
            Err(PakeError::AttemptsExceeded)
        );
    }

    #[test]
    fn a_failed_exchange_still_spends_an_attempt() {
        // Otherwise an attacker aborts mid-exchange and guesses for free.
        let mut verifier =
            PinVerifier::new("sess_1", SessionPin::from_digits("314159", 0).unwrap());
        assert_eq!(verifier.attempts_remaining(), MAX_PIN_ATTEMPTS);
        let _ = verifier.respond(b"garbage that will not parse", 0);
        assert_eq!(verifier.attempts_remaining(), MAX_PIN_ATTEMPTS - 1);
    }

    #[test]
    fn an_expired_pin_is_refused() {
        let mut verifier =
            PinVerifier::new("sess_1", SessionPin::from_digits("314159", 0).unwrap());
        let auth = PinAuth::start("sess_1", "314159").unwrap();
        assert_eq!(
            verifier.respond(auth.message(), PIN_TTL_MS + 1),
            Err(PakeError::Expired)
        );
    }

    #[test]
    fn a_consumed_pin_cannot_be_reused() {
        let mut verifier =
            PinVerifier::new("sess_1", SessionPin::from_digits("314159", 0).unwrap());
        let auth = PinAuth::start("sess_1", "314159").unwrap();
        verifier.respond(auth.message(), 0).unwrap();
        verifier.consume();
        let again = PinAuth::start("sess_1", "314159").unwrap();
        assert_eq!(
            verifier.respond(again.message(), 0),
            Err(PakeError::Expired)
        );
    }

    #[test]
    fn malformed_pins_are_rejected() {
        for bad in ["", "12345", "1234567", "12345a", "abcdef", " 12345"] {
            assert_eq!(
                PinAuth::start("s", bad).unwrap_err(),
                PakeError::MalformedPin,
                "{bad:?}"
            );
            assert!(SessionPin::from_digits(bad, 0).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn generated_pins_are_six_digits_and_vary() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            let pin = SessionPin::generate(0);
            assert_eq!(pin.display().len(), PIN_DIGITS);
            assert!(pin.display().bytes().all(|b| b.is_ascii_digit()));
            seen.insert(pin.display().to_string());
        }
        assert!(
            seen.len() > 40,
            "generated PINs are not varying: {} unique",
            seen.len()
        );
    }

    #[test]
    fn debug_output_never_contains_the_pin() {
        let pin = SessionPin::from_digits("314159", 0).unwrap();
        let verifier = PinVerifier::new("sess_1", pin.clone());
        assert!(!format!("{pin:?}").contains("314159"));
        assert!(!format!("{verifier:?}").contains("314159"));
    }

    #[test]
    fn confirmation_comparison_rejects_near_misses() {
        let tag = confirm(&[7u8; 32], "host", "sess_1");
        let mut almost = tag;
        almost[31] ^= 0x01;
        assert!(!confirm_matches(&tag, &almost));
        assert!(confirm_matches(&tag, &tag));
    }
}
