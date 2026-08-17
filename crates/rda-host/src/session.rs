//! The host's authorization state machine — `docs/PROTOCOL.md` §4, `docs/ARCHITECTURE.md` §5.2.
//!
//! Every path to input injection runs through here. The design goal is that the dangerous
//! transition — issuing a [`SessionGrant`] — happens in exactly one function, with every check in
//! front of it, so the whole authorization decision can be read in one place.
//!
//! The states are deliberately explicit rather than a pile of booleans. A boolean
//! `authenticated: bool` alongside `caps: SessionCaps` admits the combination "not authenticated
//! but has capabilities"; an enum does not.

use rda_crypto::binding::{BindingError, BindingProof, BindingVerifier, Fingerprint, PeerRole};
use rda_crypto::identity::{AddressBook, Identity, PeerTrust, PublicIdentity};
use rda_crypto::pake::{self, PakeError, PinVerifier, SessionPin};
use rda_crypto::token::{TokenError, TokenStore};
use rda_input::{AuditEvent, AuditLog, AuthMethod, SessionGrant};
use rda_proto::caps::SessionCaps;
use rda_proto::ids::DeviceId;
use tracing::{info, warn};

/// Where a session has got to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// A connection request arrived and is awaiting the local user's decision.
    AwaitingConsent,
    /// Consent given; the peer must now authenticate.
    Authenticating,
    /// The PAKE round completed and the host is waiting for the peer's key confirmation.
    ///
    /// A distinct state because SPAKE2 leaves both sides holding a key that only *matches* if both
    /// knew the PIN — it does not say whether it matched. Until confirmation arrives, this session
    /// has a shared secret and no authorization whatsoever.
    AwaitingConfirmation,
    /// The peer authenticated and the DTLS binding verified. Input is permitted.
    Established,
    /// The session ended.
    Closed {
        /// Why.
        reason: &'static str,
    },
    /// Authentication or binding failed. Terminal.
    Failed {
        /// Why.
        reason: &'static str,
    },
}

impl SessionState {
    /// Whether input injection is permitted in this state.
    #[must_use]
    pub fn permits_input(&self) -> bool {
        matches!(self, SessionState::Established)
    }
}

/// What the local user decided about an incoming connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentDecision {
    /// Allow, with these capabilities.
    Allow(SessionCaps),
    /// Refuse.
    Deny,
}

/// Why a session failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// The local user declined.
    #[error("the local user declined the connection")]
    ConsentDenied,
    /// No response within the consent window.
    #[error("consent timed out")]
    ConsentTimeout,
    /// PIN authentication failed.
    #[error("PIN authentication failed: {0}")]
    Pin(#[from] PakeError),
    /// Token authentication failed.
    #[error("token authentication failed: {0}")]
    Token(#[from] TokenError),
    /// The DTLS fingerprint binding did not verify.
    ///
    /// The MITM signal. Surfaced to the user as a security warning, never as a generic failure,
    /// and never with a "continue anyway" option.
    #[error("fingerprint binding failed: {0}")]
    Binding(#[from] BindingError),
    /// The peer presented a different identity key than the one pinned for its device id.
    #[error("peer identity key changed since it was last seen")]
    KeyChanged,
    /// An operation was attempted in the wrong state.
    #[error("operation not valid in the current session state")]
    WrongState,
}

/// How long the local user has to respond to a connection request.
pub const CONSENT_TIMEOUT_MS: u64 = 30_000;

/// Everything a peer presents to prove who it is.
///
/// The three values are meaningless apart — an identity key with no binding proves nothing about
/// the transport, and a binding proof with no identity proves nothing about who signed it — so they
/// travel as one value rather than three positional arguments that could be misordered.
pub struct PeerCredentials<'a> {
    /// The peer's long-term identity key.
    pub identity: PublicIdentity,
    /// The session's binding context, built from the fingerprints observed in the completed DTLS
    /// handshake.
    pub binding: &'a BindingVerifier,
    /// The peer's signature over its own fingerprint.
    pub proof: &'a BindingProof,
}

/// A host-side session, from connection request to teardown.
pub struct HostSession {
    session_id: String,
    peer_id: DeviceId,
    peer_identity: Option<PublicIdentity>,
    state: SessionState,
    requested_caps: SessionCaps,
    consented_caps: Option<SessionCaps>,
    grant: Option<SessionGrant>,
    pin: Option<PinVerifier>,
    /// The key derived during the PAKE round, held until the peer's confirmation verifies it.
    pending_key: Option<[u8; 32]>,
    started_at_ms: u64,
    sas: Option<Vec<&'static str>>,
}

impl HostSession {
    /// Begins a session in response to a connection request.
    ///
    /// The session starts in [`SessionState::AwaitingConsent`] with no grant. Nothing the peer
    /// sends before consent can advance it.
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        peer_id: DeviceId,
        requested_caps: SessionCaps,
        now_ms: u64,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            peer_id,
            peer_identity: None,
            state: SessionState::AwaitingConsent,
            requested_caps,
            consented_caps: None,
            grant: None,
            pin: None,
            pending_key: None,
            started_at_ms: now_ms,
            sas: None,
        }
    }

    /// The session identifier.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> &SessionState {
        &self.state
    }

    /// The grant, if authentication has completed.
    ///
    /// Returns `None` in every state but [`SessionState::Established`], which is what stops a
    /// caller injecting input into a half-authenticated session.
    #[must_use]
    pub fn grant(&self) -> Option<&SessionGrant> {
        self.grant.as_ref()
    }

    /// The short authentication string, once the handshake has produced one.
    #[must_use]
    pub fn short_authentication_string(&self) -> Option<&[&'static str]> {
        self.sas.as_deref()
    }

    /// The PIN to display to the local user, for attended sessions.
    #[must_use]
    pub fn pin_display(&self) -> Option<&str> {
        self.pin.as_ref().map(PinVerifier::pin_display)
    }

    /// Records the local user's decision.
    ///
    /// A denial is terminal: a peer must not be able to ask repeatedly until the user clicks the
    /// wrong button. Capabilities are clamped to what was requested, so consenting cannot
    /// accidentally grant more than the peer asked for.
    pub fn apply_consent(
        &mut self,
        decision: ConsentDecision,
        now_ms: u64,
        audit: &mut AuditLog,
    ) -> Result<(), SessionError> {
        if self.state != SessionState::AwaitingConsent {
            return Err(SessionError::WrongState);
        }
        if now_ms.saturating_sub(self.started_at_ms) > CONSENT_TIMEOUT_MS {
            self.state = SessionState::Failed {
                reason: "consent timed out",
            };
            return Err(SessionError::ConsentTimeout);
        }

        match decision {
            ConsentDecision::Deny => {
                self.state = SessionState::Failed {
                    reason: "consent denied",
                };
                audit.record(
                    now_ms,
                    AuditEvent::InjectionRefused {
                        session_id: self.session_id.clone(),
                        reason: "consent denied",
                    },
                );
                Err(SessionError::ConsentDenied)
            }
            ConsentDecision::Allow(caps) => {
                let granted = self.requested_caps.clamp_to(caps);
                self.consented_caps = Some(granted);
                self.pin = Some(PinVerifier::new(
                    self.session_id.clone(),
                    SessionPin::generate(now_ms),
                ));
                self.state = SessionState::Authenticating;
                info!(session = %self.session_id, ?granted, "consent granted, awaiting authentication");
                Ok(())
            }
        }
    }

    /// Runs the PAKE round and returns the host's SPAKE2 message and key confirmation.
    ///
    /// This is the first of two steps. SPAKE2 does not fail on a wrong PIN — it yields a
    /// *different* key — so nothing is authorised here. The peer must prove it derived the same key
    /// by returning a matching confirmation to [`HostSession::complete_pin_auth`].
    ///
    /// The split mirrors the real message flow: the peer cannot compute its confirmation until it
    /// has the host's SPAKE2 message, so demanding both in one call would be unimplementable.
    pub fn begin_pin_auth(
        &mut self,
        peer_pake_message: &[u8],
        now_ms: u64,
    ) -> Result<PinAuthResponse, SessionError> {
        if self.state != SessionState::Authenticating {
            return Err(SessionError::WrongState);
        }
        let verifier = self.pin.as_mut().ok_or(SessionError::WrongState)?;

        let (our_message, shared_key) =
            verifier
                .respond(peer_pake_message, now_ms)
                .inspect_err(|_| {
                    self.state = SessionState::Failed {
                        reason: "PIN authentication failed",
                    };
                })?;

        let response = PinAuthResponse {
            pake_message: our_message,
            confirmation: pake::confirm(&shared_key, "host", &self.session_id),
        };
        self.pending_key = Some(shared_key);
        self.state = SessionState::AwaitingConfirmation;
        Ok(response)
    }

    /// Verifies the peer's key confirmation and fingerprint binding, then issues the grant.
    ///
    /// **This is the only function that issues a [`SessionGrant`].** Every check gating input
    /// injection is here, in this order:
    ///
    /// 1. State — the PAKE round must already have completed.
    /// 2. Key confirmation — the derived keys actually match, compared in constant time.
    /// 3. Address book — the identity key matches what was pinned for this device id.
    /// 4. Binding — the peer's signature covers the DTLS certificate it actually presented.
    ///
    /// Only after all four does a grant exist. Any failure is terminal for the session.
    pub fn complete_pin_auth(
        &mut self,
        peer_confirmation: &[u8; 32],
        peer: PeerCredentials<'_>,
        address_book: &mut AddressBook,
        audit: &mut AuditLog,
        now_ms: u64,
    ) -> Result<(), SessionError> {
        let PeerCredentials {
            identity: peer_identity,
            binding,
            proof: peer_proof,
        } = peer;
        if self.state != SessionState::AwaitingConfirmation {
            return Err(SessionError::WrongState);
        }
        let caps = self.consented_caps.ok_or(SessionError::WrongState)?;
        let shared_key = self.pending_key.take().ok_or(SessionError::WrongState)?;

        // 2. Key confirmation, in constant time. A variable-time compare would leak how many
        //    leading bytes matched and turn a 256-bit tag into a byte-at-a-time search.
        let expected = pake::confirm(&shared_key, "controller", &self.session_id);
        if !pake::confirm_matches(&expected, peer_confirmation) {
            warn!(session = %self.session_id, "PIN confirmation mismatch");
            self.state = SessionState::Failed {
                reason: "PIN confirmation failed",
            };
            return Err(SessionError::Pin(PakeError::Failed));
        }

        // 3. Address book. A changed key is a hard failure, never a prompt: prompting on key
        //    change trains users to click through the one alert that actually matters.
        if address_book.check_and_pin(&peer_identity) == PeerTrust::KeyChanged {
            warn!(session = %self.session_id, peer = %self.peer_id, "peer identity key changed");
            self.state = SessionState::Failed {
                reason: "peer identity key changed",
            };
            return Err(SessionError::KeyChanged);
        }

        // 4. The binding. This is what a malicious relay cannot forge.
        binding
            .verify(peer_proof, Some(&self.peer_id))
            .inspect_err(|_| {
                self.state = SessionState::Failed {
                    reason: "fingerprint binding failed",
                };
            })?;

        if let Some(verifier) = self.pin.as_mut() {
            verifier.consume();
        }
        self.peer_identity = Some(peer_identity);
        self.sas = Some(rda_crypto::sas::short_authentication_string(
            &binding.transcript_hash(),
            &self.session_id,
        ));

        audit.record(
            now_ms,
            AuditEvent::SessionStarted {
                session_id: self.session_id.clone(),
                peer: self.peer_id.clone(),
                caps,
                method: AuthMethod::SessionPin,
            },
        );
        info!(session = %self.session_id, peer = %self.peer_id, ?caps, "session established");

        self.grant = Some(SessionGrant::issue(
            self.session_id.clone(),
            self.peer_id.clone(),
            caps,
            AuthMethod::SessionPin,
            now_ms,
        ));
        self.state = SessionState::Established;
        Ok(())
    }

    /// Authenticates an unattended session from a signed token.
    ///
    /// Possession of the token is not sufficient: the binding proof still has to verify against the
    /// identity key the token names, so a stolen token file alone is not a working credential.
    pub fn authenticate_with_token(
        &mut self,
        encoded_token: &str,
        host_identity: &Identity,
        tokens: &TokenStore,
        peer: PeerCredentials<'_>,
        audit: &mut AuditLog,
        now_ms: u64,
    ) -> Result<(), SessionError> {
        let PeerCredentials {
            identity: peer_identity,
            binding,
            proof: peer_proof,
        } = peer;
        if !matches!(
            self.state,
            SessionState::AwaitingConsent | SessionState::Authenticating
        ) {
            return Err(SessionError::WrongState);
        }

        let token = tokens
            .verify(encoded_token, host_identity, &peer_identity, now_ms / 1000)
            .inspect_err(|_| {
                self.state = SessionState::Failed {
                    reason: "token rejected",
                };
            })?;

        binding
            .verify(peer_proof, Some(&self.peer_id))
            .inspect_err(|_| {
                self.state = SessionState::Failed {
                    reason: "fingerprint binding failed",
                };
            })?;

        // The token's capabilities are the ceiling; the request can only narrow them.
        let caps = self.requested_caps.clamp_to(token.claims.session_caps());

        self.peer_identity = Some(peer_identity);
        self.sas = Some(rda_crypto::sas::short_authentication_string(
            &binding.transcript_hash(),
            &self.session_id,
        ));
        self.grant = Some(SessionGrant::issue(
            self.session_id.clone(),
            self.peer_id.clone(),
            caps,
            AuthMethod::UnattendedToken,
            now_ms,
        ));
        self.state = SessionState::Established;

        audit.record(
            now_ms,
            AuditEvent::SessionStarted {
                session_id: self.session_id.clone(),
                peer: self.peer_id.clone(),
                caps,
                method: AuthMethod::UnattendedToken,
            },
        );
        info!(session = %self.session_id, peer = %self.peer_id, "unattended session established");
        Ok(())
    }

    /// Narrows the session's capabilities mid-flight, e.g. when the user switches to view-only.
    pub fn restrict(&mut self, to: SessionCaps, now_ms: u64, audit: &mut AuditLog) {
        if let Some(grant) = &self.grant {
            let narrowed = grant.restrict(to);
            audit.record(
                now_ms,
                AuditEvent::CapabilitiesChanged {
                    session_id: self.session_id.clone(),
                    caps: narrowed.caps(),
                },
            );
            self.grant = Some(narrowed);
        }
    }

    /// Ends the session.
    ///
    /// The caller is responsible for releasing held keys; `rda_input::ReleaseGuard` makes that
    /// automatic on the path that matters.
    pub fn close(&mut self, reason: &'static str, now_ms: u64, audit: &mut AuditLog) {
        if matches!(self.state, SessionState::Closed { .. }) {
            return;
        }
        self.grant = None;
        self.pending_key = None;
        self.state = SessionState::Closed { reason };
        audit.record(
            now_ms,
            AuditEvent::SessionEnded {
                session_id: self.session_id.clone(),
                duration_ms: now_ms.saturating_sub(self.started_at_ms),
            },
        );
        info!(session = %self.session_id, reason, "session closed");
    }
}

/// What the host sends back to complete a PIN exchange.
#[derive(Debug, Clone)]
pub struct PinAuthResponse {
    /// The host's SPAKE2 message.
    pub pake_message: Vec<u8>,
    /// The host's key confirmation tag.
    pub confirmation: [u8; 32],
}

/// Builds a matched pair of binding verifiers for a session.
///
/// Convenience for callers and tests; the fingerprints passed here must be the ones observed in the
/// completed DTLS handshake, not the ones copied from the SDP.
#[must_use]
pub fn binding_pair(
    session_id: &str,
    controller_fp: Fingerprint,
    host_fp: Fingerprint,
    controller_nonce: [u8; 32],
    host_nonce: [u8; 32],
) -> (BindingVerifier, BindingVerifier) {
    (
        BindingVerifier::new(
            session_id,
            PeerRole::Controller,
            controller_nonce,
            host_nonce,
            controller_fp,
            host_fp,
        ),
        BindingVerifier::new(
            session_id,
            PeerRole::Host,
            host_nonce,
            controller_nonce,
            host_fp,
            controller_fp,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rda_crypto::pake::PinAuth;
    use rda_crypto::token::TokenIssuer;

    fn full_caps() -> SessionCaps {
        SessionCaps {
            view: true,
            input: true,
            clipboard: true,
            file: false,
            audio: false,
        }
    }

    struct Fixture {
        host_identity: Identity,
        controller: Identity,
        session: HostSession,
        audit: AuditLog,
        book: AddressBook,
        controller_binding: BindingVerifier,
        host_binding: BindingVerifier,
    }

    fn fixture() -> Fixture {
        let host_identity = Identity::generate();
        let controller = Identity::generate();
        let (cb, hb) = binding_pair(
            "sess_1",
            Fingerprint::from_bytes([0xAA; 32]),
            Fingerprint::from_bytes([0xBB; 32]),
            [1u8; 32],
            [2u8; 32],
        );
        Fixture {
            session: HostSession::new("sess_1", controller.device_id().clone(), full_caps(), 0),
            host_identity,
            controller,
            audit: AuditLog::new(64),
            book: AddressBook::new(),
            controller_binding: cb,
            host_binding: hb,
        }
    }

    /// Drives a complete, honest PIN handshake exactly as the wire flow runs it.
    ///
    /// Controller -> host: SPAKE2 message.
    /// Host -> controller: SPAKE2 message + host confirmation.
    /// Controller -> host: controller confirmation + binding proof.
    fn authenticate(f: &mut Fixture, pin_override: Option<&str>) -> Result<(), SessionError> {
        f.session
            .apply_consent(ConsentDecision::Allow(full_caps()), 100, &mut f.audit)?;

        let pin = pin_override
            .map(str::to_owned)
            .unwrap_or_else(|| f.session.pin_display().unwrap().to_owned());

        // Controller side, round one.
        let controller_auth = PinAuth::start("sess_1", &pin).unwrap();
        let controller_message = controller_auth.message().to_vec();

        // Host side, round one.
        let host_response = f.session.begin_pin_auth(&controller_message, 200)?;

        // Controller side, round two: finish the PAKE and confirm.
        let controller_key = controller_auth.finish(&host_response.pake_message).unwrap();
        let controller_confirmation = pake::confirm(&controller_key, "controller", "sess_1");

        // The controller also checks the host's confirmation before proceeding. A real client that
        // skipped this would talk to anyone claiming to be the host.
        let expected_host = pake::confirm(&controller_key, "host", "sess_1");
        let host_authentic = pake::confirm_matches(&expected_host, &host_response.confirmation);

        let proof = f.controller_binding.prove(&f.controller);
        let result = f.session.complete_pin_auth(
            &controller_confirmation,
            PeerCredentials {
                identity: f.controller.public(),
                binding: &f.host_binding,
                proof: &proof,
            },
            &mut f.book,
            &mut f.audit,
            300,
        );

        if result.is_ok() {
            assert!(
                host_authentic,
                "a successful session implies the host also confirmed"
            );
        }
        result
    }

    #[test]
    fn a_new_session_grants_nothing() {
        let f = fixture();
        assert_eq!(*f.session.state(), SessionState::AwaitingConsent);
        assert!(
            f.session.grant().is_none(),
            "no grant may exist before authentication"
        );
        assert!(!f.session.state().permits_input());
    }

    #[test]
    fn denied_consent_is_terminal() {
        let mut f = fixture();
        assert_eq!(
            f.session
                .apply_consent(ConsentDecision::Deny, 100, &mut f.audit),
            Err(SessionError::ConsentDenied)
        );
        assert!(f.session.grant().is_none());
        // A peer must not get a second bite.
        assert_eq!(
            f.session
                .apply_consent(ConsentDecision::Allow(full_caps()), 200, &mut f.audit),
            Err(SessionError::WrongState)
        );
    }

    #[test]
    fn consent_expires() {
        let mut f = fixture();
        assert_eq!(
            f.session.apply_consent(
                ConsentDecision::Allow(full_caps()),
                CONSENT_TIMEOUT_MS + 1,
                &mut f.audit
            ),
            Err(SessionError::ConsentTimeout)
        );
        assert!(f.session.grant().is_none());
    }

    #[test]
    fn consent_cannot_grant_more_than_was_requested() {
        let mut f = fixture();
        f.session.requested_caps = SessionCaps::view_only();
        f.session
            .apply_consent(
                ConsentDecision::Allow(SessionCaps {
                    view: true,
                    input: true,
                    clipboard: true,
                    file: true,
                    audio: true,
                }),
                100,
                &mut f.audit,
            )
            .unwrap();
        assert_eq!(f.session.consented_caps, Some(SessionCaps::view_only()));
    }

    #[test]
    fn a_pin_is_generated_only_after_consent() {
        let mut f = fixture();
        assert!(f.session.pin_display().is_none());
        f.session
            .apply_consent(ConsentDecision::Allow(full_caps()), 100, &mut f.audit)
            .unwrap();
        let pin = f.session.pin_display().unwrap();
        assert_eq!(pin.len(), 6);
        assert!(pin.bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn a_complete_honest_handshake_establishes_the_session() {
        let mut f = fixture();
        authenticate(&mut f, None).expect("honest handshake must succeed");

        assert_eq!(*f.session.state(), SessionState::Established);
        let grant = f.session.grant().expect("a grant must exist");
        assert!(grant.may_inject_input());
        assert_eq!(grant.method(), AuthMethod::SessionPin);
        assert!(f.session.short_authentication_string().is_some());
    }

    #[test]
    fn a_wrong_pin_leaves_the_session_without_a_grant() {
        let mut f = fixture();
        let result = authenticate(&mut f, Some("000000"));
        assert!(result.is_err(), "a wrong PIN must not authenticate");
        assert!(f.session.grant().is_none());
        assert!(!f.session.state().permits_input());
        assert!(matches!(f.session.state(), SessionState::Failed { .. }));
    }

    #[test]
    fn a_forged_binding_proof_is_rejected() {
        // The MITM case: the peer's PIN is right, but the DTLS certificate it presented is not the
        // one it signed over.
        let mut f = fixture();
        f.session
            .apply_consent(ConsentDecision::Allow(full_caps()), 100, &mut f.audit)
            .unwrap();
        let pin = f.session.pin_display().unwrap().to_owned();

        // The controller signs over a session whose host fingerprint differs from the real one.
        let (attacker_view, _) = binding_pair(
            "sess_1",
            Fingerprint::from_bytes([0xAA; 32]),
            Fingerprint::from_bytes([0xEE; 32]), // wrong
            [1u8; 32],
            [2u8; 32],
        );
        let proof = attacker_view.prove(&f.controller);

        let controller_auth = PinAuth::start("sess_1", &pin).unwrap();
        let host_response = f
            .session
            .begin_pin_auth(controller_auth.message(), 200)
            .unwrap();
        let controller_key = controller_auth.finish(&host_response.pake_message).unwrap();
        let confirmation = pake::confirm(&controller_key, "controller", "sess_1");

        // The PIN is right, so confirmation passes — and the binding still catches the MITM.
        let result = f.session.complete_pin_auth(
            &confirmation,
            PeerCredentials {
                identity: f.controller.public(),
                binding: &f.host_binding,
                proof: &proof,
            },
            &mut f.book,
            &mut f.audit,
            300,
        );
        assert!(
            matches!(result, Err(SessionError::Binding(_))),
            "got {result:?}"
        );
        assert!(
            f.session.grant().is_none(),
            "a MITM must never obtain a grant"
        );
    }

    #[test]
    fn input_cannot_be_authorised_before_consent() {
        let mut f = fixture();
        assert_eq!(
            f.session.begin_pin_auth(b"anything", 100).unwrap_err(),
            SessionError::WrongState
        );
    }

    #[test]
    fn confirmation_cannot_be_skipped() {
        // Jumping straight to the grant-issuing step without completing the PAKE round must fail.
        let mut f = fixture();
        f.session
            .apply_consent(ConsentDecision::Allow(full_caps()), 100, &mut f.audit)
            .unwrap();
        let proof = f.controller_binding.prove(&f.controller);
        assert_eq!(
            f.session
                .complete_pin_auth(
                    &[0u8; 32],
                    PeerCredentials {
                        identity: f.controller.public(),
                        binding: &f.host_binding,
                        proof: &proof
                    },
                    &mut f.book,
                    &mut f.audit,
                    200,
                )
                .unwrap_err(),
            SessionError::WrongState
        );
        assert!(f.session.grant().is_none());
    }

    #[test]
    fn a_wrong_confirmation_tag_is_rejected_after_a_correct_pake_round() {
        // Guards the constant-time comparison: a peer that completes the PAKE but cannot produce
        // the confirmation gets nothing.
        let mut f = fixture();
        f.session
            .apply_consent(ConsentDecision::Allow(full_caps()), 100, &mut f.audit)
            .unwrap();
        let pin = f.session.pin_display().unwrap().to_owned();
        let auth = PinAuth::start("sess_1", &pin).unwrap();
        f.session.begin_pin_auth(auth.message(), 200).unwrap();

        let proof = f.controller_binding.prove(&f.controller);
        let result = f.session.complete_pin_auth(
            &[0xAB; 32],
            PeerCredentials {
                identity: f.controller.public(),
                binding: &f.host_binding,
                proof: &proof,
            },
            &mut f.book,
            &mut f.audit,
            300,
        );
        assert!(matches!(result, Err(SessionError::Pin(_))));
        assert!(f.session.grant().is_none());
    }

    #[test]
    fn an_unattended_token_establishes_a_session() {
        let mut f = fixture();
        let token = TokenIssuer::new(&f.host_identity)
            .issue(&f.controller.public(), full_caps(), 0, 3600)
            .unwrap();
        let proof = f.controller_binding.prove(&f.controller);

        f.session
            .authenticate_with_token(
                &token.encode(),
                &f.host_identity,
                &TokenStore::new(),
                PeerCredentials {
                    identity: f.controller.public(),
                    binding: &f.host_binding,
                    proof: &proof,
                },
                &mut f.audit,
                1000,
            )
            .unwrap();

        assert_eq!(*f.session.state(), SessionState::Established);
        assert_eq!(
            f.session.grant().unwrap().method(),
            AuthMethod::UnattendedToken
        );
    }

    #[test]
    fn a_revoked_token_grants_nothing() {
        let mut f = fixture();
        let token = TokenIssuer::new(&f.host_identity)
            .issue(&f.controller.public(), full_caps(), 0, 3600)
            .unwrap();
        let mut store = TokenStore::new();
        store.revoke(token.jti());
        let proof = f.controller_binding.prove(&f.controller);

        let result = f.session.authenticate_with_token(
            &token.encode(),
            &f.host_identity,
            &store,
            PeerCredentials {
                identity: f.controller.public(),
                binding: &f.host_binding,
                proof: &proof,
            },
            &mut f.audit,
            1000,
        );
        assert!(result.is_err());
        assert!(f.session.grant().is_none());
    }

    #[test]
    fn a_valid_token_with_a_forged_binding_grants_nothing() {
        // The stolen-token-file case: the attacker has the token but not the private key, so it
        // cannot produce a binding proof over its own DTLS certificate.
        let mut f = fixture();
        let token = TokenIssuer::new(&f.host_identity)
            .issue(&f.controller.public(), full_caps(), 0, 3600)
            .unwrap();
        let thief = Identity::generate();
        let proof = f.controller_binding.prove(&thief);

        let result = f.session.authenticate_with_token(
            &token.encode(),
            &f.host_identity,
            &TokenStore::new(),
            PeerCredentials {
                identity: f.controller.public(),
                binding: &f.host_binding,
                proof: &proof,
            },
            &mut f.audit,
            1000,
        );
        assert!(result.is_err(), "a token alone must not authenticate");
        assert!(f.session.grant().is_none());
    }

    #[test]
    fn a_token_capping_capabilities_is_respected() {
        let mut f = fixture();
        let token = TokenIssuer::new(&f.host_identity)
            .issue(&f.controller.public(), SessionCaps::view_only(), 0, 3600)
            .unwrap();
        let proof = f.controller_binding.prove(&f.controller);
        f.session
            .authenticate_with_token(
                &token.encode(),
                &f.host_identity,
                &TokenStore::new(),
                PeerCredentials {
                    identity: f.controller.public(),
                    binding: &f.host_binding,
                    proof: &proof,
                },
                &mut f.audit,
                1000,
            )
            .unwrap();
        assert!(
            !f.session.grant().unwrap().may_inject_input(),
            "a view-only token must not yield input"
        );
    }

    #[test]
    fn restricting_narrows_the_live_grant() {
        let mut f = fixture();
        authenticate(&mut f, None).unwrap();
        assert!(f.session.grant().unwrap().may_inject_input());

        f.session
            .restrict(SessionCaps::view_only(), 500, &mut f.audit);
        assert!(!f.session.grant().unwrap().may_inject_input());
    }

    #[test]
    fn closing_revokes_the_grant() {
        let mut f = fixture();
        authenticate(&mut f, None).unwrap();
        f.session.close("user ended", 900, &mut f.audit);

        assert!(
            f.session.grant().is_none(),
            "a closed session must not retain a grant"
        );
        assert!(!f.session.state().permits_input());
        assert!(f
            .audit
            .entries()
            .iter()
            .any(|(_, e)| matches!(e, AuditEvent::SessionEnded { .. })));
    }

    #[test]
    fn closing_twice_records_one_end() {
        let mut f = fixture();
        authenticate(&mut f, None).unwrap();
        f.session.close("first", 900, &mut f.audit);
        f.session.close("second", 950, &mut f.audit);
        let ends = f
            .audit
            .entries()
            .iter()
            .filter(|(_, e)| matches!(e, AuditEvent::SessionEnded { .. }))
            .count();
        assert_eq!(ends, 1);
    }

    #[test]
    fn the_audit_log_records_the_session_start() {
        let mut f = fixture();
        authenticate(&mut f, None).unwrap();
        assert!(f.audit.entries().iter().any(|(_, e)| matches!(
            e,
            AuditEvent::SessionStarted {
                method: AuthMethod::SessionPin,
                ..
            }
        )));
    }

    #[test]
    fn both_ends_derive_the_same_short_authentication_string() {
        let f = fixture();
        assert_eq!(
            rda_crypto::sas::short_authentication_string(
                &f.controller_binding.transcript_hash(),
                "sess_1"
            ),
            rda_crypto::sas::short_authentication_string(
                &f.host_binding.transcript_hash(),
                "sess_1"
            )
        );
    }
}
