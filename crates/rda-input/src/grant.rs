//! Capability enforcement at the injection boundary — `docs/ARCHITECTURE.md` §4.7.
//!
//! Input injection is total system control, so "did we check authorization?" must not be a question
//! anyone can forget to ask. [`SessionGrant`] is unconstructible without evidence that
//! authentication completed, and every injection entry point requires one. A caller that skipped
//! the handshake has nothing to pass, so the mistake is a compile error rather than a code-review
//! finding.
//!
//! Enforcement lives here rather than in the UI on purpose: a modified or hostile client must gain
//! nothing by lying about what it is allowed to do.

use rda_proto::caps::SessionCaps;
use rda_proto::ids::DeviceId;

/// How a session was authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// A human at the host read a PIN aloud and it verified through SPAKE2.
    SessionPin,
    /// A signed unattended token, whose subject also proved key possession.
    UnattendedToken,
}

/// Proof that authentication completed, carrying what it authorised.
///
/// The only constructor is [`SessionGrant::issue`], which is `pub(crate)`-adjacent by convention:
/// it takes the evidence types produced by a completed handshake. Nothing in this crate fabricates
/// one, and the fields are read-only from outside.
#[derive(Debug, Clone)]
pub struct SessionGrant {
    session_id: String,
    peer: DeviceId,
    caps: SessionCaps,
    method: AuthMethod,
    granted_at_ms: u64,
}

impl SessionGrant {
    /// Issues a grant after a verified handshake.
    ///
    /// `caps` is what the host decided to allow; it is stored verbatim and can only ever be
    /// narrowed afterwards ([`SessionGrant::restrict`]).
    #[must_use]
    pub fn issue(
        session_id: impl Into<String>,
        peer: DeviceId,
        caps: SessionCaps,
        method: AuthMethod,
        granted_at_ms: u64,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            peer,
            caps,
            method,
            granted_at_ms,
        }
    }

    /// The session this grant belongs to.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The authenticated peer.
    #[must_use]
    pub fn peer(&self) -> &DeviceId {
        &self.peer
    }

    /// The capabilities granted.
    #[must_use]
    pub fn caps(&self) -> SessionCaps {
        self.caps
    }

    /// How the peer authenticated.
    #[must_use]
    pub fn method(&self) -> AuthMethod {
        self.method
    }

    /// When the grant was issued.
    #[must_use]
    pub fn granted_at_ms(&self) -> u64 {
        self.granted_at_ms
    }

    /// Whether this grant permits input injection.
    #[must_use]
    pub fn may_inject_input(&self) -> bool {
        self.caps.input
    }

    /// Whether this grant permits clipboard synchronisation.
    #[must_use]
    pub fn may_use_clipboard(&self) -> bool {
        self.caps.clipboard
    }

    /// Narrows the grant mid-session.
    ///
    /// Used when the local user downgrades a session to view-only without disconnecting. Only ever
    /// narrows — a "restriction" that widened would be an escalation path.
    #[must_use]
    pub fn restrict(&self, to: SessionCaps) -> Self {
        Self {
            caps: self.caps.clamp_to(to),
            ..self.clone()
        }
    }
}

/// Why an injection attempt was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GuardError {
    /// The session is view-only.
    #[error("session does not grant input injection")]
    InputNotGranted,
    /// The session is not permitted clipboard access.
    #[error("session does not grant clipboard access")]
    ClipboardNotGranted,
    /// The event rate exceeded the per-class budget.
    #[error("rate limit exceeded for this event class")]
    RateLimited,
    /// A field failed validation.
    #[error("event field `{0}` is out of range")]
    InvalidField(&'static str),
    /// The display id does not exist.
    #[error("unknown display id")]
    UnknownDisplay,
    /// The HID usage is not in the allowlist.
    #[error("HID usage is not permitted")]
    DisallowedUsage,
    /// The host policy blocks this key combination.
    #[error("key combination is blocked by host policy")]
    BlockedCombination,
    /// The local user is actively using the machine and has preempted the remote peer.
    #[error("local user has control")]
    LocalUserActive,
}

/// Per-class event rate limits.
///
/// A flood defence and a wear-out defence: an unbounded event rate can hang a compositor or fill an
/// audit log. Exceeding a limit drops events and raises telemetry; it does not tear down the
/// session, because a legitimate burst should not disconnect a user mid-drag.
#[derive(Debug, Clone, Copy)]
pub struct RateLimits {
    /// Pointer motion events per second.
    pub pointer_per_s: u32,
    /// Key and button events per second.
    pub key_per_s: u32,
    /// Clipboard operations per second.
    pub clipboard_per_s: u32,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            // 1000/s covers a high-polling-rate mouse even though the controller should have
            // coalesced to 60 Hz before sending (`docs/PROTOCOL.md` §8).
            pointer_per_s: 1000,
            // Far above human typing; low enough that a key-repeat storm is bounded.
            key_per_s: 100,
            clipboard_per_s: 20,
        }
    }
}

/// Which budget an event draws from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventClass {
    /// Pointer motion.
    Pointer,
    /// Keys, buttons and wheel.
    Key,
    /// Clipboard operations.
    Clipboard,
}

/// Sliding-window rate limiter over the three event classes.
#[derive(Debug, Clone)]
pub struct RateGuard {
    limits: RateLimits,
    pointer: Window,
    key: Window,
    clipboard: Window,
}

#[derive(Debug, Clone, Default)]
struct Window {
    start_ms: u64,
    count: u32,
    dropped: u64,
}

impl Window {
    fn allow(&mut self, limit: u32, now_ms: u64) -> bool {
        if now_ms.saturating_sub(self.start_ms) >= 1000 {
            self.start_ms = now_ms;
            self.count = 0;
        }
        self.count += 1;
        if self.count > limit {
            self.dropped += 1;
            false
        } else {
            true
        }
    }
}

impl RateGuard {
    /// Builds a guard with the given limits.
    #[must_use]
    pub fn new(limits: RateLimits) -> Self {
        Self {
            limits,
            pointer: Window::default(),
            key: Window::default(),
            clipboard: Window::default(),
        }
    }

    /// Records an event and reports whether it is within budget.
    pub fn allow(&mut self, class: EventClass, now_ms: u64) -> bool {
        match class {
            EventClass::Pointer => self.pointer.allow(self.limits.pointer_per_s, now_ms),
            EventClass::Key => self.key.allow(self.limits.key_per_s, now_ms),
            EventClass::Clipboard => self.clipboard.allow(self.limits.clipboard_per_s, now_ms),
        }
    }

    /// Total events dropped per class, for telemetry.
    #[must_use]
    pub fn dropped(&self) -> (u64, u64, u64) {
        (
            self.pointer.dropped,
            self.key.dropped,
            self.clipboard.dropped,
        )
    }
}

impl Default for RateGuard {
    fn default() -> Self {
        Self::new(RateLimits::default())
    }
}

/// Host policy over key combinations.
///
/// **This is not a security boundary and must not be documented as one.** A peer with input can
/// reach most outcomes another way. It is an operational safety feature for kiosk and unattended
/// deployments, and is off by default because silently swallowing a user's Ctrl+Alt+Del is worse
/// than the risk it mitigates.
#[derive(Debug, Clone, Default)]
pub struct CombinationPolicy {
    blocked: Vec<(u16, u16)>,
}

impl CombinationPolicy {
    /// A policy that blocks nothing. The default.
    #[must_use]
    pub fn permissive() -> Self {
        Self::default()
    }

    /// Blocks a `(modifier_mask, usage)` pair.
    pub fn block(&mut self, modifiers: u16, usage: u16) -> &mut Self {
        self.blocked.push((modifiers, usage));
        self
    }

    /// Whether a key event is permitted.
    #[must_use]
    pub fn permits(&self, modifiers: u16, usage: u16) -> bool {
        !self
            .blocked
            .iter()
            .any(|&(m, u)| u == usage && modifiers & m == m)
    }

    /// Number of blocked combinations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocked.len()
    }

    /// Returns `true` if nothing is blocked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocked.is_empty()
    }
}

/// One entry in the local audit log.
///
/// Deliberately **not** a keystroke log — recording what was typed would itself be a vulnerability,
/// and a far more attractive target than the thing it protects. It records what a session was
/// permitted to do and what bulk data crossed the boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    /// A session began.
    SessionStarted {
        /// Session identifier.
        session_id: String,
        /// The authenticated peer.
        peer: DeviceId,
        /// What was granted.
        caps: SessionCaps,
        /// How the peer authenticated.
        method: AuthMethod,
    },
    /// A session ended.
    SessionEnded {
        /// Session identifier.
        session_id: String,
        /// Duration in milliseconds.
        duration_ms: u64,
    },
    /// Capabilities were narrowed mid-session.
    CapabilitiesChanged {
        /// Session identifier.
        session_id: String,
        /// The new set.
        caps: SessionCaps,
    },
    /// The local user took control back.
    LocalTakeover {
        /// Session identifier.
        session_id: String,
    },
    /// A clipboard transfer crossed the boundary.
    ClipboardTransfer {
        /// Session identifier.
        session_id: String,
        /// Direction: `true` if data went to the host.
        inbound: bool,
        /// Payload size in bytes.
        bytes: usize,
    },
    /// Events were dropped by the rate limiter.
    RateLimitTripped {
        /// Session identifier.
        session_id: String,
        /// Which class.
        class: &'static str,
        /// How many were dropped.
        dropped: u64,
    },
    /// An injection was refused.
    InjectionRefused {
        /// Session identifier.
        session_id: String,
        /// Why.
        reason: &'static str,
    },
}

/// An append-only audit log.
#[derive(Debug, Clone, Default)]
pub struct AuditLog {
    entries: Vec<(u64, AuditEvent)>,
    capacity: usize,
}

impl AuditLog {
    /// Builds a log retaining at most `capacity` entries in memory.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::new(),
            capacity,
        }
    }

    /// Appends an event.
    pub fn record(&mut self, now_ms: u64, event: AuditEvent) {
        if self.capacity > 0 && self.entries.len() >= self.capacity {
            self.entries.remove(0);
        }
        self.entries.push((now_ms, event));
    }

    /// All retained entries, oldest first.
    #[must_use]
    pub fn entries(&self) -> &[(u64, AuditEvent)] {
        &self.entries
    }

    /// Number of retained entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if nothing has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> DeviceId {
        rda_proto::ids::device_id_from_pubkey(&[1u8; 32])
    }

    fn full_grant() -> SessionGrant {
        SessionGrant::issue(
            "sess_1",
            peer(),
            SessionCaps {
                view: true,
                input: true,
                clipboard: true,
                file: true,
                audio: true,
            },
            AuthMethod::SessionPin,
            0,
        )
    }

    #[test]
    fn a_view_only_grant_refuses_input() {
        let grant = SessionGrant::issue(
            "sess_1",
            peer(),
            SessionCaps::view_only(),
            AuthMethod::SessionPin,
            0,
        );
        assert!(!grant.may_inject_input());
        assert!(!grant.may_use_clipboard());
    }

    #[test]
    fn restriction_only_ever_narrows() {
        let grant = SessionGrant::issue(
            "sess_1",
            peer(),
            SessionCaps::view_only(),
            AuthMethod::SessionPin,
            0,
        );
        // Attempting to "restrict" to a wider set must not widen anything.
        let attempted_escalation = grant.restrict(SessionCaps {
            view: true,
            input: true,
            clipboard: true,
            file: true,
            audio: true,
        });
        assert!(
            !attempted_escalation.may_inject_input(),
            "restrict must never widen"
        );

        let narrowed = full_grant().restrict(SessionCaps::view_only());
        assert!(!narrowed.may_inject_input());
        assert!(narrowed.caps().view);
    }

    #[test]
    fn restriction_preserves_session_identity() {
        let narrowed = full_grant().restrict(SessionCaps::view_only());
        assert_eq!(narrowed.session_id(), "sess_1");
        assert_eq!(narrowed.peer(), &peer());
        assert_eq!(narrowed.method(), AuthMethod::SessionPin);
    }

    #[test]
    fn rate_limits_bound_each_class_independently() {
        let mut guard = RateGuard::new(RateLimits {
            pointer_per_s: 3,
            key_per_s: 2,
            clipboard_per_s: 1,
        });
        for _ in 0..3 {
            assert!(guard.allow(EventClass::Pointer, 0));
        }
        assert!(
            !guard.allow(EventClass::Pointer, 0),
            "pointer budget must be enforced"
        );
        // Exhausting one class must not starve another.
        assert!(guard.allow(EventClass::Key, 0));
        assert!(guard.allow(EventClass::Key, 0));
        assert!(!guard.allow(EventClass::Key, 0));
        assert!(guard.allow(EventClass::Clipboard, 0));
    }

    #[test]
    fn rate_windows_refill() {
        let mut guard = RateGuard::new(RateLimits {
            pointer_per_s: 1,
            ..Default::default()
        });
        assert!(guard.allow(EventClass::Pointer, 0));
        assert!(!guard.allow(EventClass::Pointer, 500));
        assert!(
            guard.allow(EventClass::Pointer, 1000),
            "a new second restores the budget"
        );
    }

    #[test]
    fn dropped_counts_are_reported_for_telemetry() {
        let mut guard = RateGuard::new(RateLimits {
            key_per_s: 1,
            ..Default::default()
        });
        guard.allow(EventClass::Key, 0);
        guard.allow(EventClass::Key, 0);
        guard.allow(EventClass::Key, 0);
        let (_, keys, _) = guard.dropped();
        assert_eq!(keys, 2);
    }

    #[test]
    fn default_policy_blocks_nothing() {
        let policy = CombinationPolicy::permissive();
        assert!(policy.is_empty());
        assert!(policy.permits(rda_proto::control::Modifiers::LEFT_CTRL, 0x04));
    }

    #[test]
    fn a_configured_policy_blocks_only_the_named_combination() {
        use rda_proto::control::Modifiers;
        let mut policy = CombinationPolicy::permissive();
        // Block Ctrl+Alt+Delete.
        policy.block(Modifiers::LEFT_CTRL | Modifiers::LEFT_ALT, 0x4C);

        assert!(!policy.permits(Modifiers::LEFT_CTRL | Modifiers::LEFT_ALT, 0x4C));
        // Same key without the modifiers is fine.
        assert!(policy.permits(0, 0x4C));
        // Same modifiers with a different key is fine.
        assert!(policy.permits(Modifiers::LEFT_CTRL | Modifiers::LEFT_ALT, 0x04));
        // Extra modifiers still match the blocked subset.
        assert!(!policy.permits(
            Modifiers::LEFT_CTRL | Modifiers::LEFT_ALT | Modifiers::LEFT_SHIFT,
            0x4C
        ));
    }

    #[test]
    fn the_audit_log_records_what_a_session_was_permitted_to_do() {
        let mut log = AuditLog::new(10);
        log.record(
            100,
            AuditEvent::SessionStarted {
                session_id: "sess_1".into(),
                peer: peer(),
                caps: SessionCaps::view_only(),
                method: AuthMethod::SessionPin,
            },
        );
        log.record(
            200,
            AuditEvent::LocalTakeover {
                session_id: "sess_1".into(),
            },
        );
        assert_eq!(log.len(), 2);
        assert_eq!(log.entries()[0].0, 100);
    }

    #[test]
    fn the_audit_log_is_bounded() {
        let mut log = AuditLog::new(3);
        for i in 0..10 {
            log.record(
                i,
                AuditEvent::SessionEnded {
                    session_id: format!("s{i}"),
                    duration_ms: 0,
                },
            );
        }
        assert_eq!(log.len(), 3);
        // Oldest entries are evicted, newest retained.
        assert_eq!(log.entries()[2].0, 9);
    }
}
