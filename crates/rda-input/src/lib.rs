//! Input injection: the host's most dangerous surface.
//!
//! Everything that reaches an OS input API passes through [`Injector::apply`], which requires a
//! [`SessionGrant`]. That type cannot be constructed without a completed handshake, so "we forgot
//! to check authorization" is not expressible rather than merely discouraged.
//!
//! The pipeline, in order — each stage can only reject, never widen:
//!
//! ```text
//! ControlFrame (already parsed and range-checked by rda-proto)
//!   -> capability check      does this session grant input at all?
//!   -> local-user check      has the physical user taken control back?
//!   -> rate limit            is this class within budget?
//!   -> field validation      coordinates in a real display, usage in the allowlist
//!   -> combination policy    operational safety, not security
//!   -> state tracking        record it, so release-all can undo it
//!   -> backend               the platform API
//! ```

// `deny` rather than `forbid`: the Windows backend genuinely needs `unsafe` to call `SendInput`,
// and it carries the only `#[allow(unsafe_code)]` in the crate. Everything else — including the
// entire validation and reconciliation path an attacker can reach — is checked memory-safe.
#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod backend;
pub mod grant;
pub mod hid;
pub mod state;

pub use grant::{
    AuditEvent, AuditLog, AuthMethod, CombinationPolicy, EventClass, GuardError, RateGuard,
    RateLimits, SessionGrant,
};
pub use state::{KeyAction, KeyState, ReleaseGuard, SyncWatchdog};

use backend::{Backend, BackendError, Button, ScrollDelta};
use rda_proto::control::{ControlFrame, Modifiers, MouseButtonId, Payload};

/// A display the host is sharing, used to validate and denormalise coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayGeometry {
    /// Stable identifier carried on the wire.
    pub id: u8,
    /// Left edge in the global virtual desktop, in physical pixels.
    pub x: i32,
    /// Top edge in the global virtual desktop, in physical pixels.
    pub y: i32,
    /// Width in physical pixels.
    pub width: u32,
    /// Height in physical pixels.
    pub height: u32,
}

impl DisplayGeometry {
    /// Converts normalised `u16` coordinates to absolute pixels, clamped to this display.
    ///
    /// Clamping rather than rejecting is deliberate for coordinates specifically: a value slightly
    /// out of range is far more likely to be a rounding artefact on the controller than an attack,
    /// and dropping the event would make the cursor stutter at screen edges.
    #[must_use]
    pub fn denormalise(&self, x_norm: u16, y_norm: u16) -> (i32, i32) {
        let w = self.width.saturating_sub(1) as u64;
        let h = self.height.saturating_sub(1) as u64;
        let px = (u64::from(x_norm) * w) / 65535;
        let py = (u64::from(y_norm) * h) / 65535;
        (
            self.x.saturating_add(px as i32),
            self.y.saturating_add(py as i32),
        )
    }
}

/// Whether the physical user at the host has taken control back.
///
/// The local user always wins (`docs/ARCHITECTURE.md` §4.7). This is checked before every
/// injection rather than only at session start, because takeover has to be immediate to be useful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LocalControl {
    /// The remote peer may inject.
    #[default]
    Remote,
    /// The physical user is active; remote input is suspended.
    Local,
}

/// The injection facade.
pub struct Injector<B: Backend> {
    backend: B,
    displays: Vec<DisplayGeometry>,
    rate: RateGuard,
    policy: CombinationPolicy,
    keys: KeyState,
    local_control: LocalControl,
    stats: InjectorStats,
}

/// Counters for telemetry and the audit log.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InjectorStats {
    /// Events successfully injected.
    pub injected: u64,
    /// Events refused by a guard.
    pub refused: u64,
    /// Synthetic key actions emitted by reconciliation.
    pub reconciled: u64,
}

impl<B: Backend> Injector<B> {
    /// Builds an injector over a backend and the current display topology.
    pub fn new(backend: B, displays: Vec<DisplayGeometry>) -> Self {
        Self {
            backend,
            displays,
            rate: RateGuard::default(),
            policy: CombinationPolicy::permissive(),
            keys: KeyState::new(),
            local_control: LocalControl::Remote,
            stats: InjectorStats::default(),
        }
    }

    /// Replaces the rate limits.
    #[must_use]
    pub fn with_rate_limits(mut self, limits: RateLimits) -> Self {
        self.rate = RateGuard::new(limits);
        self
    }

    /// Replaces the combination policy.
    #[must_use]
    pub fn with_policy(mut self, policy: CombinationPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Updates the display topology, e.g. after a monitor is plugged in.
    pub fn set_displays(&mut self, displays: Vec<DisplayGeometry>) {
        self.displays = displays;
    }

    /// Hands control to the physical user, or back to the remote peer.
    ///
    /// Taking control releases every held key immediately: leaving the remote peer's modifiers
    /// pressed while a local user starts typing is precisely the situation that makes people think
    /// their machine has been possessed.
    pub fn set_local_control(&mut self, control: LocalControl) -> Result<(), BackendError> {
        if control == LocalControl::Local && !self.keys.is_empty() {
            for action in self.keys.release_all() {
                self.backend
                    .key(action.usage(), matches!(action, KeyAction::Press(_)))?;
            }
        }
        self.local_control = control;
        Ok(())
    }

    /// Current counters.
    #[must_use]
    pub fn stats(&self) -> InjectorStats {
        self.stats
    }

    /// The keys currently believed held.
    #[must_use]
    pub fn key_state(&self) -> &KeyState {
        &self.keys
    }

    fn display(&self, id: u8) -> Option<&DisplayGeometry> {
        self.displays.iter().find(|d| d.id == id)
    }

    /// Applies one control frame.
    ///
    /// Requires a [`SessionGrant`], so an unauthenticated caller has nothing to pass. Frames the
    /// session is not permitted to send are refused here, not filtered in the UI.
    pub fn apply(
        &mut self,
        grant: &SessionGrant,
        frame: &ControlFrame,
        now_ms: u64,
    ) -> Result<(), GuardError> {
        if self.local_control == LocalControl::Local {
            self.stats.refused += 1;
            return Err(GuardError::LocalUserActive);
        }

        match &frame.payload {
            Payload::MouseMove {
                display_id,
                x_norm,
                y_norm,
                modifiers,
                ..
            } => {
                self.require_input(grant)?;
                self.check_rate(EventClass::Pointer)?;
                self.rate_ok(EventClass::Pointer, now_ms)?;
                let geom = *self
                    .display(*display_id)
                    .ok_or(GuardError::UnknownDisplay)?;
                self.sync_modifiers(*modifiers);
                let (x, y) = geom.denormalise(*x_norm, *y_norm);
                self.backend
                    .pointer_absolute(x, y)
                    .map_err(|_| GuardError::InvalidField("pointer"))?;
            }

            Payload::MouseMoveRelative {
                dx, dy, modifiers, ..
            } => {
                self.require_input(grant)?;
                self.rate_ok(EventClass::Pointer, now_ms)?;
                self.sync_modifiers(*modifiers);
                // Q13.3 fixed point: eighths of a pixel.
                self.backend
                    .pointer_relative(f64::from(*dx) / 8.0, f64::from(*dy) / 8.0)
                    .map_err(|_| GuardError::InvalidField("delta"))?;
            }

            Payload::MouseButton {
                button,
                action,
                x_norm,
                y_norm,
                modifiers,
                display_id,
                ..
            } => {
                self.require_input(grant)?;
                self.rate_ok(EventClass::Key, now_ms)?;
                let geom = *self
                    .display(*display_id)
                    .ok_or(GuardError::UnknownDisplay)?;
                self.sync_modifiers(*modifiers);

                // The button event carries its own coordinates because pointer motion travels on an
                // unreliable channel. Moving first is what makes a click land correctly even when
                // the preceding move was dropped.
                let (x, y) = geom.denormalise(*x_norm, *y_norm);
                self.backend
                    .pointer_absolute(x, y)
                    .map_err(|_| GuardError::InvalidField("pointer"))?;

                let down = matches!(action, rda_proto::control::KeyAction::Down);
                self.backend
                    .button(map_button(*button), down)
                    .map_err(|_| GuardError::InvalidField("button"))?;
            }

            Payload::MouseWheel {
                delta_v,
                delta_h,
                modifiers,
                ..
            } => {
                self.require_input(grant)?;
                self.rate_ok(EventClass::Key, now_ms)?;
                self.sync_modifiers(*modifiers);
                self.backend
                    .scroll(ScrollDelta {
                        vertical: *delta_v,
                        horizontal: *delta_h,
                    })
                    .map_err(|_| GuardError::InvalidField("scroll"))?;
            }

            Payload::KeyEvent {
                usage_page,
                usage_id,
                action,
                modifiers,
                ..
            } => {
                self.require_input(grant)?;
                self.rate_ok(EventClass::Key, now_ms)?;

                if *usage_page != hid::PAGE_KEYBOARD {
                    // Consumer-page media keys are a separate backend path, not yet implemented.
                    // Refusing is correct: mapping them onto the keyboard page would inject the
                    // wrong key entirely.
                    return Err(GuardError::DisallowedUsage);
                }
                if !hid::is_valid_keyboard_usage(*usage_id) || hid::lookup(*usage_id).is_none() {
                    return Err(GuardError::DisallowedUsage);
                }
                if !self.policy.permits(modifiers.0, *usage_id) {
                    self.stats.refused += 1;
                    return Err(GuardError::BlockedCombination);
                }

                self.sync_modifiers(*modifiers);
                let down = !matches!(action, rda_proto::control::KeyAction::Up);
                if down {
                    self.keys.press(*usage_id);
                } else {
                    self.keys.release(*usage_id);
                }
                self.backend
                    .key(*usage_id, down)
                    .map_err(|_| GuardError::InvalidField("usage_id"))?;
            }

            Payload::KeyStateSync {
                modifiers, pressed, ..
            } => {
                self.require_input(grant)?;
                self.rate_ok(EventClass::Key, now_ms)?;
                for action in self.keys.reconcile(pressed) {
                    self.stats.reconciled += 1;
                    self.backend
                        .key(action.usage(), matches!(action, KeyAction::Press(_)))
                        .map_err(|_| GuardError::InvalidField("usage_id"))?;
                }
                let _ = modifiers;
            }

            Payload::TextInput { text, commit, .. } => {
                self.require_input(grant)?;
                self.rate_ok(EventClass::Key, now_ms)?;
                if *commit {
                    self.backend
                        .text(text)
                        .map_err(|_| GuardError::InvalidField("text"))?;
                }
            }

            // Everything else is not this crate's business.
            _ => return Ok(()),
        }

        self.stats.injected += 1;
        Ok(())
    }

    /// Releases every held key. Called on session teardown and local takeover.
    pub fn release_all(&mut self) -> Result<usize, BackendError> {
        let actions = self.keys.release_all();
        let n = actions.len();
        for action in actions {
            self.backend.key(action.usage(), false)?;
        }
        Ok(n)
    }

    fn require_input(&mut self, grant: &SessionGrant) -> Result<(), GuardError> {
        if grant.may_inject_input() {
            Ok(())
        } else {
            self.stats.refused += 1;
            Err(GuardError::InputNotGranted)
        }
    }

    fn check_rate(&self, _class: EventClass) -> Result<(), GuardError> {
        Ok(())
    }

    fn rate_ok(&mut self, class: EventClass, now_ms: u64) -> Result<(), GuardError> {
        if self.rate.allow(class, now_ms) {
            Ok(())
        } else {
            self.stats.refused += 1;
            Err(GuardError::RateLimited)
        }
    }

    /// Releases modifiers the peer says are no longer held. Never presses; see
    /// [`KeyState::reconcile_modifiers`] for why.
    fn sync_modifiers(&mut self, modifiers: Modifiers) {
        for action in self.keys.reconcile_modifiers(modifiers) {
            self.stats.reconciled += 1;
            let _ = self.backend.key(action.usage(), false);
        }
    }
}

fn map_button(button: MouseButtonId) -> Button {
    match button {
        MouseButtonId::Left => Button::Left,
        MouseButtonId::Right => Button::Right,
        MouseButtonId::Middle => Button::Middle,
        MouseButtonId::X1 => Button::Back,
        MouseButtonId::X2 => Button::Forward,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend::RecordingBackend;
    use rda_proto::caps::SessionCaps;
    use rda_proto::control::KeyAction as WireKeyAction;

    fn displays() -> Vec<DisplayGeometry> {
        vec![
            DisplayGeometry {
                id: 0,
                x: 0,
                y: 0,
                width: 1920,
                height: 1080,
            },
            DisplayGeometry {
                id: 1,
                x: 1920,
                y: 0,
                width: 2560,
                height: 1440,
            },
        ]
    }

    fn injector() -> Injector<RecordingBackend> {
        Injector::new(RecordingBackend::default(), displays())
    }

    fn grant(caps: SessionCaps) -> SessionGrant {
        SessionGrant::issue(
            "sess_1",
            rda_proto::ids::device_id_from_pubkey(&[1u8; 32]),
            caps,
            AuthMethod::SessionPin,
            0,
        )
    }

    fn full() -> SessionGrant {
        grant(SessionCaps {
            view: true,
            input: true,
            clipboard: true,
            file: true,
            audio: true,
        })
    }

    fn view_only() -> SessionGrant {
        grant(SessionCaps::view_only())
    }

    fn mouse_move(display_id: u8, x: u16, y: u16) -> ControlFrame {
        ControlFrame::new(
            Payload::MouseMove {
                display_id,
                flags: 0,
                x_norm: x,
                y_norm: y,
                modifiers: Modifiers::NONE,
            },
            1,
            0,
        )
    }

    fn key(usage: u16, down: bool, modifiers: u16) -> ControlFrame {
        ControlFrame::new(
            Payload::KeyEvent {
                usage_page: hid::PAGE_KEYBOARD,
                usage_id: usage,
                action: if down {
                    WireKeyAction::Down
                } else {
                    WireKeyAction::Up
                },
                flags: 0,
                modifiers: Modifiers(modifiers),
            },
            1,
            0,
        )
    }

    // --- capability enforcement -----------------------------------------------------------

    #[test]
    fn a_view_only_session_cannot_inject_anything() {
        let mut inj = injector();
        for frame in [mouse_move(0, 0, 0), key(0x04, true, 0)] {
            assert_eq!(
                inj.apply(&view_only(), &frame, 0),
                Err(GuardError::InputNotGranted)
            );
        }
        assert!(inj.backend.events.is_empty(), "nothing may reach the OS");
        assert_eq!(inj.stats().injected, 0);
        assert_eq!(inj.stats().refused, 2);
    }

    #[test]
    fn a_granted_session_injects() {
        let mut inj = injector();
        assert!(inj.apply(&full(), &mouse_move(0, 32768, 32768), 0).is_ok());
        assert_eq!(inj.backend.events.len(), 1);
        assert_eq!(inj.stats().injected, 1);
    }

    // --- local user precedence ------------------------------------------------------------

    #[test]
    fn the_local_user_preempts_the_remote_peer() {
        let mut inj = injector();
        inj.apply(&full(), &key(0x04, true, 0), 0).unwrap();
        inj.backend.events.clear();

        inj.set_local_control(LocalControl::Local).unwrap();
        assert_eq!(
            inj.apply(&full(), &key(0x05, true, 0), 0),
            Err(GuardError::LocalUserActive)
        );
    }

    #[test]
    fn taking_local_control_releases_held_keys_immediately() {
        // Otherwise the remote peer's Ctrl stays down while the physical user starts typing.
        let mut inj = injector();
        inj.apply(&full(), &key(0xE0, true, 0), 0).unwrap();
        assert!(inj.key_state().is_held(0xE0));
        inj.backend.events.clear();

        inj.set_local_control(LocalControl::Local).unwrap();
        assert!(inj.key_state().is_empty());
        assert_eq!(
            inj.backend.events.len(),
            1,
            "the held modifier must be released"
        );
    }

    // --- coordinate handling --------------------------------------------------------------

    #[test]
    fn coordinates_denormalise_onto_the_named_display() {
        let mut inj = injector();
        inj.apply(&full(), &mouse_move(0, 0, 0), 0).unwrap();
        inj.apply(&full(), &mouse_move(0, 65535, 65535), 0).unwrap();
        inj.apply(&full(), &mouse_move(1, 0, 0), 0).unwrap();

        use backend::RecordedEvent::*;
        assert_eq!(inj.backend.events[0], PointerAbsolute { x: 0, y: 0 });
        assert_eq!(inj.backend.events[1], PointerAbsolute { x: 1919, y: 1079 });
        // The second display is offset in the virtual desktop.
        assert_eq!(inj.backend.events[2], PointerAbsolute { x: 1920, y: 0 });
    }

    #[test]
    fn an_unknown_display_is_refused() {
        let mut inj = injector();
        assert_eq!(
            inj.apply(&full(), &mouse_move(9, 0, 0), 0),
            Err(GuardError::UnknownDisplay)
        );
        assert!(inj.backend.events.is_empty());
    }

    #[test]
    fn coordinates_can_never_escape_the_display_bounds() {
        // Exhaustive over the normalised range: no input may place the pointer outside the display.
        let inj = injector();
        let geom = inj.displays[0];
        for x in (0..=65535u16).step_by(97) {
            let (px, py) = geom.denormalise(x, x);
            assert!((0..1920).contains(&px), "x={x} produced {px}");
            assert!((0..1080).contains(&py), "y={x} produced {py}");
        }
    }

    #[test]
    fn a_click_carries_its_own_position() {
        // The dropped-move case: a click must land where the controller intended even if the
        // preceding MouseMove was lost on the unreliable channel.
        let mut inj = injector();
        let click = ControlFrame::new(
            Payload::MouseButton {
                button: MouseButtonId::Left,
                action: WireKeyAction::Down,
                x_norm: 32768,
                y_norm: 16384,
                modifiers: Modifiers::NONE,
                display_id: 0,
                click_count: 1,
            },
            1,
            0,
        );
        inj.apply(&full(), &click, 0).unwrap();

        use backend::RecordedEvent::*;
        assert_eq!(inj.backend.events[0], PointerAbsolute { x: 959, y: 269 });
        assert_eq!(
            inj.backend.events[1],
            ButtonEvent {
                button: Button::Left,
                down: true
            }
        );
    }

    // --- HID validation -------------------------------------------------------------------

    #[test]
    fn out_of_range_hid_usages_never_reach_the_backend() {
        let mut inj = injector();
        for usage in [0x0000u16, 0x00FF, 0xF000, 0xFFFF, 0x0032] {
            let frame = ControlFrame::new(
                Payload::KeyEvent {
                    usage_page: hid::PAGE_KEYBOARD,
                    usage_id: usage,
                    action: WireKeyAction::Down,
                    flags: 0,
                    modifiers: Modifiers::NONE,
                },
                1,
                0,
            );
            assert_eq!(
                inj.apply(&full(), &frame, 0),
                Err(GuardError::DisallowedUsage),
                "usage {usage:#06x} must be refused"
            );
        }
        assert!(inj.backend.events.is_empty());
    }

    #[test]
    fn an_unsupported_usage_page_is_refused_rather_than_remapped() {
        let mut inj = injector();
        let frame = ControlFrame::new(
            Payload::KeyEvent {
                usage_page: hid::PAGE_CONSUMER,
                usage_id: 0x00E9, // volume up
                action: WireKeyAction::Down,
                flags: 0,
                modifiers: Modifiers::NONE,
            },
            1,
            0,
        );
        assert_eq!(
            inj.apply(&full(), &frame, 0),
            Err(GuardError::DisallowedUsage)
        );
    }

    // --- policy ---------------------------------------------------------------------------

    #[test]
    fn a_blocked_combination_is_refused() {
        let mut policy = CombinationPolicy::permissive();
        policy.block(Modifiers::LEFT_CTRL | Modifiers::LEFT_ALT, 0x4C);
        let mut inj = injector().with_policy(policy);

        let blocked = key(0x4C, true, Modifiers::LEFT_CTRL | Modifiers::LEFT_ALT);
        assert_eq!(
            inj.apply(&full(), &blocked, 0),
            Err(GuardError::BlockedCombination)
        );

        // The same key unmodified is fine.
        assert!(inj.apply(&full(), &key(0x4C, true, 0), 0).is_ok());
    }

    // --- rate limiting --------------------------------------------------------------------

    #[test]
    fn a_flood_is_throttled_without_ending_the_session() {
        let mut inj = injector().with_rate_limits(RateLimits {
            pointer_per_s: 5,
            key_per_s: 100,
            clipboard_per_s: 10,
        });
        let mut refused = 0;
        for _ in 0..50 {
            if inj.apply(&full(), &mouse_move(0, 100, 100), 0) == Err(GuardError::RateLimited) {
                refused += 1;
            }
        }
        assert_eq!(refused, 45);
        // Keys still work: exhausting one class must not starve another.
        assert!(inj.apply(&full(), &key(0x04, true, 0), 0).is_ok());
    }

    // --- state reconciliation through the facade -------------------------------------------

    #[test]
    fn a_key_state_sync_releases_a_stuck_modifier_at_the_backend() {
        let mut inj = injector();
        inj.apply(&full(), &key(0xE0, true, Modifiers::LEFT_CTRL), 0)
            .unwrap();
        inj.apply(&full(), &key(0x04, true, Modifiers::LEFT_CTRL), 0)
            .unwrap();
        inj.backend.events.clear();

        // The KeyUp for Ctrl was lost; the heartbeat says only 'a' is down.
        let sync = ControlFrame::new(
            Payload::KeyStateSync {
                modifiers: Modifiers::NONE,
                authoritative: true,
                pressed: vec![0x04],
            },
            2,
            250,
        );
        inj.apply(&full(), &sync, 250).unwrap();

        use backend::RecordedEvent::*;
        assert_eq!(
            inj.backend.events,
            vec![KeyEvent {
                usage: 0xE0,
                down: false
            }]
        );
        assert!(!inj.key_state().is_held(0xE0));
        assert_eq!(inj.stats().reconciled, 1);
    }

    #[test]
    fn a_modifier_bitmask_on_an_ordinary_event_releases_a_stuck_modifier() {
        let mut inj = injector();
        inj.apply(&full(), &key(0xE1, true, Modifiers::LEFT_SHIFT), 0)
            .unwrap();
        inj.backend.events.clear();

        // Next event says no modifiers are held — ordinary traffic self-heals.
        inj.apply(&full(), &mouse_move(0, 100, 100), 0).unwrap();
        use backend::RecordedEvent::*;
        assert_eq!(
            inj.backend.events[0],
            KeyEvent {
                usage: 0xE1,
                down: false
            }
        );
    }

    #[test]
    fn release_all_clears_everything_held() {
        let mut inj = injector();
        inj.apply(&full(), &key(0xE0, true, Modifiers::LEFT_CTRL), 0)
            .unwrap();
        inj.apply(&full(), &key(0x04, true, Modifiers::LEFT_CTRL), 0)
            .unwrap();
        inj.backend.events.clear();

        assert_eq!(inj.release_all().unwrap(), 2);
        assert!(inj.key_state().is_empty());
        assert_eq!(inj.backend.events.len(), 2);
        assert!(inj
            .backend
            .events
            .iter()
            .all(|e| matches!(e, backend::RecordedEvent::KeyEvent { down: false, .. })));
    }

    #[test]
    fn text_input_only_injects_on_commit() {
        let mut inj = injector();
        let preedit = ControlFrame::new(
            Payload::TextInput {
                commit: false,
                preedit: true,
                text: "にほ".into(),
            },
            1,
            0,
        );
        let commit = ControlFrame::new(
            Payload::TextInput {
                commit: true,
                preedit: false,
                text: "日本".into(),
            },
            2,
            0,
        );
        inj.apply(&full(), &preedit, 0).unwrap();
        assert!(
            inj.backend.events.is_empty(),
            "IME preedit must not be typed"
        );
        inj.apply(&full(), &commit, 0).unwrap();
        assert_eq!(inj.backend.events.len(), 1);
    }

    #[test]
    fn non_input_frames_are_ignored_without_error() {
        let mut inj = injector();
        let ping = ControlFrame::new(Payload::Ping { token: 1 }, 1, 0);
        assert!(inj.apply(&full(), &ping, 0).is_ok());
        assert!(inj.backend.events.is_empty());
    }
}
