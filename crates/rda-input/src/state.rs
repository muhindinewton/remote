//! Key state tracking and reconciliation — `docs/ARCHITECTURE.md` §4.4.
//!
//! The failure this exists to prevent: a `KeyUp` is lost in transit, the host believes Ctrl is still
//! held, and every subsequent keystroke becomes a shortcut. On a lossy 220 ms path this is not
//! hypothetical — it is the single most reported class of bug in remote desktop products.
//!
//! Three mechanisms, all mandatory:
//!
//! 1. **Modifier bitmask on every event.** Ordinary traffic self-heals within one event.
//! 2. **`KeyStateSync` heartbeat every 250 ms**, carrying the full pressed set. Bounds the lifetime
//!    of a lost `KeyUp` to a quarter second.
//! 3. **Release-all on every terminal condition**, enforced by [`ReleaseGuard`] so that a panic or
//!    an early return cannot skip it.

use crate::hid;
use rda_proto::control::Modifiers;
use std::collections::BTreeSet;

/// Maximum keys we will track as simultaneously held.
///
/// Matches the `KeyStateSync` wire cap. A real keyboard cannot exceed this; the bound exists so a
/// hostile peer cannot grow our state without limit.
pub const MAX_HELD_KEYS: usize = 32;

/// An action the reconciler wants performed on the OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    /// Press a key that should be down but is not.
    Press(u16),
    /// Release a key that is down but should not be.
    Release(u16),
}

impl KeyAction {
    /// The HID usage this action refers to.
    #[must_use]
    pub fn usage(self) -> u16 {
        match self {
            KeyAction::Press(u) | KeyAction::Release(u) => u,
        }
    }
}

/// The host's view of which keys the remote peer is holding.
#[derive(Debug, Clone, Default)]
pub struct KeyState {
    held: BTreeSet<u16>,
}

impl KeyState {
    /// A state with nothing held.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a key going down. Returns `false` if the key was already held.
    pub fn press(&mut self, usage: u16) -> bool {
        if self.held.len() >= MAX_HELD_KEYS && !self.held.contains(&usage) {
            return false;
        }
        self.held.insert(usage)
    }

    /// Records a key going up. Returns `false` if it was not held.
    pub fn release(&mut self, usage: u16) -> bool {
        self.held.remove(&usage)
    }

    /// Whether a key is currently held.
    #[must_use]
    pub fn is_held(&self, usage: u16) -> bool {
        self.held.contains(&usage)
    }

    /// Every held key, ascending.
    #[must_use]
    pub fn held(&self) -> Vec<u16> {
        self.held.iter().copied().collect()
    }

    /// How many keys are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// The modifier bitmask implied by the held keys.
    #[must_use]
    pub fn modifiers(&self) -> Modifiers {
        let mut bits = 0u16;
        for &usage in &self.held {
            if let Some(bit) = hid::modifier_bit(usage) {
                bits |= bit;
            }
        }
        Modifiers(bits)
    }

    /// Reconciles against an authoritative `KeyStateSync` snapshot.
    ///
    /// Returns the actions needed to make the OS match. Releases are emitted **before** presses:
    /// releasing a stuck modifier first means any key we then press is not silently transformed
    /// into a shortcut by the very modifier we were trying to clear.
    #[must_use]
    pub fn reconcile(&mut self, authoritative: &[u16]) -> Vec<KeyAction> {
        let target: BTreeSet<u16> = authoritative
            .iter()
            .copied()
            .filter(|&u| hid::is_valid_keyboard_usage(u))
            .take(MAX_HELD_KEYS)
            .collect();

        let mut actions = Vec::new();
        for &usage in self.held.difference(&target) {
            actions.push(KeyAction::Release(usage));
        }
        for &usage in target.difference(&self.held) {
            actions.push(KeyAction::Press(usage));
        }
        self.held = target;
        actions
    }

    /// Reconciles against a modifier bitmask carried on an ordinary event.
    ///
    /// This is the cheap path that runs on every keystroke and mouse move: it can only *release*
    /// modifiers, never press them. A bitmask says which modifiers are down, but not which physical
    /// key produced them — pressing "some Ctrl" on that evidence would guess wrong half the time,
    /// and a spurious press is far worse than a slightly late one that the 250 ms heartbeat fixes.
    #[must_use]
    pub fn reconcile_modifiers(&mut self, modifiers: Modifiers) -> Vec<KeyAction> {
        let mut actions = Vec::new();
        for &usage in &hid::MODIFIER_USAGES {
            let bit = hid::modifier_bit(usage).unwrap_or(0);
            let should_be_down = modifiers.0 & bit != 0;
            if self.held.contains(&usage) && !should_be_down {
                actions.push(KeyAction::Release(usage));
            }
        }
        for action in &actions {
            self.held.remove(&action.usage());
        }
        actions
    }

    /// Produces the actions to release everything, and clears the state.
    #[must_use]
    pub fn release_all(&mut self) -> Vec<KeyAction> {
        // Non-modifiers first, then modifiers. Releasing Shift before the key it modifies can
        // deliver a spurious unmodified keystroke to the focused application.
        let mut usages: Vec<u16> = self.held.iter().copied().collect();
        usages.sort_by_key(|&u| (hid::is_modifier(u), u));
        self.held.clear();
        usages.into_iter().map(KeyAction::Release).collect()
    }
}

/// Ensures every held key is released when a session ends, however it ends.
///
/// Constructed at session start and dropped on teardown. Because the release runs in `Drop`, an
/// early return, a `?`, or a panic unwinding through the session task all still release the keys.
/// Leaving a modifier stuck on someone else's machine after a dropped connection is exactly the
/// kind of failure that is invisible in testing and infuriating in production.
pub struct ReleaseGuard<F: FnMut(Vec<KeyAction>)> {
    state: KeyState,
    on_release: F,
    armed: bool,
}

impl<F: FnMut(Vec<KeyAction>)> ReleaseGuard<F> {
    /// Arms a guard over a fresh key state.
    pub fn new(on_release: F) -> Self {
        Self {
            state: KeyState::new(),
            on_release,
            armed: true,
        }
    }

    /// Mutable access to the tracked state.
    pub fn state_mut(&mut self) -> &mut KeyState {
        &mut self.state
    }

    /// Read access to the tracked state.
    pub fn state(&self) -> &KeyState {
        &self.state
    }

    /// Releases everything now and disarms the guard.
    ///
    /// The normal, explicit path. `Drop` remains as the backstop for the paths that are not normal.
    pub fn release_now(&mut self) {
        if self.armed {
            let actions = self.state.release_all();
            if !actions.is_empty() {
                (self.on_release)(actions);
            }
            self.armed = false;
        }
    }
}

impl<F: FnMut(Vec<KeyAction>)> Drop for ReleaseGuard<F> {
    fn drop(&mut self) {
        self.release_now();
    }
}

/// How often the controller must send a full `KeyStateSync`, in milliseconds.
pub const SYNC_INTERVAL_MS: u64 = 250;

/// Tracks whether the peer is keeping up its sync obligation.
#[derive(Debug, Clone)]
pub struct SyncWatchdog {
    last_sync_ms: u64,
    grace_ms: u64,
}

impl Default for SyncWatchdog {
    fn default() -> Self {
        // Three missed heartbeats before we act. At 220 ms RTT a single late sync is ordinary
        // jitter, not evidence of a problem.
        Self {
            last_sync_ms: 0,
            grace_ms: SYNC_INTERVAL_MS * 3,
        }
    }
}

impl SyncWatchdog {
    /// A watchdog started at `now_ms`.
    #[must_use]
    pub fn new(now_ms: u64) -> Self {
        Self {
            last_sync_ms: now_ms,
            ..Self::default()
        }
    }

    /// Records that a sync arrived.
    pub fn observe(&mut self, now_ms: u64) {
        self.last_sync_ms = now_ms;
    }

    /// Whether the peer has gone quiet while keys are held.
    ///
    /// When this trips with keys down, the safe action is to release them: a peer that has stopped
    /// syncing may be gone, and its keys must not stay pressed on someone else's machine.
    #[must_use]
    pub fn is_stale(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_sync_ms) > self.grace_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTRL_L: u16 = 0xE0;
    const SHIFT_L: u16 = 0xE1;
    const ALT_L: u16 = 0xE2;
    const KEY_A: u16 = 0x04;
    const KEY_B: u16 = 0x05;

    #[test]
    fn press_and_release_track_state() {
        let mut s = KeyState::new();
        assert!(s.press(KEY_A));
        assert!(!s.press(KEY_A), "a repeat press is not a state change");
        assert!(s.is_held(KEY_A));
        assert!(s.release(KEY_A));
        assert!(!s.release(KEY_A));
        assert!(s.is_empty());
    }

    #[test]
    fn modifiers_are_derived_from_held_keys() {
        let mut s = KeyState::new();
        s.press(CTRL_L);
        s.press(SHIFT_L);
        s.press(KEY_A);
        let m = s.modifiers();
        assert!(m.contains(Modifiers::LEFT_CTRL));
        assert!(m.contains(Modifiers::LEFT_SHIFT));
        assert!(!m.contains(Modifiers::LEFT_ALT));
    }

    #[test]
    fn reconciliation_releases_a_stuck_modifier() {
        // The core scenario: a KeyUp for Ctrl was lost, so the host still thinks it is held. The
        // next KeyStateSync says only 'a' is down.
        let mut s = KeyState::new();
        s.press(CTRL_L);
        s.press(KEY_A);

        let actions = s.reconcile(&[KEY_A]);
        assert_eq!(actions, vec![KeyAction::Release(CTRL_L)]);
        assert!(!s.is_held(CTRL_L));
        assert!(s.is_held(KEY_A));
    }

    #[test]
    fn reconciliation_presses_a_key_whose_keydown_was_lost() {
        let mut s = KeyState::new();
        let actions = s.reconcile(&[SHIFT_L, KEY_A]);
        assert_eq!(actions.len(), 2);
        assert!(actions.contains(&KeyAction::Press(SHIFT_L)));
        assert!(actions.contains(&KeyAction::Press(KEY_A)));
    }

    #[test]
    fn reconciliation_emits_releases_before_presses() {
        // Pressing a key while a stuck modifier is still down would deliver a shortcut instead of
        // the keystroke. Ordering is load-bearing, not cosmetic.
        let mut s = KeyState::new();
        s.press(CTRL_L);
        let actions = s.reconcile(&[KEY_B]);
        assert_eq!(
            actions,
            vec![KeyAction::Release(CTRL_L), KeyAction::Press(KEY_B)]
        );
    }

    #[test]
    fn reconciliation_is_a_no_op_when_state_already_matches() {
        let mut s = KeyState::new();
        s.press(SHIFT_L);
        s.press(KEY_A);
        assert!(s.reconcile(&[SHIFT_L, KEY_A]).is_empty());
    }

    #[test]
    fn reconciliation_ignores_invalid_usages_from_the_wire() {
        let mut s = KeyState::new();
        let actions = s.reconcile(&[KEY_A, 0x0000, 0xFFFF, 0x0F00]);
        assert_eq!(actions, vec![KeyAction::Press(KEY_A)]);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn reconciliation_bounds_the_tracked_set() {
        let mut s = KeyState::new();
        let huge: Vec<u16> = (0x04..0x60).collect(); // 92 valid usages
        let _ = s.reconcile(&huge);
        assert!(s.len() <= MAX_HELD_KEYS, "held set grew to {}", s.len());
    }

    #[test]
    fn press_refuses_to_grow_past_the_cap() {
        let mut s = KeyState::new();
        for usage in 0x04..(0x04 + MAX_HELD_KEYS as u16) {
            assert!(s.press(usage));
        }
        assert!(
            !s.press(0x50),
            "a hostile peer must not grow our state without limit"
        );
        assert_eq!(s.len(), MAX_HELD_KEYS);
    }

    #[test]
    fn modifier_bitmask_reconciliation_only_releases() {
        // A bitmask says a modifier is down but not which physical key. Guessing a press would be
        // wrong half the time, so this path releases only.
        let mut s = KeyState::new();
        s.press(CTRL_L);
        s.press(ALT_L);

        // Event says only Ctrl is held now.
        let actions = s.reconcile_modifiers(Modifiers(Modifiers::LEFT_CTRL));
        assert_eq!(actions, vec![KeyAction::Release(ALT_L)]);
        assert!(s.is_held(CTRL_L));

        // Event claims Shift is held, which we have no record of. We must not invent a press.
        let actions =
            s.reconcile_modifiers(Modifiers(Modifiers::LEFT_CTRL | Modifiers::LEFT_SHIFT));
        assert!(
            actions.is_empty(),
            "must not press a modifier from a bitmask alone"
        );
        assert!(!s.is_held(SHIFT_L));
    }

    #[test]
    fn modifier_reconciliation_leaves_ordinary_keys_alone() {
        let mut s = KeyState::new();
        s.press(KEY_A);
        s.press(CTRL_L);
        let actions = s.reconcile_modifiers(Modifiers::NONE);
        assert_eq!(actions, vec![KeyAction::Release(CTRL_L)]);
        assert!(
            s.is_held(KEY_A),
            "a modifier bitmask says nothing about ordinary keys"
        );
    }

    #[test]
    fn release_all_frees_non_modifiers_before_modifiers() {
        // Releasing Shift first would deliver an unmodified keystroke to the focused app.
        let mut s = KeyState::new();
        s.press(SHIFT_L);
        s.press(KEY_A);
        s.press(CTRL_L);

        let actions = s.release_all();
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[0], KeyAction::Release(KEY_A));
        assert!(hid::is_modifier(actions[1].usage()));
        assert!(hid::is_modifier(actions[2].usage()));
        assert!(s.is_empty());
    }

    #[test]
    fn the_guard_releases_on_normal_teardown() {
        let released = std::cell::RefCell::new(Vec::new());
        {
            let mut guard = ReleaseGuard::new(|actions| released.borrow_mut().extend(actions));
            guard.state_mut().press(CTRL_L);
            guard.state_mut().press(KEY_A);
        }
        assert_eq!(released.borrow().len(), 2);
    }

    #[test]
    fn the_guard_releases_even_when_the_scope_unwinds() {
        // The case that matters: a session task panics mid-drag with Ctrl held. Without Drop, that
        // modifier stays pressed on the host until the user notices and presses it themselves.
        let released = std::cell::RefCell::new(Vec::new());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut guard = ReleaseGuard::new(|actions| released.borrow_mut().extend(actions));
            guard.state_mut().press(SHIFT_L);
            panic!("session task died");
        }));
        assert!(result.is_err());
        assert_eq!(released.borrow().as_slice(), &[KeyAction::Release(SHIFT_L)]);
    }

    #[test]
    fn the_guard_does_not_release_twice() {
        let count = std::cell::Cell::new(0);
        {
            let mut guard = ReleaseGuard::new(|_| count.set(count.get() + 1));
            guard.state_mut().press(KEY_A);
            guard.release_now();
            assert_eq!(count.get(), 1);
        }
        assert_eq!(
            count.get(),
            1,
            "Drop must not re-fire after an explicit release"
        );
    }

    #[test]
    fn the_guard_stays_quiet_when_nothing_is_held() {
        let fired = std::cell::Cell::new(false);
        {
            let _guard = ReleaseGuard::new(|_| fired.set(true));
        }
        assert!(!fired.get());
    }

    #[test]
    fn the_watchdog_trips_after_three_missed_heartbeats() {
        let mut w = SyncWatchdog::new(0);
        assert!(!w.is_stale(SYNC_INTERVAL_MS * 2));
        assert!(!w.is_stale(SYNC_INTERVAL_MS * 3));
        assert!(w.is_stale(SYNC_INTERVAL_MS * 3 + 1));

        w.observe(SYNC_INTERVAL_MS * 3);
        assert!(!w.is_stale(SYNC_INTERVAL_MS * 4));
    }
}
