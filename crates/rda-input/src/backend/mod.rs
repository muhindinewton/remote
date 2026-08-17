//! Platform injection backends — `docs/ARCHITECTURE.md` §4.6.
//!
//! The trait is deliberately narrow. Everything above it — validation, capability checks, rate
//! limiting, state tracking — is platform-independent and therefore testable on any machine
//! ([`RecordingBackend`]). What is left here is the irreducible platform-specific part, which is
//! also the only part that needs `unsafe`.
//!
//! | Platform | API | Notes |
//! |---|---|---|
//! | macOS | `CGEventPost` at `kCGHIDEventTap` | Requires TCC Accessibility permission |
//! | Windows | `SendInput` with `KEYEVENTF_SCANCODE` | UIPI blocks injection into higher-integrity windows |
//! | Linux | `uinput` | Works under X11 and Wayland; needs `/dev/uinput` access |

use crate::hid;

#[cfg(target_os = "macos")]
pub mod macos;

// The only `unsafe` in this crate. `SendInput` and `GetSystemMetrics` are FFI calls with no safe
// wrapper available; each block carries a SAFETY note stating the invariant it relies on.
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

/// A mouse button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    /// Primary.
    Left,
    /// Secondary.
    Right,
    /// Wheel click.
    Middle,
    /// Thumb button, back.
    Back,
    /// Thumb button, forward.
    Forward,
}

/// A scroll amount, in units of 1/120 of a traditional detent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScrollDelta {
    /// Vertical component. Positive scrolls up.
    pub vertical: i16,
    /// Horizontal component. Positive scrolls right.
    pub horizontal: i16,
}

impl ScrollDelta {
    /// Converts to whole wheel detents as a float, for APIs that want continuous values.
    #[must_use]
    pub fn detents(self) -> (f64, f64) {
        (
            f64::from(self.vertical) / 120.0,
            f64::from(self.horizontal) / 120.0,
        )
    }

    /// Converts to whole detents, truncating. For APIs that only take integers.
    #[must_use]
    pub fn whole_detents(self) -> (i32, i32) {
        (
            i32::from(self.vertical) / 120,
            i32::from(self.horizontal) / 120,
        )
    }
}

/// Why a backend call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    /// The OS refused, usually because a permission is missing.
    ///
    /// On macOS this means TCC Accessibility has not been granted; on Linux it usually means
    /// `/dev/uinput` is not writable.
    #[error("permission denied by the operating system: {0}")]
    PermissionDenied(String),
    /// The backend could not be initialised.
    #[error("failed to initialise input backend: {0}")]
    Unavailable(String),
    /// The HID usage has no code on this platform.
    #[error("HID usage {0:#06x} is not mapped on this platform")]
    UnmappedUsage(u16),
    /// The OS call failed.
    #[error("input injection failed: {0}")]
    InjectionFailed(String),
    /// This platform has no implementation.
    #[error("input injection is not implemented on this platform")]
    Unsupported,
}

/// The platform-specific part of input injection.
///
/// Implementations may assume every argument has already been validated: usages are in the
/// allowlist and mapped, coordinates are inside a real display. That assumption is what keeps the
/// `unsafe` blocks small enough to review.
pub trait Backend {
    /// Moves the pointer to an absolute position in the virtual desktop, in physical pixels.
    fn pointer_absolute(&mut self, x: i32, y: i32) -> Result<(), BackendError>;

    /// Moves the pointer by a relative amount, in pixels. Used when the pointer is captured.
    fn pointer_relative(&mut self, dx: f64, dy: f64) -> Result<(), BackendError>;

    /// Presses or releases a mouse button.
    fn button(&mut self, button: Button, down: bool) -> Result<(), BackendError>;

    /// Scrolls.
    fn scroll(&mut self, delta: ScrollDelta) -> Result<(), BackendError>;

    /// Presses or releases a key, given its HID usage.
    fn key(&mut self, usage: u16, down: bool) -> Result<(), BackendError>;

    /// Types a Unicode string, bypassing the keyboard layout.
    ///
    /// The escape hatch for dead keys, compose sequences and IME output, which cannot be expressed
    /// as key positions.
    fn text(&mut self, text: &str) -> Result<(), BackendError>;

    /// Human-readable backend name, for diagnostics.
    fn name(&self) -> &'static str;
}

/// Forwards through a box, so a backend can be chosen at runtime.
///
/// The host decides between the real platform backend and [`RecordingBackend`] based on whether the
/// operator consented to injection, which is a decision made too late for a type parameter.
impl<B: Backend + ?Sized> Backend for Box<B> {
    fn pointer_absolute(&mut self, x: i32, y: i32) -> Result<(), BackendError> {
        (**self).pointer_absolute(x, y)
    }

    fn pointer_relative(&mut self, dx: f64, dy: f64) -> Result<(), BackendError> {
        (**self).pointer_relative(dx, dy)
    }

    fn button(&mut self, button: Button, down: bool) -> Result<(), BackendError> {
        (**self).button(button, down)
    }

    fn scroll(&mut self, delta: ScrollDelta) -> Result<(), BackendError> {
        (**self).scroll(delta)
    }

    fn key(&mut self, usage: u16, down: bool) -> Result<(), BackendError> {
        (**self).key(usage, down)
    }

    fn text(&mut self, text: &str) -> Result<(), BackendError> {
        (**self).text(text)
    }

    fn name(&self) -> &'static str {
        (**self).name()
    }
}

/// Translates a HID usage to this platform's key code, or fails loudly.
///
/// Shared by every backend so an unmapped key produces the same error everywhere rather than each
/// platform inventing a fallback.
pub fn platform_code(usage: u16) -> Result<u16, BackendError> {
    hid::lookup(usage)
        .and_then(|m| m.platform_code())
        .ok_or(BackendError::UnmappedUsage(usage))
}

/// A backend that records calls instead of performing them.
///
/// Every guard, validation rule and reconciliation path in this crate is tested through this, on
/// any platform, with no permissions and no side effects.
#[derive(Debug, Default, Clone)]
pub struct RecordingBackend {
    /// Everything the injector asked for, in order.
    pub events: Vec<RecordedEvent>,
    /// When set, every call fails with this error. Used to test error propagation.
    pub fail_with: Option<BackendError>,
}

/// One recorded backend call.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum RecordedEvent {
    PointerAbsolute { x: i32, y: i32 },
    PointerRelative { dx_milli: i64, dy_milli: i64 },
    ButtonEvent { button: Button, down: bool },
    Scroll { vertical: i16, horizontal: i16 },
    KeyEvent { usage: u16, down: bool },
    Text { text: String },
}

impl RecordingBackend {
    /// Returns only the key events, for concise assertions.
    #[must_use]
    pub fn keys(&self) -> Vec<(u16, bool)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                RecordedEvent::KeyEvent { usage, down } => Some((*usage, *down)),
                _ => None,
            })
            .collect()
    }

    fn check(&self) -> Result<(), BackendError> {
        match &self.fail_with {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
}

impl Backend for RecordingBackend {
    fn pointer_absolute(&mut self, x: i32, y: i32) -> Result<(), BackendError> {
        self.check()?;
        self.events.push(RecordedEvent::PointerAbsolute { x, y });
        Ok(())
    }

    fn pointer_relative(&mut self, dx: f64, dy: f64) -> Result<(), BackendError> {
        self.check()?;
        // Stored as milli-pixels so the event type stays comparable in assertions.
        self.events.push(RecordedEvent::PointerRelative {
            dx_milli: (dx * 1000.0) as i64,
            dy_milli: (dy * 1000.0) as i64,
        });
        Ok(())
    }

    fn button(&mut self, button: Button, down: bool) -> Result<(), BackendError> {
        self.check()?;
        self.events
            .push(RecordedEvent::ButtonEvent { button, down });
        Ok(())
    }

    fn scroll(&mut self, delta: ScrollDelta) -> Result<(), BackendError> {
        self.check()?;
        self.events.push(RecordedEvent::Scroll {
            vertical: delta.vertical,
            horizontal: delta.horizontal,
        });
        Ok(())
    }

    fn key(&mut self, usage: u16, down: bool) -> Result<(), BackendError> {
        self.check()?;
        self.events.push(RecordedEvent::KeyEvent { usage, down });
        Ok(())
    }

    fn text(&mut self, text: &str) -> Result<(), BackendError> {
        self.check()?;
        self.events.push(RecordedEvent::Text {
            text: text.to_owned(),
        });
        Ok(())
    }

    fn name(&self) -> &'static str {
        "recording"
    }
}

/// Builds the backend for the platform this build targets.
///
/// Returns [`BackendError::Unsupported`] rather than a silent no-op on unimplemented platforms: a
/// remote desktop that appears to accept input and quietly discards it is worse than one that
/// refuses the session.
///
/// The returned backend is **not** `Send`. macOS `CGEventSource` is thread-affine, and the Windows
/// and Linux handles are cheapest to keep on one thread too. The host agent therefore owns a
/// dedicated injection thread and feeds it over a channel, which is the arrangement
/// `docs/ARCHITECTURE.md` §3.2 already requires for capture — the same reasoning applies here.
pub fn platform_backend() -> Result<Box<dyn Backend>, BackendError> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(macos::MacosBackend::new()?))
    }
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(windows::WindowsBackend::new()?))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::LinuxBackend::new()?))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Err(BackendError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scroll_converts_to_detents() {
        let one_notch = ScrollDelta {
            vertical: 120,
            horizontal: 0,
        };
        assert_eq!(one_notch.detents(), (1.0, 0.0));
        assert_eq!(one_notch.whole_detents(), (1, 0));

        // High-resolution trackpad output: a fraction of a detent must survive as a fraction.
        let fine = ScrollDelta {
            vertical: 30,
            horizontal: -15,
        };
        assert_eq!(fine.detents(), (0.25, -0.125));
        assert_eq!(
            fine.whole_detents(),
            (0, 0),
            "sub-detent scroll truncates for integer APIs"
        );
    }

    #[test]
    fn platform_code_resolves_mapped_keys_and_rejects_others() {
        assert!(
            platform_code(0x04).is_ok(),
            "KeyA must map on every platform"
        );
        assert_eq!(
            platform_code(0x0000),
            Err(BackendError::UnmappedUsage(0x0000))
        );
        assert_eq!(
            platform_code(0xFFFF),
            Err(BackendError::UnmappedUsage(0xFFFF))
        );
    }

    #[test]
    fn the_recording_backend_captures_calls_in_order() {
        let mut b = RecordingBackend::default();
        b.pointer_absolute(10, 20).unwrap();
        b.key(0x04, true).unwrap();
        b.key(0x04, false).unwrap();
        assert_eq!(b.events.len(), 3);
        assert_eq!(b.keys(), vec![(0x04, true), (0x04, false)]);
    }

    #[test]
    fn the_recording_backend_can_simulate_failure() {
        let mut b = RecordingBackend {
            fail_with: Some(BackendError::PermissionDenied("test".into())),
            ..Default::default()
        };
        assert!(b.key(0x04, true).is_err());
        assert!(
            b.events.is_empty(),
            "a failed call must not be recorded as having happened"
        );
    }
}
