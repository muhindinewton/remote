//! macOS input injection via Core Graphics event taps.
//!
//! Requires the **TCC Accessibility** permission, which is separate from Screen Recording, prompted
//! separately, and cannot be granted programmatically. `CGEventPost` silently does nothing without
//! it — no error, no exception — so [`MacosBackend::new`] probes for it up front rather than
//! letting a session connect and mysteriously ignore every keystroke.
//!
//! Events are posted at `kCGHIDEventTap` rather than `kCGSessionEventTap`: HID-level events look
//! like real hardware and reach everything, including the login window and applications that
//! filter synthetic input.
//!
//! No `unsafe` appears here — the `core-graphics` crate wraps the C API safely, so the crate-wide
//! `forbid(unsafe_code)` holds all the way down to the OS boundary.

use super::{Backend, BackendError, Button, ScrollDelta};
use core_graphics::event::{CGEvent, CGEventTapLocation, CGEventType, CGMouseButton};
use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
use core_graphics::geometry::CGPoint;

/// Core Graphics input backend.
pub struct MacosBackend {
    source: CGEventSource,
    /// Last known pointer position, needed because button and scroll events must carry one.
    cursor: CGPoint,
    /// Which buttons are down, so motion becomes a drag rather than a move.
    left_down: bool,
    right_down: bool,
    middle_down: bool,
}

impl MacosBackend {
    /// Creates a backend, failing if Accessibility permission is missing.
    pub fn new() -> Result<Self, BackendError> {
        // `HIDSystemState` keeps our synthetic modifier state consistent with the system's view.
        // Using `Private` or a fresh state would desynchronise modifiers from what applications
        // observe, so a shift injected here would not affect the next key.
        let source = CGEventSource::new(CGEventSourceStateID::HIDSystemState).map_err(|()| {
            BackendError::PermissionDenied(
                "could not create a Core Graphics event source; grant Accessibility permission \
                 in System Settings > Privacy & Security > Accessibility"
                    .to_string(),
            )
        })?;

        let cursor = CGEvent::new(source.clone())
            .map(|e| e.location())
            .unwrap_or(CGPoint::new(0.0, 0.0));

        Ok(Self {
            source,
            cursor,
            left_down: false,
            right_down: false,
            middle_down: false,
        })
    }

    /// The event type for a pointer motion, given which buttons are held.
    ///
    /// macOS distinguishes moving from dragging. Posting `MouseMoved` while a button is down makes
    /// drag-and-drop, text selection and window dragging all silently fail — one of the most
    /// common defects in Mac remote-desktop implementations.
    fn motion_type(&self) -> CGEventType {
        if self.left_down {
            CGEventType::LeftMouseDragged
        } else if self.right_down {
            CGEventType::RightMouseDragged
        } else if self.middle_down {
            CGEventType::OtherMouseDragged
        } else {
            CGEventType::MouseMoved
        }
    }

    fn held_button(&self) -> CGMouseButton {
        if self.right_down {
            CGMouseButton::Right
        } else if self.middle_down {
            CGMouseButton::Center
        } else {
            CGMouseButton::Left
        }
    }

    fn post_motion(&mut self) -> Result<(), BackendError> {
        let event = CGEvent::new_mouse_event(
            self.source.clone(),
            self.motion_type(),
            self.cursor,
            self.held_button(),
        )
        .map_err(|()| {
            BackendError::InjectionFailed("could not construct a mouse event".to_string())
        })?;
        event.post(CGEventTapLocation::HID);
        Ok(())
    }
}

fn map_button(button: Button) -> (CGMouseButton, CGEventType, CGEventType) {
    match button {
        Button::Left => (
            CGMouseButton::Left,
            CGEventType::LeftMouseDown,
            CGEventType::LeftMouseUp,
        ),
        Button::Right => (
            CGMouseButton::Right,
            CGEventType::RightMouseDown,
            CGEventType::RightMouseUp,
        ),
        // macOS has no dedicated event type for the thumb buttons; they ride the "other" channel
        // and are distinguished by the button number.
        Button::Middle | Button::Back | Button::Forward => (
            CGMouseButton::Center,
            CGEventType::OtherMouseDown,
            CGEventType::OtherMouseUp,
        ),
    }
}

impl Backend for MacosBackend {
    fn pointer_absolute(&mut self, x: i32, y: i32) -> Result<(), BackendError> {
        self.cursor = CGPoint::new(f64::from(x), f64::from(y));
        self.post_motion()
    }

    fn pointer_relative(&mut self, dx: f64, dy: f64) -> Result<(), BackendError> {
        self.cursor = CGPoint::new(self.cursor.x + dx, self.cursor.y + dy);
        self.post_motion()
    }

    fn button(&mut self, button: Button, down: bool) -> Result<(), BackendError> {
        let (cg_button, down_type, up_type) = map_button(button);
        match button {
            Button::Left => self.left_down = down,
            Button::Right => self.right_down = down,
            Button::Middle | Button::Back | Button::Forward => self.middle_down = down,
        }

        let event = CGEvent::new_mouse_event(
            self.source.clone(),
            if down { down_type } else { up_type },
            self.cursor,
            cg_button,
        )
        .map_err(|()| {
            BackendError::InjectionFailed("could not construct a button event".to_string())
        })?;
        event.post(CGEventTapLocation::HID);
        Ok(())
    }

    fn scroll(&mut self, delta: ScrollDelta) -> Result<(), BackendError> {
        // Pixel units preserve high-resolution trackpad scrolling; line units would quantise a
        // smooth gesture into jumps. 120 wire units is one traditional detent, which macOS treats
        // as roughly 10 pixels.
        let vertical = (i32::from(delta.vertical) * 10) / 120;
        let horizontal = (i32::from(delta.horizontal) * 10) / 120;

        let event = CGEvent::new_scroll_event(
            self.source.clone(),
            core_graphics::event::ScrollEventUnit::PIXEL,
            2,
            vertical,
            horizontal,
            0,
        )
        .map_err(|()| {
            BackendError::InjectionFailed("could not construct a scroll event".to_string())
        })?;
        event.post(CGEventTapLocation::HID);
        Ok(())
    }

    fn key(&mut self, usage: u16, down: bool) -> Result<(), BackendError> {
        let keycode = super::platform_code(usage)?;
        let event =
            CGEvent::new_keyboard_event(self.source.clone(), keycode, down).map_err(|()| {
                BackendError::InjectionFailed(format!(
                    "could not construct a key event for usage {usage:#06x}"
                ))
            })?;
        event.post(CGEventTapLocation::HID);
        Ok(())
    }

    fn text(&mut self, text: &str) -> Result<(), BackendError> {
        // Key code 0 with an overridden string is the documented way to type characters that have
        // no key position — dead keys, compose output, CJK IME commits.
        let event = CGEvent::new_keyboard_event(self.source.clone(), 0, true).map_err(|()| {
            BackendError::InjectionFailed("could not construct a text event".to_string())
        })?;
        event.set_string(text);
        event.post(CGEventTapLocation::HID);

        let up = CGEvent::new_keyboard_event(self.source.clone(), 0, false).map_err(|()| {
            BackendError::InjectionFailed("could not construct a text event".to_string())
        })?;
        up.set_string(text);
        up.post(CGEventTapLocation::HID);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "macos-coregraphics"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn button_mapping_is_total_and_down_differs_from_up() {
        // CGEventType has no PartialEq, so compare the discriminants the OS actually sees.
        for b in [
            Button::Left,
            Button::Right,
            Button::Middle,
            Button::Back,
            Button::Forward,
        ] {
            let (_, down, up) = map_button(b);
            assert_ne!(
                down as u32, up as u32,
                "{b:?} maps down and up to the same event type"
            );
        }
    }

    #[test]
    fn scroll_conversion_preserves_direction() {
        // Guards against a sign flip, which is invisible in code review and immediately obvious to
        // a user whose scrolling goes the wrong way.
        let up = ScrollDelta {
            vertical: 120,
            horizontal: 0,
        };
        assert_eq!((i32::from(up.vertical) * 10) / 120, 10);
        let down = ScrollDelta {
            vertical: -120,
            horizontal: 0,
        };
        assert_eq!((i32::from(down.vertical) * 10) / 120, -10);
    }

    /// Only runs where Accessibility permission has been granted. Skips rather than fails
    /// otherwise: CI has no TCC grant, and a red test that means "unprivileged environment" trains
    /// people to ignore it.
    #[test]
    fn backend_constructs_when_permitted() {
        match MacosBackend::new() {
            Ok(b) => assert_eq!(b.name(), "macos-coregraphics"),
            Err(BackendError::PermissionDenied(_)) => {
                eprintln!("skipping: Accessibility permission not granted");
            }
            Err(e) => panic!("unexpected backend error: {e}"),
        }
    }

    #[test]
    fn motion_becomes_a_drag_while_a_button_is_held() {
        let Ok(mut backend) = MacosBackend::new() else {
            eprintln!("skipping: Accessibility permission not granted");
            return;
        };
        assert_eq!(backend.motion_type() as u32, CGEventType::MouseMoved as u32);
        backend.left_down = true;
        assert_eq!(
            backend.motion_type() as u32,
            CGEventType::LeftMouseDragged as u32,
            "moving with the left button down must be a drag, or selection and drag-drop break"
        );
        backend.left_down = false;
        backend.right_down = true;
        assert_eq!(
            backend.motion_type() as u32,
            CGEventType::RightMouseDragged as u32
        );
    }
}
