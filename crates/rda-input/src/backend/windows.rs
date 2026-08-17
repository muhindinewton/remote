//! Windows input injection via `SendInput`.
//!
//! **Scan codes, not virtual keys.** `KEYEVENTF_SCANCODE` sends the physical key position, which is
//! what the HID usage on the wire already represents. Virtual-key codes are layout-dependent, so
//! using them would make a controller on one layout type the wrong character on a host with
//! another — the exact failure the HID design exists to avoid.
//!
//! **UIPI is a real limitation, not a bug.** A medium-integrity process cannot inject into a
//! higher-integrity window: input aimed at an elevated application, the UAC prompt or the logon
//! screen silently vanishes. Silently — no error is returned, which makes it a support nightmare.
//! Reaching those requires the SYSTEM service path in `docs/ARCHITECTURE.md` §3.1, which is a
//! separate work item; [`WindowsBackend::may_reach_elevated_windows`] reports the limitation so the
//! host can warn instead of appearing broken.
//!
//! Not compiled or tested on this machine — verified by cross-target `cargo check` only.

use super::{Backend, BackendError, Button, ScrollDelta};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYBD_EVENT_FLAGS,
    KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, KEYEVENTF_UNICODE,
    MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN,
    MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN,
    MOUSEEVENTF_XUP, MOUSEINPUT, MOUSE_EVENT_FLAGS,
};

/// First thumb button. Not re-exported by the `windows` crate's input module, so it is defined
/// here from the Win32 headers.
const XBUTTON1: i32 = 0x0001;
/// Second thumb button.
const XBUTTON2: i32 = 0x0002;
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};

/// `SendInput` backend.
pub struct WindowsBackend {
    /// Virtual desktop bounds, cached so absolute coordinates can be normalised.
    virtual_x: i32,
    virtual_y: i32,
    virtual_width: i32,
    virtual_height: i32,
}

impl WindowsBackend {
    /// Creates a backend and reads the virtual desktop geometry.
    pub fn new() -> Result<Self, BackendError> {
        // SAFETY: GetSystemMetrics takes an index and returns an int; no pointers involved.
        let (x, y, w, h) = unsafe {
            (
                GetSystemMetrics(SM_XVIRTUALSCREEN),
                GetSystemMetrics(SM_YVIRTUALSCREEN),
                GetSystemMetrics(SM_CXVIRTUALSCREEN),
                GetSystemMetrics(SM_CYVIRTUALSCREEN),
            )
        };
        if w <= 0 || h <= 0 {
            return Err(BackendError::Unavailable(
                "could not read virtual desktop dimensions".to_string(),
            ));
        }
        Ok(Self {
            virtual_x: x,
            virtual_y: y,
            virtual_width: w,
            virtual_height: h,
        })
    }

    /// Whether this process can inject into elevated windows.
    ///
    /// Always `false` for a user-session process. The host should surface this so a user whose
    /// keystrokes stop working at a UAC prompt gets an explanation rather than a mystery.
    #[must_use]
    pub fn may_reach_elevated_windows(&self) -> bool {
        false
    }

    fn send(&self, input: INPUT) -> Result<(), BackendError> {
        // SAFETY: `SendInput` reads `count` elements of the slice we pass and the size we declare
        // matches `INPUT` exactly. The slice outlives the call.
        let sent = unsafe { SendInput(&[input], std::mem::size_of::<INPUT>() as i32) };
        if sent == 1 {
            Ok(())
        } else {
            // A zero return here is almost always UIPI blocking the target window rather than a
            // malformed structure, so the message says so.
            Err(BackendError::InjectionFailed(
                "SendInput was blocked, most likely by UIPI on a higher-integrity window"
                    .to_string(),
            ))
        }
    }

    fn mouse(
        &self,
        dx: i32,
        dy: i32,
        data: i32,
        flags: MOUSE_EVENT_FLAGS,
    ) -> Result<(), BackendError> {
        self.send(INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx,
                    dy,
                    mouseData: data as u32,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        })
    }

    fn keyboard(&self, scan: u16, vk: u16, flags: KEYBD_EVENT_FLAGS) -> Result<(), BackendError> {
        self.send(INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: windows::Win32::UI::Input::KeyboardAndMouse::VIRTUAL_KEY(vk),
                    wScan: scan,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        })
    }
}

impl Backend for WindowsBackend {
    fn pointer_absolute(&mut self, x: i32, y: i32) -> Result<(), BackendError> {
        // MOUSEEVENTF_ABSOLUTE wants 0..=65535 across the virtual desktop, so the physical pixel
        // position has to be renormalised against the whole desktop rather than one display.
        let nx = ((i64::from(x - self.virtual_x) * 65535) / i64::from(self.virtual_width)) as i32;
        let ny = ((i64::from(y - self.virtual_y) * 65535) / i64::from(self.virtual_height)) as i32;
        self.mouse(
            nx.clamp(0, 65535),
            ny.clamp(0, 65535),
            0,
            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
        )
    }

    fn pointer_relative(&mut self, dx: f64, dy: f64) -> Result<(), BackendError> {
        self.mouse(dx.round() as i32, dy.round() as i32, 0, MOUSEEVENTF_MOVE)
    }

    fn button(&mut self, button: Button, down: bool) -> Result<(), BackendError> {
        let (flags, data) = match (button, down) {
            (Button::Left, true) => (MOUSEEVENTF_LEFTDOWN, 0),
            (Button::Left, false) => (MOUSEEVENTF_LEFTUP, 0),
            (Button::Right, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
            (Button::Right, false) => (MOUSEEVENTF_RIGHTUP, 0),
            (Button::Middle, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
            (Button::Middle, false) => (MOUSEEVENTF_MIDDLEUP, 0),
            (Button::Back, true) => (MOUSEEVENTF_XDOWN, XBUTTON1),
            (Button::Back, false) => (MOUSEEVENTF_XUP, XBUTTON1),
            (Button::Forward, true) => (MOUSEEVENTF_XDOWN, XBUTTON2),
            (Button::Forward, false) => (MOUSEEVENTF_XUP, XBUTTON2),
        };
        self.mouse(0, 0, data, flags)
    }

    fn scroll(&mut self, delta: ScrollDelta) -> Result<(), BackendError> {
        // Windows `WHEEL_DELTA` is 120, which is exactly the wire unit — no conversion needed, and
        // fractional trackpad scrolling passes through intact.
        if delta.vertical != 0 {
            self.mouse(0, 0, i32::from(delta.vertical), MOUSEEVENTF_WHEEL)?;
        }
        if delta.horizontal != 0 {
            self.mouse(0, 0, i32::from(delta.horizontal), MOUSEEVENTF_HWHEEL)?;
        }
        Ok(())
    }

    fn key(&mut self, usage: u16, down: bool) -> Result<(), BackendError> {
        let mapping = crate::hid::lookup(usage).ok_or(BackendError::UnmappedUsage(usage))?;
        let mut flags = KEYEVENTF_SCANCODE;
        if mapping.windows_extended() {
            flags |= KEYEVENTF_EXTENDEDKEY;
        }
        if !down {
            flags |= KEYEVENTF_KEYUP;
        }
        self.keyboard(mapping.windows_scancode_low(), 0, flags)
    }

    fn text(&mut self, text: &str) -> Result<(), BackendError> {
        // KEYEVENTF_UNICODE takes UTF-16 code units, so anything outside the BMP arrives as a
        // surrogate pair — which is correct, because Windows reassembles them.
        for unit in text.encode_utf16() {
            self.keyboard(unit, 0, KEYEVENTF_UNICODE)?;
            self.keyboard(unit, 0, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "windows-sendinput"
    }
}
