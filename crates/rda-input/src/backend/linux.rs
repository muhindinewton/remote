//! Linux input injection via `uinput`.
//!
//! `uinput` creates a virtual kernel input device, so events are indistinguishable from real
//! hardware and work under **both X11 and Wayland**. `XTEST` is X11-only and would strand every
//! Wayland user; the emerging `libei` path is compositor-mediated and consent-based, which is
//! preferable long term but not yet universally available.
//!
//! **What genuinely does not work:** unattended access on a locked Wayland session. There is no
//! generic mechanism for it — it needs a compositor-specific daemon such as
//! `gnome-remote-desktop` in system mode. `docs/ARCHITECTURE.md` §3.1 states this plainly rather
//! than pretending a flag exists.
//!
//! Requires write access to `/dev/uinput`, normally via a udev rule granting the `input` group.
//!
//! Not compiled or tested on this machine — verified by cross-target `cargo check` only.

use super::{Backend, BackendError, Button, ScrollDelta};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;

// evdev event types.
const EV_SYN: u16 = 0x00;
const EV_KEY: u16 = 0x01;
const EV_REL: u16 = 0x02;
const EV_ABS: u16 = 0x03;

const SYN_REPORT: u16 = 0;
const REL_X: u16 = 0x00;
const REL_Y: u16 = 0x01;
const REL_WHEEL_HI_RES: u16 = 0x0b;
const REL_HWHEEL_HI_RES: u16 = 0x0c;
const ABS_X: u16 = 0x00;
const ABS_Y: u16 = 0x01;

// evdev button codes.
const BTN_LEFT: u16 = 0x110;
const BTN_RIGHT: u16 = 0x111;
const BTN_MIDDLE: u16 = 0x112;
const BTN_SIDE: u16 = 0x113;
const BTN_EXTRA: u16 = 0x114;

/// One `input_event` as the kernel expects it.
///
/// Laid out by hand rather than bound from C so the encoding is explicit and reviewable. The
/// timestamp is left zero, which tells the kernel to stamp it on receipt.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct InputEvent {
    time_sec: i64,
    time_usec: i64,
    kind: u16,
    code: u16,
    value: i32,
}

impl InputEvent {
    fn new(kind: u16, code: u16, value: i32) -> Self {
        Self {
            time_sec: 0,
            time_usec: 0,
            kind,
            code,
            value,
        }
    }

    /// Serialises to the kernel's wire layout.
    ///
    /// Written explicitly rather than by transmuting the struct: a byte-for-byte encoder is
    /// checkable by a test, and it keeps this file free of `unsafe`.
    fn to_bytes(self) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[0..8].copy_from_slice(&self.time_sec.to_ne_bytes());
        out[8..16].copy_from_slice(&self.time_usec.to_ne_bytes());
        out[16..18].copy_from_slice(&self.kind.to_ne_bytes());
        out[18..20].copy_from_slice(&self.code.to_ne_bytes());
        out[20..24].copy_from_slice(&self.value.to_ne_bytes());
        out
    }
}

/// `uinput` backend.
pub struct LinuxBackend {
    device: File,
    absolute_capable: bool,
}

impl LinuxBackend {
    /// Opens `/dev/uinput` and creates the virtual device.
    ///
    /// Device setup requires `ioctl`, which needs `unsafe`. The rest of this file does not, so the
    /// unreviewed surface is one function rather than the whole backend.
    pub fn new() -> Result<Self, BackendError> {
        let device = OpenOptions::new()
            .write(true)
            .open("/dev/uinput")
            .map_err(|e| {
                match e.kind() {
                std::io::ErrorKind::PermissionDenied => BackendError::PermissionDenied(
                    "cannot open /dev/uinput; add a udev rule granting the input group write access"
                        .to_string(),
                ),
                std::io::ErrorKind::NotFound => BackendError::Unavailable(
                    "/dev/uinput not present; load the uinput kernel module".to_string(),
                ),
                _ => BackendError::Unavailable(format!("cannot open /dev/uinput: {e}")),
            }
            })?;

        let backend = Self {
            device,
            absolute_capable: false,
        };
        backend.configure()?;
        Ok(backend)
    }

    /// Registers the capabilities and creates the device.
    ///
    /// Kept as a stub returning an explicit error rather than a silent success: a backend that
    /// claims to work and then swallows every event is worse than one that refuses to start.
    fn configure(&self) -> Result<(), BackendError> {
        let _ = self.device.as_raw_fd();
        Err(BackendError::Unavailable(
            "uinput device setup requires ioctl registration, which is not yet implemented; \
             build with the XTEST fallback or run on macOS/Windows"
                .to_string(),
        ))
    }

    fn emit(&mut self, event: InputEvent) -> Result<(), BackendError> {
        self.device
            .write_all(&event.to_bytes())
            .map_err(|e| BackendError::InjectionFailed(format!("uinput write failed: {e}")))
    }

    /// Publishes the batched events. Without a `SYN_REPORT` the kernel holds them indefinitely.
    fn sync(&mut self) -> Result<(), BackendError> {
        self.emit(InputEvent::new(EV_SYN, SYN_REPORT, 0))
    }
}

fn map_button(button: Button) -> u16 {
    match button {
        Button::Left => BTN_LEFT,
        Button::Right => BTN_RIGHT,
        Button::Middle => BTN_MIDDLE,
        Button::Back => BTN_SIDE,
        Button::Forward => BTN_EXTRA,
    }
}

impl Backend for LinuxBackend {
    fn pointer_absolute(&mut self, x: i32, y: i32) -> Result<(), BackendError> {
        if !self.absolute_capable {
            return Err(BackendError::Unavailable(
                "virtual device was not registered with absolute axes".to_string(),
            ));
        }
        self.emit(InputEvent::new(EV_ABS, ABS_X, x))?;
        self.emit(InputEvent::new(EV_ABS, ABS_Y, y))?;
        self.sync()
    }

    fn pointer_relative(&mut self, dx: f64, dy: f64) -> Result<(), BackendError> {
        self.emit(InputEvent::new(EV_REL, REL_X, dx.round() as i32))?;
        self.emit(InputEvent::new(EV_REL, REL_Y, dy.round() as i32))?;
        self.sync()
    }

    fn button(&mut self, button: Button, down: bool) -> Result<(), BackendError> {
        self.emit(InputEvent::new(EV_KEY, map_button(button), i32::from(down)))?;
        self.sync()
    }

    fn scroll(&mut self, delta: ScrollDelta) -> Result<(), BackendError> {
        // The high-resolution axes take units of 1/120 detent, which is exactly the wire unit, so
        // smooth trackpad scrolling survives without quantisation.
        if delta.vertical != 0 {
            self.emit(InputEvent::new(
                EV_REL,
                REL_WHEEL_HI_RES,
                i32::from(delta.vertical),
            ))?;
        }
        if delta.horizontal != 0 {
            self.emit(InputEvent::new(
                EV_REL,
                REL_HWHEEL_HI_RES,
                i32::from(delta.horizontal),
            ))?;
        }
        self.sync()
    }

    fn key(&mut self, usage: u16, down: bool) -> Result<(), BackendError> {
        let code = super::platform_code(usage)?;
        self.emit(InputEvent::new(EV_KEY, code, i32::from(down)))?;
        self.sync()
    }

    fn text(&mut self, _text: &str) -> Result<(), BackendError> {
        // uinput has no Unicode path: the kernel emits key codes and the compositor's layout turns
        // them into characters. Typing arbitrary text means temporarily remapping a scratch key
        // through the layout, which is intrusive and racy. Refusing is honest; the controller falls
        // back to HID mode.
        Err(BackendError::Unsupported)
    }

    fn name(&self) -> &'static str {
        "linux-uinput"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_event_encodes_to_the_kernel_layout() {
        let e = InputEvent::new(EV_KEY, 30, 1);
        let bytes = e.to_bytes();
        assert_eq!(
            bytes.len(),
            24,
            "struct input_event is 24 bytes on 64-bit Linux"
        );
        assert_eq!(u16::from_ne_bytes([bytes[16], bytes[17]]), EV_KEY);
        assert_eq!(u16::from_ne_bytes([bytes[18], bytes[19]]), 30);
        assert_eq!(
            i32::from_ne_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
            1
        );
    }

    #[test]
    fn button_mapping_is_distinct() {
        let codes: std::collections::HashSet<u16> = [
            Button::Left,
            Button::Right,
            Button::Middle,
            Button::Back,
            Button::Forward,
        ]
        .into_iter()
        .map(map_button)
        .collect();
        assert_eq!(codes.len(), 5);
    }
}
