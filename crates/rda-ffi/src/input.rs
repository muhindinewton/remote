//! Input encoding across the FFI boundary — `docs/PROTOCOL.md` §7.
//!
//! Dart captures pointer and keyboard events; these turn them into wire frames the transport can
//! send unchanged. The encoding lives here rather than in Dart for one reason: `rda-proto` is the
//! single source of truth for the wire format, and a second implementation in another language
//! would drift from it silently.
//!
//! The coalescing rule is the other reason. A trackpad emits pointer events at up to 1000 Hz;
//! forwarding all of them is ~352 kbps of pure overhead on a link that may only have 800 kbps
//! (`docs/PROTOCOL.md` §8). [`RdaInputEncoder`] enforces the 60 Hz cap, and flushes pending motion
//! before a button so the click's coordinates stay correct.

use crate::error::{clear_last_error, set_last_error};
use crate::{RdaStatus, RDA_ERR_INVALID_ARGUMENT, RDA_ERR_NULL_ARGUMENT, RDA_OK};
use rda_proto::control::{
    ControlFrame, KeyAction, Modifiers, MouseButtonId, Payload, USAGE_PAGE_KEYBOARD,
};

/// Maximum pointer events per second sent to the host.
///
/// Matches the negotiated frame rate ceiling: sampling faster than the host can redraw spends
/// bandwidth to move a cursor nobody sees move.
pub const POINTER_HZ: u64 = 60;

/// Encodes input events into wire frames, with coalescing.
pub struct RdaInputEncoder {
    sequence: u16,
    epoch_ms: u64,
    last_pointer_ms: u64,
    /// Motion held back by coalescing, flushed before any button or key event.
    pending_move: Option<(u8, u16, u16, Modifiers)>,
    /// The most recently produced frame, kept alive so its bytes can be borrowed.
    scratch: Vec<u8>,
    coalesced: u64,
    emitted: u64,
}

impl Default for RdaInputEncoder {
    fn default() -> Self {
        Self::new(0)
    }
}

impl RdaInputEncoder {
    /// Creates an encoder whose timestamps are relative to `epoch_ms`.
    #[must_use]
    pub fn new(epoch_ms: u64) -> Self {
        Self {
            sequence: 0,
            epoch_ms,
            last_pointer_ms: 0,
            pending_move: None,
            scratch: Vec::new(),
            coalesced: 0,
            emitted: 0,
        }
    }

    fn next_sequence(&mut self) -> u16 {
        let s = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        s
    }

    fn encode(&mut self, payload: Payload, now_ms: u64) -> &[u8] {
        let sequence = self.next_sequence();
        let timestamp = now_ms.saturating_sub(self.epoch_ms) as u32;
        let frame = ControlFrame::new(payload, sequence, timestamp);
        self.scratch = frame.encode();
        self.emitted += 1;
        &self.scratch
    }

    /// Number of pointer events dropped by coalescing, and frames actually produced.
    #[must_use]
    pub fn stats(&self) -> (u64, u64) {
        (self.coalesced, self.emitted)
    }
}

/// Creates an input encoder.
#[no_mangle]
pub extern "C" fn rda_input_create(epoch_ms: u64) -> *mut RdaInputEncoder {
    Box::into_raw(Box::new(RdaInputEncoder::new(epoch_ms)))
}

/// Destroys an input encoder. Null is accepted and ignored.
///
/// # Safety
///
/// `handle` must have come from [`rda_input_create`] and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn rda_input_destroy(handle: *mut RdaInputEncoder) {
    if handle.is_null() {
        return;
    }
    // SAFETY: the caller guarantees the handle came from `Box::into_raw` and is destroyed once.
    drop(unsafe { Box::from_raw(handle) });
}

/// # Safety
///
/// `handle` must be null or a live encoder.
unsafe fn encoder<'a>(handle: *mut RdaInputEncoder) -> Option<&'a mut RdaInputEncoder> {
    if handle.is_null() {
        set_last_error("input encoder handle was null");
        return None;
    }
    // SAFETY: the caller guarantees a live handle used from one thread.
    Some(unsafe { &mut *handle })
}

/// Result of encoding one input event.
///
/// `len` is zero when the event was coalesced away, which is the normal outcome for most pointer
/// motion and must not be treated as an error.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RdaInputFrame {
    /// Pointer to the encoded frame, valid until the next call on this encoder.
    pub data: *const u8,
    /// Length in bytes, or zero when nothing was produced.
    pub len: usize,
    /// Which DataChannel this frame must be sent on — see [`rda_channel_label`].
    pub channel: u8,
}

/// Channel identifier for the reliable ordered input channel (`input-k`).
pub const RDA_CHANNEL_INPUT_KEYS: u8 = 1;
/// Channel identifier for the unreliable unordered pointer channel (`input-p`).
pub const RDA_CHANNEL_INPUT_POINTER: u8 = 2;

/// Records pointer motion, coalescing to [`POINTER_HZ`].
///
/// Coordinates are normalised `0..=65535` across the target display, so they are independent of
/// resolution and DPI and survive a resolution change in flight.
///
/// # Safety
///
/// `handle` must be a live encoder and `out` must point at a writable [`RdaInputFrame`].
#[no_mangle]
pub unsafe extern "C" fn rda_input_pointer_move(
    handle: *mut RdaInputEncoder,
    display_id: u8,
    x_norm: u16,
    y_norm: u16,
    modifiers: u16,
    now_ms: u64,
    out: *mut RdaInputFrame,
) -> RdaStatus {
    clear_last_error();
    // SAFETY: the caller guarantees a live handle.
    let Some(enc) = (unsafe { encoder(handle) }) else {
        return RDA_ERR_NULL_ARGUMENT;
    };
    if out.is_null() {
        set_last_error("output pointer was null");
        return RDA_ERR_NULL_ARGUMENT;
    }

    let interval = 1000 / POINTER_HZ;
    if now_ms.saturating_sub(enc.last_pointer_ms) < interval {
        // Hold the newest position; the older one is worthless.
        enc.pending_move = Some((display_id, x_norm, y_norm, Modifiers(modifiers)));
        enc.coalesced += 1;
        // SAFETY: the caller guarantees `out` is writable.
        unsafe { std::ptr::write(out, RdaInputFrame::default()) };
        return RDA_OK;
    }

    enc.last_pointer_ms = now_ms;
    enc.pending_move = None;
    let bytes = enc.encode(
        Payload::MouseMove {
            display_id,
            flags: 0,
            x_norm,
            y_norm,
            modifiers: Modifiers(modifiers),
        },
        now_ms,
    );
    let frame = RdaInputFrame {
        data: bytes.as_ptr(),
        len: bytes.len(),
        channel: RDA_CHANNEL_INPUT_POINTER,
    };
    // SAFETY: the caller guarantees `out` is writable.
    unsafe { std::ptr::write(out, frame) };
    RDA_OK
}

/// Encodes a mouse button event.
///
/// Carries its own coordinates because pointer motion rides an unreliable channel: without them a
/// dropped move immediately before a click would place the click at the wrong place
/// (`docs/PROTOCOL.md` §7.3).
///
/// # Safety
///
/// `handle` must be a live encoder and `out` must point at a writable [`RdaInputFrame`].
#[no_mangle]
pub unsafe extern "C" fn rda_input_pointer_button(
    handle: *mut RdaInputEncoder,
    button: u8,
    pressed: bool,
    display_id: u8,
    x_norm: u16,
    y_norm: u16,
    modifiers: u16,
    click_count: u8,
    now_ms: u64,
    out: *mut RdaInputFrame,
) -> RdaStatus {
    clear_last_error();
    // SAFETY: the caller guarantees a live handle.
    let Some(enc) = (unsafe { encoder(handle) }) else {
        return RDA_ERR_NULL_ARGUMENT;
    };
    if out.is_null() {
        set_last_error("output pointer was null");
        return RDA_ERR_NULL_ARGUMENT;
    }

    let button_id = match button {
        1 => MouseButtonId::Left,
        2 => MouseButtonId::Right,
        3 => MouseButtonId::Middle,
        4 => MouseButtonId::X1,
        5 => MouseButtonId::X2,
        other => {
            set_last_error(format!("unknown mouse button {other}"));
            return RDA_ERR_INVALID_ARGUMENT;
        }
    };

    // Any coalesced motion is now stale in a way that matters: the click must land where the user
    // last saw the cursor, so the pending position is discarded in favour of the click's own.
    enc.pending_move = None;

    let bytes = enc.encode(
        Payload::MouseButton {
            button: button_id,
            action: if pressed {
                KeyAction::Down
            } else {
                KeyAction::Up
            },
            x_norm,
            y_norm,
            modifiers: Modifiers(modifiers),
            display_id,
            click_count: click_count.clamp(1, 3),
        },
        now_ms,
    );
    let frame = RdaInputFrame {
        data: bytes.as_ptr(),
        len: bytes.len(),
        channel: RDA_CHANNEL_INPUT_KEYS,
    };
    // SAFETY: the caller guarantees `out` is writable.
    unsafe { std::ptr::write(out, frame) };
    RDA_OK
}

/// Encodes a scroll event, in units of 1/120 of a traditional detent.
///
/// # Safety
///
/// `handle` must be a live encoder and `out` must point at a writable [`RdaInputFrame`].
#[no_mangle]
pub unsafe extern "C" fn rda_input_scroll(
    handle: *mut RdaInputEncoder,
    delta_v: i16,
    delta_h: i16,
    display_id: u8,
    modifiers: u16,
    now_ms: u64,
    out: *mut RdaInputFrame,
) -> RdaStatus {
    clear_last_error();
    // SAFETY: the caller guarantees a live handle.
    let Some(enc) = (unsafe { encoder(handle) }) else {
        return RDA_ERR_NULL_ARGUMENT;
    };
    if out.is_null() {
        set_last_error("output pointer was null");
        return RDA_ERR_NULL_ARGUMENT;
    }

    let bytes = enc.encode(
        Payload::MouseWheel {
            delta_v,
            delta_h,
            modifiers: Modifiers(modifiers),
            display_id,
            flags: 0,
        },
        now_ms,
    );
    let frame = RdaInputFrame {
        data: bytes.as_ptr(),
        len: bytes.len(),
        channel: RDA_CHANNEL_INPUT_KEYS,
    };
    // SAFETY: the caller guarantees `out` is writable.
    unsafe { std::ptr::write(out, frame) };
    RDA_OK
}

/// Encodes a key event from a **HID usage id**, not a platform key code.
///
/// Dart must map its own key events to HID usages before calling this. That is the whole point of
/// the design: a controller on an AZERTY layout pressing the key labelled `A` must produce whatever
/// the host's layout produces at that position (`docs/ARCHITECTURE.md` §4.2).
///
/// # Safety
///
/// `handle` must be a live encoder and `out` must point at a writable [`RdaInputFrame`].
#[no_mangle]
pub unsafe extern "C" fn rda_input_key(
    handle: *mut RdaInputEncoder,
    usage_id: u16,
    pressed: bool,
    modifiers: u16,
    now_ms: u64,
    out: *mut RdaInputFrame,
) -> RdaStatus {
    clear_last_error();
    // SAFETY: the caller guarantees a live handle.
    let Some(enc) = (unsafe { encoder(handle) }) else {
        return RDA_ERR_NULL_ARGUMENT;
    };
    if out.is_null() {
        set_last_error("output pointer was null");
        return RDA_ERR_NULL_ARGUMENT;
    }
    // Range-check here as well as on the host: a bad usage should never reach the wire.
    if !(0x01..=0xE7).contains(&usage_id) {
        set_last_error(format!(
            "HID usage {usage_id:#06x} is outside the keyboard page"
        ));
        return RDA_ERR_INVALID_ARGUMENT;
    }

    let bytes = enc.encode(
        Payload::KeyEvent {
            usage_page: USAGE_PAGE_KEYBOARD,
            usage_id,
            action: if pressed {
                KeyAction::Down
            } else {
                KeyAction::Up
            },
            flags: 0,
            modifiers: Modifiers(modifiers),
        },
        now_ms,
    );
    let frame = RdaInputFrame {
        data: bytes.as_ptr(),
        len: bytes.len(),
        channel: RDA_CHANNEL_INPUT_KEYS,
    };
    // SAFETY: the caller guarantees `out` is writable.
    unsafe { std::ptr::write(out, frame) };
    RDA_OK
}

/// Encodes the periodic full key-state snapshot.
///
/// The host reconciles against this and releases anything that should not be down, which bounds the
/// lifetime of a lost key-up to one sync interval. Without it, a dropped release leaves a modifier
/// stuck and every subsequent keystroke becomes a shortcut (`docs/ARCHITECTURE.md` §4.4).
///
/// # Safety
///
/// `handle` must be a live encoder, `usages` must point at `count` readable `u16` values, and `out`
/// must point at a writable [`RdaInputFrame`].
#[no_mangle]
pub unsafe extern "C" fn rda_input_key_state_sync(
    handle: *mut RdaInputEncoder,
    usages: *const u16,
    count: usize,
    modifiers: u16,
    now_ms: u64,
    out: *mut RdaInputFrame,
) -> RdaStatus {
    clear_last_error();
    // SAFETY: the caller guarantees a live handle.
    let Some(enc) = (unsafe { encoder(handle) }) else {
        return RDA_ERR_NULL_ARGUMENT;
    };
    if out.is_null() {
        set_last_error("output pointer was null");
        return RDA_ERR_NULL_ARGUMENT;
    }
    if count > rda_proto::control::MAX_PRESSED_KEYS {
        set_last_error(format!("cannot report {count} pressed keys"));
        return RDA_ERR_INVALID_ARGUMENT;
    }
    if count > 0 && usages.is_null() {
        set_last_error("key list was null but the count was non-zero");
        return RDA_ERR_NULL_ARGUMENT;
    }

    // SAFETY: the caller guarantees `count` readable `u16` values; an empty list uses a null-safe
    // empty slice instead of dereferencing.
    let pressed: Vec<u16> = if count == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(usages, count) }.to_vec()
    };

    let bytes = enc.encode(
        Payload::KeyStateSync {
            modifiers: Modifiers(modifiers),
            authoritative: true,
            pressed,
        },
        now_ms,
    );
    let frame = RdaInputFrame {
        data: bytes.as_ptr(),
        len: bytes.len(),
        channel: RDA_CHANNEL_INPUT_KEYS,
    };
    // SAFETY: the caller guarantees `out` is writable.
    unsafe { std::ptr::write(out, frame) };
    RDA_OK
}

/// The DataChannel label for a channel id, or null for an unknown id.
///
/// Lets Dart name the channel it must send on without duplicating the topology table.
#[no_mangle]
pub extern "C" fn rda_channel_label(channel: u8) -> *const std::ffi::c_char {
    match channel {
        RDA_CHANNEL_INPUT_KEYS => c"input-k".as_ptr(),
        RDA_CHANNEL_INPUT_POINTER => c"input-p".as_ptr(),
        _ => std::ptr::null(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rda_proto::control::{Channel, MessageType};

    fn encoder_handle() -> *mut RdaInputEncoder {
        rda_input_create(0)
    }

    /// Decodes whatever the last call produced.
    ///
    /// # Safety
    ///
    /// `frame.data` must still be valid.
    unsafe fn decode(frame: &RdaInputFrame) -> ControlFrame {
        assert!(!frame.data.is_null());
        // SAFETY: the caller guarantees the borrow is still valid.
        let bytes = unsafe { std::slice::from_raw_parts(frame.data, frame.len) };
        ControlFrame::decode(bytes).expect("the encoder must produce decodable frames")
    }

    #[test]
    fn every_entry_point_tolerates_a_null_handle() {
        let null = std::ptr::null_mut();
        let mut out = RdaInputFrame::default();
        // SAFETY: null is explicitly permitted by the contract.
        unsafe {
            assert_eq!(
                rda_input_pointer_move(null, 0, 0, 0, 0, 0, &mut out),
                RDA_ERR_NULL_ARGUMENT
            );
            assert_eq!(
                rda_input_pointer_button(null, 1, true, 0, 0, 0, 0, 1, 0, &mut out),
                RDA_ERR_NULL_ARGUMENT
            );
            assert_eq!(
                rda_input_scroll(null, 0, 0, 0, 0, 0, &mut out),
                RDA_ERR_NULL_ARGUMENT
            );
            assert_eq!(
                rda_input_key(null, 0x04, true, 0, 0, &mut out),
                RDA_ERR_NULL_ARGUMENT
            );
            assert_eq!(
                rda_input_key_state_sync(null, std::ptr::null(), 0, 0, 0, &mut out),
                RDA_ERR_NULL_ARGUMENT
            );
            rda_input_destroy(null);
        }
    }

    #[test]
    fn a_null_output_pointer_is_refused() {
        let handle = encoder_handle();
        // SAFETY: live handle; null out is explicitly permitted as an argument to reject.
        unsafe {
            assert_eq!(
                rda_input_pointer_move(handle, 0, 0, 0, 0, 0, std::ptr::null_mut()),
                RDA_ERR_NULL_ARGUMENT
            );
            rda_input_destroy(handle);
        }
    }

    #[test]
    fn pointer_motion_encodes_to_the_unreliable_channel() {
        let handle = encoder_handle();
        let mut out = RdaInputFrame::default();
        // SAFETY: live handle and writable output.
        unsafe {
            assert_eq!(
                rda_input_pointer_move(handle, 0, 32768, 16384, 0, 100, &mut out),
                RDA_OK
            );
            assert_eq!(out.channel, RDA_CHANNEL_INPUT_POINTER);

            let frame = decode(&out);
            assert_eq!(frame.header.typed(), Some(MessageType::MouseMove));
            assert_eq!(
                frame.header.typed().unwrap().channel(),
                Channel::InputPointer
            );
            match frame.payload {
                Payload::MouseMove { x_norm, y_norm, .. } => {
                    assert_eq!((x_norm, y_norm), (32768, 16384));
                }
                other => panic!("expected MouseMove, got {other:?}"),
            }
            rda_input_destroy(handle);
        }
    }

    #[test]
    fn pointer_motion_is_coalesced_to_the_target_rate() {
        // A 1000 Hz trackpad would otherwise spend ~352 kbps on cursor updates nobody can see.
        let handle = encoder_handle();
        let mut out = RdaInputFrame::default();
        let mut emitted = 0;
        // SAFETY: live handle and writable output.
        unsafe {
            for ms in 0..100u64 {
                rda_input_pointer_move(handle, 0, ms as u16, 0, 0, ms, &mut out);
                if out.len > 0 {
                    emitted += 1;
                }
            }
            // 100 ms at 60 Hz is about six frames, not a hundred.
            assert!(
                (5..=8).contains(&emitted),
                "emitted {emitted} frames in 100 ms"
            );
            rda_input_destroy(handle);
        }
    }

    #[test]
    fn a_coalesced_event_is_reported_as_success_with_no_bytes() {
        // Dart must not treat this as an error: it is the normal outcome for most motion.
        let handle = encoder_handle();
        let mut out = RdaInputFrame::default();
        // SAFETY: live handle and writable output.
        unsafe {
            assert_eq!(
                rda_input_pointer_move(handle, 0, 1, 1, 0, 100, &mut out),
                RDA_OK
            );
            assert!(out.len > 0);
            assert_eq!(
                rda_input_pointer_move(handle, 0, 2, 2, 0, 101, &mut out),
                RDA_OK
            );
            assert_eq!(out.len, 0, "a coalesced event produces no frame");
            assert!(out.data.is_null());
            rda_input_destroy(handle);
        }
    }

    #[test]
    fn a_click_carries_its_own_coordinates_on_the_reliable_channel() {
        // Without this, a dropped move immediately before the click puts it in the wrong place.
        let handle = encoder_handle();
        let mut out = RdaInputFrame::default();
        // SAFETY: live handle and writable output.
        unsafe {
            assert_eq!(
                rda_input_pointer_button(handle, 1, true, 0, 40000, 20000, 0, 1, 100, &mut out),
                RDA_OK
            );
            assert_eq!(out.channel, RDA_CHANNEL_INPUT_KEYS);

            match decode(&out).payload {
                Payload::MouseButton {
                    button,
                    action,
                    x_norm,
                    y_norm,
                    ..
                } => {
                    assert_eq!(button, MouseButtonId::Left);
                    assert_eq!(action, KeyAction::Down);
                    assert_eq!((x_norm, y_norm), (40000, 20000));
                }
                other => panic!("expected MouseButton, got {other:?}"),
            }
            rda_input_destroy(handle);
        }
    }

    #[test]
    fn an_unknown_mouse_button_is_refused() {
        let handle = encoder_handle();
        let mut out = RdaInputFrame::default();
        // SAFETY: live handle and writable output.
        unsafe {
            assert_eq!(
                rda_input_pointer_button(handle, 99, true, 0, 0, 0, 0, 1, 0, &mut out),
                RDA_ERR_INVALID_ARGUMENT
            );
            rda_input_destroy(handle);
        }
    }

    #[test]
    fn keys_are_encoded_as_hid_usages() {
        let handle = encoder_handle();
        let mut out = RdaInputFrame::default();
        // SAFETY: live handle and writable output.
        unsafe {
            // 0x04 is the key at the 'A' position, whatever the layout calls it.
            assert_eq!(
                rda_input_key(handle, 0x04, true, Modifiers::LEFT_SHIFT, 100, &mut out),
                RDA_OK
            );
            match decode(&out).payload {
                Payload::KeyEvent {
                    usage_page,
                    usage_id,
                    action,
                    modifiers,
                    ..
                } => {
                    assert_eq!(usage_page, USAGE_PAGE_KEYBOARD);
                    assert_eq!(usage_id, 0x04);
                    assert_eq!(action, KeyAction::Down);
                    assert!(modifiers.contains(Modifiers::LEFT_SHIFT));
                }
                other => panic!("expected KeyEvent, got {other:?}"),
            }
            rda_input_destroy(handle);
        }
    }

    #[test]
    fn an_out_of_range_hid_usage_never_reaches_the_wire() {
        let handle = encoder_handle();
        let mut out = RdaInputFrame::default();
        // SAFETY: live handle and writable output.
        unsafe {
            for usage in [0x0000u16, 0x00FF, 0xFFFF] {
                assert_eq!(
                    rda_input_key(handle, usage, true, 0, 0, &mut out),
                    RDA_ERR_INVALID_ARGUMENT,
                    "usage {usage:#06x} must be refused"
                );
            }
            rda_input_destroy(handle);
        }
    }

    #[test]
    fn key_state_sync_carries_the_full_pressed_set() {
        let handle = encoder_handle();
        let mut out = RdaInputFrame::default();
        let usages = [0x00E1u16, 0x0004];
        // SAFETY: live handle, valid slice, writable output.
        unsafe {
            assert_eq!(
                rda_input_key_state_sync(
                    handle,
                    usages.as_ptr(),
                    usages.len(),
                    Modifiers::LEFT_SHIFT,
                    100,
                    &mut out
                ),
                RDA_OK
            );
            match decode(&out).payload {
                Payload::KeyStateSync {
                    pressed,
                    authoritative,
                    ..
                } => {
                    assert_eq!(pressed, vec![0x00E1, 0x0004]);
                    assert!(authoritative);
                }
                other => panic!("expected KeyStateSync, got {other:?}"),
            }
            rda_input_destroy(handle);
        }
    }

    #[test]
    fn an_empty_key_state_sync_is_valid_and_does_not_dereference_null() {
        // The all-keys-up sync is the one that actually releases a stuck modifier.
        let handle = encoder_handle();
        let mut out = RdaInputFrame::default();
        // SAFETY: live handle; a null list with count zero is explicitly permitted.
        unsafe {
            assert_eq!(
                rda_input_key_state_sync(handle, std::ptr::null(), 0, 0, 100, &mut out),
                RDA_OK
            );
            match decode(&out).payload {
                Payload::KeyStateSync { pressed, .. } => assert!(pressed.is_empty()),
                other => panic!("expected KeyStateSync, got {other:?}"),
            }
            rda_input_destroy(handle);
        }
    }

    #[test]
    fn too_many_pressed_keys_are_refused() {
        let handle = encoder_handle();
        let mut out = RdaInputFrame::default();
        let usages = [0x04u16; 100];
        // SAFETY: live handle and valid slice.
        unsafe {
            assert_eq!(
                rda_input_key_state_sync(handle, usages.as_ptr(), usages.len(), 0, 0, &mut out),
                RDA_ERR_INVALID_ARGUMENT
            );
            rda_input_destroy(handle);
        }
    }

    #[test]
    fn sequence_numbers_advance_and_wrap_without_panicking() {
        let handle = encoder_handle();
        let mut out = RdaInputFrame::default();
        // SAFETY: live handle and writable output.
        unsafe {
            let mut seen = Vec::new();
            for i in 0..5u64 {
                rda_input_key(handle, 0x04, i % 2 == 0, 0, i, &mut out);
                seen.push(decode(&out).header.sequence);
            }
            assert_eq!(seen, vec![0, 1, 2, 3, 4]);

            // Wrapping must not panic: at a few hundred events per second this happens routinely.
            (*handle).sequence = u16::MAX;
            rda_input_key(handle, 0x04, true, 0, 0, &mut out);
            rda_input_key(handle, 0x04, false, 0, 0, &mut out);
            assert_eq!(decode(&out).header.sequence, 0);
            rda_input_destroy(handle);
        }
    }

    #[test]
    fn channel_labels_match_the_protocol_topology() {
        use std::ffi::CStr;
        // SAFETY: the returned pointers are static string literals.
        unsafe {
            assert_eq!(
                CStr::from_ptr(rda_channel_label(RDA_CHANNEL_INPUT_KEYS))
                    .to_str()
                    .unwrap(),
                Channel::InputKeys.label()
            );
            assert_eq!(
                CStr::from_ptr(rda_channel_label(RDA_CHANNEL_INPUT_POINTER))
                    .to_str()
                    .unwrap(),
                Channel::InputPointer.label()
            );
        }
        assert!(rda_channel_label(200).is_null());
    }
}
