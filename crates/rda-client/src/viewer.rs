//! The viewer window: what makes this a remote desktop rather than a frame dumper.
//!
//! **Why the window owns the main thread.** macOS requires the event loop to run on the process's
//! first thread, and Windows requires messages to be pumped on the thread that created the window.
//! Neither is negotiable, so the network runs on a tokio runtime on another thread and the two talk
//! over channels. That is also the right shape regardless of the OS rule: a decode that takes 12 ms
//! must never be the reason a keystroke waits.
//!
//! **The channels are deliberately asymmetric.** Frames go to a depth-1 slot where a newer frame
//! replaces an older one, because showing a stale frame is worse than showing nothing — the buffer
//! that matters is the jitter buffer, and a second queue behind it would silently add latency no
//! one budgeted for. Input goes to an unbounded queue, because every event matters: a dropped
//! key-up is a stuck key on someone else's machine.

use rda_proto::control::{Modifiers, MouseButtonId};
use std::sync::mpsc;

/// One thing the user did, on its way to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEvent {
    /// Pointer moved to a position normalised against the remote display.
    Move {
        x_norm: u16,
        y_norm: u16,
        modifiers: Modifiers,
    },
    /// A mouse button changed state, carrying where the pointer was when it happened.
    Button {
        button: MouseButtonId,
        down: bool,
        x_norm: u16,
        y_norm: u16,
        modifiers: Modifiers,
    },
    /// The wheel turned, in wheel detents scaled by 120 as the wire expects.
    Scroll {
        vertical: i16,
        horizontal: i16,
        modifiers: Modifiers,
    },
    /// A key changed state, identified by HID usage.
    Key {
        usage: u16,
        down: bool,
        modifiers: Modifiers,
    },
    /// The window closed; the session should end.
    Quit,
}

/// A decoded frame ready to display, already converted to what the window wants.
pub struct Framebuffer {
    /// `0RGB` pixels, one `u32` per pixel, tightly packed.
    pub pixels: Vec<u32>,
    pub width: usize,
    pub height: usize,
}

impl Framebuffer {
    /// Converts a decoded BGRA frame, dropping the row padding the decoder added.
    ///
    /// The stride is not decoration: VideoToolbox aligns rows to 16 or 64 bytes, so at most widths
    /// `stride != width * 4`. Ignoring it produces the diagonal shear that looks like a codec bug
    /// and is not one.
    #[must_use]
    pub fn from_decoded(frame: &rda_decode::decoder::DecodedFrame) -> Self {
        let (w, h) = (frame.width as usize, frame.height as usize);
        let mut pixels = Vec::with_capacity(w * h);
        for y in 0..h {
            let row = &frame.data[y * frame.stride..y * frame.stride + w * 4];
            pixels.extend(row.chunks_exact(4).map(|px| {
                // BGRA in memory, 0RGB in a u32.
                u32::from(px[2]) << 16 | u32::from(px[1]) << 8 | u32::from(px[0])
            }));
        }
        Self {
            pixels,
            width: w,
            height: h,
        }
    }
}

/// The newest frame, and only the newest.
///
/// A queue here would trade latency for smoothness, which is the wrong trade for remote control:
/// the user is steering, and a cursor that lags behind the hand is worse than one that stutters.
#[derive(Default)]
pub struct LatestFrame {
    slot: std::sync::Mutex<Option<Framebuffer>>,
}

impl LatestFrame {
    /// Replaces whatever was pending.
    pub fn put(&self, frame: Framebuffer) {
        *self.slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(frame);
    }

    /// Takes the pending frame, if there is one.
    pub fn take(&self) -> Option<Framebuffer> {
        self.slot.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

/// Translates a `minifb` key to a HID usage on page 0x07.
///
/// HID usage is the canonical key identity on the wire (`docs/PROTOCOL.md` §7.5) because it names a
/// physical key position rather than the character a layout would produce — which is what makes
/// a French keyboard drive an American host correctly.
#[must_use]
pub fn hid_usage_for(key: minifb::Key) -> Option<u16> {
    use minifb::Key as K;
    let name = match key {
        K::A => "KeyA",
        K::B => "KeyB",
        K::C => "KeyC",
        K::D => "KeyD",
        K::E => "KeyE",
        K::F => "KeyF",
        K::G => "KeyG",
        K::H => "KeyH",
        K::I => "KeyI",
        K::J => "KeyJ",
        K::K => "KeyK",
        K::L => "KeyL",
        K::M => "KeyM",
        K::N => "KeyN",
        K::O => "KeyO",
        K::P => "KeyP",
        K::Q => "KeyQ",
        K::R => "KeyR",
        K::S => "KeyS",
        K::T => "KeyT",
        K::U => "KeyU",
        K::V => "KeyV",
        K::W => "KeyW",
        K::X => "KeyX",
        K::Y => "KeyY",
        K::Z => "KeyZ",
        K::Key1 => "Digit1",
        K::Key2 => "Digit2",
        K::Key3 => "Digit3",
        K::Key4 => "Digit4",
        K::Key5 => "Digit5",
        K::Key6 => "Digit6",
        K::Key7 => "Digit7",
        K::Key8 => "Digit8",
        K::Key9 => "Digit9",
        K::Key0 => "Digit0",
        K::Enter => "Enter",
        K::Escape => "Escape",
        K::Backspace => "Backspace",
        K::Tab => "Tab",
        K::Space => "Space",
        K::Minus => "Minus",
        K::Equal => "Equal",
        K::LeftBracket => "BracketLeft",
        K::RightBracket => "BracketRight",
        K::Backslash => "Backslash",
        K::Semicolon => "Semicolon",
        K::Apostrophe => "Quote",
        K::Backquote => "Backquote",
        K::Comma => "Comma",
        K::Period => "Period",
        K::Slash => "Slash",
        K::CapsLock => "CapsLock",
        K::F1 => "F1",
        K::F2 => "F2",
        K::F3 => "F3",
        K::F4 => "F4",
        K::F5 => "F5",
        K::F6 => "F6",
        K::F7 => "F7",
        K::F8 => "F8",
        K::F9 => "F9",
        K::F10 => "F10",
        K::F11 => "F11",
        K::F12 => "F12",
        K::Insert => "Insert",
        K::Home => "Home",
        K::PageUp => "PageUp",
        K::Delete => "Delete",
        K::End => "End",
        K::PageDown => "PageDown",
        K::Right => "ArrowRight",
        K::Left => "ArrowLeft",
        K::Down => "ArrowDown",
        K::Up => "ArrowUp",
        K::LeftCtrl => "ControlLeft",
        K::LeftShift => "ShiftLeft",
        K::LeftAlt => "AltLeft",
        K::LeftSuper => "MetaLeft",
        K::RightCtrl => "ControlRight",
        K::RightShift => "ShiftRight",
        K::RightAlt => "AltRight",
        K::RightSuper => "MetaRight",
        _ => return None,
    };
    rda_input::hid::lookup_by_name(name).map(|m| m.usage)
}

/// Every key the viewer forwards, so the window loop can diff press state each frame.
///
/// `minifb` reports keys held rather than transitions, so the transitions are derived here. Missing
/// a key-up leaves a modifier stuck down on the *host* — someone else's machine — which is why the
/// diff is over a fixed list rather than only over keys seen recently.
#[must_use]
pub fn tracked_keys() -> Vec<minifb::Key> {
    use minifb::Key as K;
    vec![
        K::A,
        K::B,
        K::C,
        K::D,
        K::E,
        K::F,
        K::G,
        K::H,
        K::I,
        K::J,
        K::K,
        K::L,
        K::M,
        K::N,
        K::O,
        K::P,
        K::Q,
        K::R,
        K::S,
        K::T,
        K::U,
        K::V,
        K::W,
        K::X,
        K::Y,
        K::Z,
        K::Key0,
        K::Key1,
        K::Key2,
        K::Key3,
        K::Key4,
        K::Key5,
        K::Key6,
        K::Key7,
        K::Key8,
        K::Key9,
        K::Enter,
        K::Escape,
        K::Backspace,
        K::Tab,
        K::Space,
        K::Minus,
        K::Equal,
        K::LeftBracket,
        K::RightBracket,
        K::Backslash,
        K::Semicolon,
        K::Apostrophe,
        K::Backquote,
        K::Comma,
        K::Period,
        K::Slash,
        K::CapsLock,
        K::F1,
        K::F2,
        K::F3,
        K::F4,
        K::F5,
        K::F6,
        K::F7,
        K::F8,
        K::F9,
        K::F10,
        K::F11,
        K::F12,
        K::Insert,
        K::Home,
        K::PageUp,
        K::Delete,
        K::End,
        K::PageDown,
        K::Right,
        K::Left,
        K::Down,
        K::Up,
        K::LeftCtrl,
        K::LeftShift,
        K::LeftAlt,
        K::LeftSuper,
        K::RightCtrl,
        K::RightShift,
        K::RightAlt,
        K::RightSuper,
    ]
}

/// Builds the modifier bitmask the wire carries alongside every event.
#[must_use]
pub fn modifiers_from(window: &minifb::Window) -> Modifiers {
    use minifb::Key as K;
    // Bits 0-7 are byte-identical to the HID boot-protocol modifier byte, so this is assembled as
    // a mask rather than through a translation table.
    let mut bits = 0u16;
    for (key, bit) in [
        (K::LeftCtrl, Modifiers::LEFT_CTRL),
        (K::LeftShift, Modifiers::LEFT_SHIFT),
        (K::LeftAlt, Modifiers::LEFT_ALT),
        (K::LeftSuper, Modifiers::LEFT_GUI),
        (K::RightCtrl, Modifiers::RIGHT_CTRL),
        (K::RightShift, Modifiers::RIGHT_SHIFT),
        (K::RightAlt, Modifiers::RIGHT_ALT),
        (K::RightSuper, Modifiers::RIGHT_GUI),
    ] {
        if window.is_key_down(key) {
            bits |= bit;
        }
    }
    Modifiers(bits)
}

/// Maps a window pointer position onto the remote display.
///
/// **The window is not the remote screen.** The viewer preserves aspect ratio, so unless the two
/// happen to match, the picture sits in a letterboxed sub-rectangle with bars either side. Treating
/// the whole window as the remote screen — which is what this did until it took the frame size —
/// puts every click somewhere other than where the user aimed, by an offset that grows with the bar
/// width and a scale error that grows with the aspect mismatch. Hovering a button lands next to it,
/// and the session is unusable for anything but watching.
///
/// The geometry mirrors `minifb`'s `AspectRatioStretch`: fit to the tighter axis, centre the result.
///
/// Returns `None` before the first frame, when there is no picture and therefore nothing to point
/// at. Normalised to `u16` rather than sent as pixels so the host's resolution stays the host's
/// business (`docs/PROTOCOL.md` §7.1), and clamped rather than rejected — a position slightly
/// outside is a rounding artefact, and dropping it makes the cursor stutter at screen edges.
#[must_use]
pub fn map_to_remote(
    mx: f32,
    my: f32,
    window_w: usize,
    window_h: usize,
    frame_w: usize,
    frame_h: usize,
) -> Option<(u16, u16)> {
    if frame_w == 0 || frame_h == 0 || window_w == 0 || window_h == 0 {
        return None;
    }
    let (ww, wh) = (window_w as f32, window_h as f32);
    let frame_aspect = frame_w as f32 / frame_h as f32;
    let window_aspect = ww / wh;

    // The picture fills whichever axis runs out first; the other gets the bars.
    let (content_w, content_h) = if frame_aspect > window_aspect {
        (ww, ww / frame_aspect)
    } else {
        (wh * frame_aspect, wh)
    };
    let x_offset = (ww - content_w) / 2.0;
    let y_offset = (wh - content_h) / 2.0;

    let fx = ((mx - x_offset) / content_w).clamp(0.0, 1.0);
    let fy = ((my - y_offset) / content_h).clamp(0.0, 1.0);
    Some((
        (fx * f32::from(u16::MAX)).round() as u16,
        (fy * f32::from(u16::MAX)).round() as u16,
    ))
}

/// Runs the window until it closes, draining frames and emitting input.
///
/// Returns when the user closes the window or presses the escape hatch, having sent
/// [`InputEvent::Quit`].
pub fn run(
    title: &str,
    width: usize,
    height: usize,
    frames: std::sync::Arc<LatestFrame>,
    input: mpsc::Sender<InputEvent>,
    session_over: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), minifb::Error> {
    let mut window = minifb::Window::new(
        title,
        width,
        height,
        minifb::WindowOptions {
            resize: true,
            scale_mode: minifb::ScaleMode::AspectRatioStretch,
            ..minifb::WindowOptions::default()
        },
    )?;
    // 60 Hz. The stream may be slower and the redraw loop must not spin regardless.
    window.set_target_fps(60);

    let tracked = tracked_keys();
    let mut key_down = vec![false; tracked.len()];
    let mut buttons_down = [false; 3];
    let mut last_pointer: Option<(u16, u16)> = None;
    let mut canvas = vec![0u32; width * height];
    let (mut canvas_w, mut canvas_h) = (width, height);
    let mut have_frame = false;

    // Three ways out, and all three have to work: the user closes the window, the user presses
    // Escape, or the far end goes away. Without the third the window outlives its session and shows
    // a frozen screen with no explanation, which is worse than closing.
    while window.is_open()
        && !window.is_key_down(minifb::Key::Escape)
        && !session_over.load(std::sync::atomic::Ordering::Relaxed)
    {
        if let Some(frame) = frames.take() {
            canvas = frame.pixels;
            canvas_w = frame.width;
            canvas_h = frame.height;
            have_frame = true;
        }

        let modifiers = modifiers_from(&window);

        // Pointer. Only movement is sent: at 60 Hz an unconditional send would put 60 identical
        // positions a second on the wire for a hand that is not moving.
        if let Some((mx, my)) = window.get_mouse_pos(minifb::MouseMode::Clamp) {
            let (w, h) = window.get_size();
            // Mapped against the picture, not the window: the bars are not part of the remote
            // screen, and counting them displaces every pointer event.
            if let Some(position) = map_to_remote(mx, my, w, h, canvas_w, canvas_h) {
                if last_pointer != Some(position) {
                    last_pointer = Some(position);
                    let _ = input.send(InputEvent::Move {
                        x_norm: position.0,
                        y_norm: position.1,
                        modifiers,
                    });
                }
            }
        }

        for (index, (button, id)) in [
            (minifb::MouseButton::Left, MouseButtonId::Left),
            (minifb::MouseButton::Middle, MouseButtonId::Middle),
            (minifb::MouseButton::Right, MouseButtonId::Right),
        ]
        .into_iter()
        .enumerate()
        {
            let down = window.get_mouse_down(button);
            if down != buttons_down[index] {
                buttons_down[index] = down;
                let (x_norm, y_norm) = last_pointer.unwrap_or((0, 0));
                let _ = input.send(InputEvent::Button {
                    button: id,
                    down,
                    x_norm,
                    y_norm,
                    modifiers,
                });
            }
        }

        if let Some((sx, sy)) = window.get_scroll_wheel() {
            if sx != 0.0 || sy != 0.0 {
                // One detent is 120 on the wire, matching Windows' WHEEL_DELTA (§7.4).
                let _ = input.send(InputEvent::Scroll {
                    vertical: (sy * 120.0).clamp(f32::from(i16::MIN), f32::from(i16::MAX)) as i16,
                    horizontal: (sx * 120.0).clamp(f32::from(i16::MIN), f32::from(i16::MAX)) as i16,
                    modifiers,
                });
            }
        }

        // Keys, as transitions derived from held state.
        for (index, key) in tracked.iter().enumerate() {
            let down = window.is_key_down(*key);
            if down != key_down[index] {
                key_down[index] = down;
                if let Some(usage) = hid_usage_for(*key) {
                    let _ = input.send(InputEvent::Key {
                        usage,
                        down,
                        modifiers,
                    });
                }
            }
        }

        if have_frame {
            let _ = window.update_with_buffer(&canvas, canvas_w, canvas_h);
        } else {
            window.update();
        }
    }

    // Whatever is still held is released by the host's reconciliation when the session ends, but
    // saying so explicitly means a clean exit does not depend on that safety net firing.
    for (index, key) in tracked.iter().enumerate() {
        if key_down[index] {
            if let Some(usage) = hid_usage_for(*key) {
                let _ = input.send(InputEvent::Key {
                    usage,
                    down: false,
                    modifiers: Modifiers::NONE,
                });
            }
        }
    }
    let _ = input.send(InputEvent::Quit);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_matching_the_remote_aspect_has_no_bars() {
        // 800x600 window, 800x600 remote: corners map to corners, centre to centre.
        assert_eq!(map_to_remote(0.0, 0.0, 800, 600, 800, 600), Some((0, 0)));
        assert_eq!(
            map_to_remote(800.0, 600.0, 800, 600, 800, 600),
            Some((u16::MAX, u16::MAX))
        );
        let (x, y) = map_to_remote(400.0, 300.0, 800, 600, 800, 600).unwrap();
        assert!((i32::from(x) - 32767).abs() <= 1);
        assert!((i32::from(y) - 32767).abs() <= 1);
    }

    #[test]
    fn pillarboxing_does_not_displace_the_pointer() {
        // The reported bug. A 3:2 remote screen in a 16:9 window leaves vertical bars; mapping
        // against the window put every click left of where the user aimed.
        let (ww, wh) = (1920usize, 1080usize);
        let (fw, fh) = (2940usize, 1912usize); // ~1.537, narrower than 1.778
        let content_w = wh as f32 * (fw as f32 / fh as f32);
        let x_offset = (ww as f32 - content_w) / 2.0;

        // The left edge of the *picture* is the left edge of the remote screen.
        assert_eq!(map_to_remote(x_offset, 0.0, ww, wh, fw, fh), Some((0, 0)));
        // The right edge of the picture is the right edge of the remote screen.
        let (x, _) = map_to_remote(x_offset + content_w, 0.0, ww, wh, fw, fh).unwrap();
        assert_eq!(x, u16::MAX);
        // And the centre of the picture is the centre of the screen — not the centre of the window.
        let (cx, _) = map_to_remote(x_offset + content_w / 2.0, 540.0, ww, wh, fw, fh).unwrap();
        assert!(
            (i32::from(cx) - 32767).abs() <= 2,
            "the picture centre must map to the screen centre, got {cx}"
        );
    }

    #[test]
    fn letterboxing_does_not_displace_the_pointer() {
        // The other orientation: a wide remote screen in a tall window leaves horizontal bars.
        let (ww, wh) = (1000usize, 1000usize);
        let (fw, fh) = (2000usize, 1000usize);
        let content_h = ww as f32 / (fw as f32 / fh as f32);
        let y_offset = (wh as f32 - content_h) / 2.0;

        assert_eq!(map_to_remote(0.0, y_offset, ww, wh, fw, fh), Some((0, 0)));
        let (_, y) = map_to_remote(0.0, y_offset + content_h, ww, wh, fw, fh).unwrap();
        assert_eq!(y, u16::MAX);
        let (_, cy) = map_to_remote(500.0, y_offset + content_h / 2.0, ww, wh, fw, fh).unwrap();
        assert!((i32::from(cy) - 32767).abs() <= 2, "got {cy}");
    }

    #[test]
    fn the_bars_clamp_to_the_screen_edge_rather_than_wrapping() {
        // A pointer parked in a bar is outside the remote screen. Clamping pins it to the edge;
        // wrapping would teleport the remote cursor to the opposite side.
        let (ww, wh) = (1920usize, 1080usize);
        let (fw, fh) = (2940usize, 1912usize);
        assert_eq!(map_to_remote(0.0, 540.0, ww, wh, fw, fh).unwrap().0, 0);
        assert_eq!(
            map_to_remote(1920.0, 540.0, ww, wh, fw, fh).unwrap().0,
            u16::MAX
        );
    }

    #[test]
    fn there_is_nothing_to_point_at_before_the_first_frame() {
        assert_eq!(map_to_remote(10.0, 10.0, 800, 600, 0, 0), None);
        assert_eq!(map_to_remote(10.0, 10.0, 0, 0, 800, 600), None);
    }

    #[test]
    fn letters_and_digits_map_to_their_hid_usages() {
        // Spot-check against the published HID table rather than against our own constants.
        assert_eq!(hid_usage_for(minifb::Key::A), Some(0x04));
        assert_eq!(hid_usage_for(minifb::Key::Z), Some(0x1D));
        assert_eq!(hid_usage_for(minifb::Key::Key1), Some(0x1E));
        assert_eq!(hid_usage_for(minifb::Key::Enter), Some(0x28));
        assert_eq!(hid_usage_for(minifb::Key::Space), Some(0x2C));
    }

    #[test]
    fn every_tracked_key_actually_maps() {
        // A key in the tracked list with no usage is a key the user presses and nothing happens.
        for key in tracked_keys() {
            assert!(
                hid_usage_for(key).is_some(),
                "{key:?} is tracked but has no HID usage"
            );
        }
    }

    #[test]
    fn modifiers_are_distinct_per_side() {
        // Left and right modifiers are separate usages; collapsing them breaks any host shortcut
        // that distinguishes them.
        assert_ne!(
            hid_usage_for(minifb::Key::LeftShift),
            hid_usage_for(minifb::Key::RightShift)
        );
        assert_ne!(
            hid_usage_for(minifb::Key::LeftCtrl),
            hid_usage_for(minifb::Key::RightCtrl)
        );
    }

    #[test]
    fn the_frame_slot_keeps_only_the_newest() {
        let slot = LatestFrame::default();
        slot.put(Framebuffer {
            pixels: vec![1],
            width: 1,
            height: 1,
        });
        slot.put(Framebuffer {
            pixels: vec![2],
            width: 1,
            height: 1,
        });
        assert_eq!(slot.take().unwrap().pixels, vec![2]);
        assert!(slot.take().is_none());
    }

    #[test]
    fn bgra_becomes_0rgb_and_row_padding_is_dropped() {
        // A padded stride is the normal case out of VideoToolbox, and ignoring it shears the image.
        let frame = rda_decode::decoder::DecodedFrame {
            data: vec![
                0x11, 0x22, 0x33, 0xFF, 0x44, 0x55, 0x66, 0xFF, 0xDE, 0xAD, // row 0 + padding
                0x77, 0x88, 0x99, 0xFF, 0xAA, 0xBB, 0xCC, 0xFF, 0xBE, 0xEF, // row 1 + padding
            ],
            width: 2,
            height: 2,
            stride: 10,
            pts_us: 0,
            sequence: 0,
        };
        let fb = Framebuffer::from_decoded(&frame);
        assert_eq!(fb.width, 2);
        assert_eq!(fb.height, 2);
        assert_eq!(
            fb.pixels,
            vec![0x0033_2211, 0x0066_5544, 0x0099_8877, 0x00CC_BBAA]
        );
    }
}
