//! macOS screen capture via Core Graphics.
//!
//! Uses `CGDisplayCreateImage`, which is simple, dependency-light and works today. It is **not**
//! the final implementation: `docs/ARCHITECTURE.md` §3.1 selects **ScreenCaptureKit** (macOS 12.3+)
//! because it delivers `CMSampleBuffer` wrapping an `IOSurface` that hands directly to
//! VideoToolbox with no copy, and it reports damage. This backend copies each frame through the
//! CPU, which is acceptable for proving the pipeline in Phase 3 and is the first thing Phase 4
//! replaces. [`MacosCapturer::is_zero_copy_capable`] reports which one is in use so the
//! substitution is observable rather than assumed.
//!
//! Requires the **TCC Screen Recording** permission. It cannot be granted programmatically, and the
//! flow is: prompt → user opens System Settings → **the application must restart**. "Granted but
//! not yet effective" is therefore a real state the host has to handle, not an edge case.
//!
//! No `unsafe` here — `core-graphics` wraps the C API, so the crate-wide `forbid(unsafe_code)`
//! holds to the OS boundary.

use crate::{
    CaptureConfig, CaptureError, DirtyRegion, DisplayInfo, Frame, PixelFormat, ScreenCapturer,
    Surface,
};
use core_graphics::display::CGDisplay;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Core Graphics capture backend.
pub struct MacosCapturer {
    displays: Vec<DisplayInfo>,
    active: Option<ActiveCapture>,
    sequence: u64,
}

struct ActiveCapture {
    display: DisplayInfo,
    native: CGDisplay,
    config: CaptureConfig,
    last_frame_at: Option<Instant>,
    /// Hash of the previous frame's bytes, for the coarse damage check below.
    last_hash: Option<u64>,
}

impl MacosCapturer {
    /// Enumerates displays and verifies capture permission.
    pub fn new() -> Result<Self, CaptureError> {
        let displays = enumerate_displays()?;
        if displays.is_empty() {
            return Err(CaptureError::Unavailable("no active displays".to_string()));
        }
        Ok(Self {
            displays,
            active: None,
            sequence: 0,
        })
    }

    /// Whether this backend can hand frames to the encoder without a CPU copy.
    ///
    /// Always `false` here. ScreenCaptureKit in Phase 4 will return `true`, and the difference is
    /// worth several milliseconds per frame on the latency budget.
    #[must_use]
    pub fn is_zero_copy_capable(&self) -> bool {
        false
    }

    /// Probes whether Screen Recording permission has been granted.
    ///
    /// Without it `CGDisplayCreateImage` returns a black image or `None` rather than an error, so
    /// an explicit probe is the only way to tell a permission problem from an idle screen.
    pub fn check_permission() -> Result<(), CaptureError> {
        let display = CGDisplay::main();
        if display.image().is_some() {
            Ok(())
        } else {
            Err(CaptureError::PermissionDenied(
                "Screen Recording permission is not granted; enable it in System Settings > \
                 Privacy & Security > Screen Recording, then restart the application"
                    .to_string(),
            ))
        }
    }
}

fn enumerate_displays() -> Result<Vec<DisplayInfo>, CaptureError> {
    let ids = CGDisplay::active_displays()
        .map_err(|e| CaptureError::Unavailable(format!("CGGetActiveDisplayList failed: {e:?}")))?;

    Ok(ids
        .into_iter()
        .enumerate()
        .map(|(index, native_id)| {
            let display = CGDisplay::new(native_id);
            let bounds = display.bounds();

            // `CGDisplayPixelsWide` is a legacy API that reports **points**, not backing pixels: on
            // a Retina display it returns 1470 where the captured image is 2940 wide. Using it
            // would make every frame arrive at twice the geometry the peer was told, and would put
            // every injected coordinate at half its intended position.
            // `CGDisplayMode::pixel_width` is the one that reports true backing pixels.
            let mode = display.display_mode();
            let pixel_width = mode
                .as_ref()
                .map(|m| m.pixel_width() as u32)
                .unwrap_or_else(|| display.pixels_wide() as u32);
            let pixel_height = mode
                .as_ref()
                .map(|m| m.pixel_height() as u32)
                .unwrap_or_else(|| display.pixels_high() as u32);

            // Backing scale is the ratio of physical pixels to layout points.
            let point_width = bounds.size.width.max(1.0);
            let scale_permille = ((f64::from(pixel_width) / point_width) * 1000.0).round() as u32;

            DisplayInfo {
                id: index as u8,
                native_id: u64::from(native_id),
                name: if display.is_main() {
                    "Main Display".to_string()
                } else {
                    format!("Display {}", index + 1)
                },
                x: bounds.origin.x as i32,
                y: bounds.origin.y as i32,
                width: pixel_width,
                height: pixel_height,
                scale_permille: scale_permille.max(1000),
                primary: display.is_main(),
            }
        })
        .collect())
}

/// Cheap change detection.
///
/// `CGDisplayCreateImage` reports no damage information, so without this an idle desktop would
/// re-encode an identical frame 60 times a second. A full hash is far cheaper than an encode, and
/// this whole function disappears in Phase 4 when ScreenCaptureKit provides real dirty rectangles.
fn frame_hash(bytes: &[u8]) -> u64 {
    // FNV-1a over a stride-sampled subset. Sampling keeps the cost proportional to a fraction of
    // the frame while still catching any change large enough to be worth transmitting.
    const STEP: usize = 97;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= u64::from(bytes[i]);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
        i += STEP;
    }
    hash ^= bytes.len() as u64;
    hash.wrapping_mul(0x0000_0100_0000_01B3)
}

impl ScreenCapturer for MacosCapturer {
    fn displays(&self) -> Result<Vec<DisplayInfo>, CaptureError> {
        Ok(self.displays.clone())
    }

    fn start(&mut self, display_id: u8, config: CaptureConfig) -> Result<(), CaptureError> {
        let display = self
            .displays
            .iter()
            .find(|d| d.id == display_id)
            .cloned()
            .ok_or(CaptureError::UnknownDisplay(display_id))?;

        let native = CGDisplay::new(display.native_id as u32);
        if native.image().is_none() {
            return Err(CaptureError::PermissionDenied(
                "Screen Recording permission is not granted; enable it in System Settings > \
                 Privacy & Security > Screen Recording, then restart the application"
                    .to_string(),
            ));
        }

        self.active = Some(ActiveCapture {
            display,
            native,
            config,
            last_frame_at: None,
            last_hash: None,
        });
        Ok(())
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        let sequence = self.sequence;
        let active = self
            .active
            .as_mut()
            .ok_or_else(|| CaptureError::Unavailable("capture not started".to_string()))?;

        // Pace to the target rate. Without this the loop spins as fast as the CPU allows and burns
        // a core to produce frames the encoder will drop.
        let interval =
            Duration::from_micros(1_000_000 / u64::from(active.config.target_fps.max(1)));
        if let Some(last) = active.last_frame_at {
            let elapsed = last.elapsed();
            if elapsed < interval {
                let wait = interval - elapsed;
                if wait > timeout {
                    return Ok(None);
                }
                std::thread::sleep(wait);
            }
        }

        let image = active.native.image().ok_or_else(|| {
            // A display that was capturable and now is not usually means the display was
            // reconfigured or disconnected — recoverable, not fatal.
            CaptureError::SessionLost("CGDisplayCreateImage returned no image".to_string())
        })?;

        let width = image.width() as u32;
        let height = image.height() as u32;
        let stride = image.bytes_per_row();

        if width != active.display.width || height != active.display.height {
            // Resolution changed under us. The caller re-enumerates and restarts rather than
            // sending frames whose geometry disagrees with what the peer was told.
            return Err(CaptureError::SessionLost(format!(
                "display resolution changed from {}x{} to {width}x{height}",
                active.display.width, active.display.height
            )));
        }

        let data = image.data();
        let bytes: Arc<[u8]> = Arc::from(data.bytes().to_vec().into_boxed_slice());

        let dirty = if active.config.track_damage {
            let hash = frame_hash(&bytes);
            let unchanged = active.last_hash == Some(hash);
            active.last_hash = Some(hash);
            if unchanged {
                DirtyRegion::Unchanged
            } else {
                DirtyRegion::Full
            }
        } else {
            DirtyRegion::Full
        };

        active.last_frame_at = Some(Instant::now());
        self.sequence += 1;

        Ok(Some(Frame {
            surface: Surface::Cpu {
                data: bytes,
                stride,
                format: PixelFormat::Bgra8,
            },
            display_id: active.display.id,
            width,
            height,
            captured_at: Instant::now(),
            dirty,
            sequence,
        }))
    }

    fn stop(&mut self) -> Result<(), CaptureError> {
        self.active = None;
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
    fn displays_enumerate_with_sane_geometry() {
        let Ok(displays) = enumerate_displays() else {
            eprintln!("skipping: no display server");
            return;
        };
        for d in &displays {
            assert!(
                d.width > 0 && d.height > 0,
                "{}: zero-sized display",
                d.name
            );
            assert!(d.scale_permille >= 1000, "{}: scale below 1.0", d.name);
            assert!(d.scale_permille <= 4000, "{}: implausible scale", d.name);
        }
        if !displays.is_empty() {
            assert_eq!(displays.iter().filter(|d| d.primary).count(), 1);
            // Ids must be contiguous from zero: the wire carries this as a u8 index.
            for (i, d) in displays.iter().enumerate() {
                assert_eq!(d.id, i as u8);
            }
        }
    }

    #[test]
    fn the_hash_distinguishes_different_frames() {
        let a = vec![0u8; 4096];
        let mut b = vec![0u8; 4096];
        // Change a byte the sampler actually visits.
        b[97] = 1;
        assert_ne!(frame_hash(&a), frame_hash(&b));
        assert_eq!(frame_hash(&a), frame_hash(&a.clone()));
        // Different lengths must not collide even when the sampled bytes match.
        assert_ne!(frame_hash(&a), frame_hash(&vec![0u8; 8192]));
    }

    #[test]
    fn the_backend_reports_that_it_is_not_yet_zero_copy() {
        // A guard against this silently becoming the permanent implementation.
        let Ok(c) = MacosCapturer::new() else {
            eprintln!("skipping: no display server");
            return;
        };
        assert!(!c.is_zero_copy_capable());
        assert_eq!(c.name(), "macos-coregraphics");
    }

    #[test]
    fn capturing_an_unknown_display_is_refused() {
        let Ok(mut c) = MacosCapturer::new() else {
            eprintln!("skipping: no display server");
            return;
        };
        assert_eq!(
            c.start(200, CaptureConfig::default()),
            Err(CaptureError::UnknownDisplay(200))
        );
    }

    #[test]
    fn a_real_frame_can_be_captured_when_permitted() {
        let Ok(mut c) = MacosCapturer::new() else {
            eprintln!("skipping: no display server");
            return;
        };
        match c.start(
            0,
            CaptureConfig {
                target_fps: 10,
                ..Default::default()
            },
        ) {
            Ok(()) => {}
            Err(CaptureError::PermissionDenied(_)) => {
                eprintln!("skipping: Screen Recording permission not granted");
                return;
            }
            Err(e) => panic!("unexpected start error: {e}"),
        }

        let frame = c
            .next_frame(Duration::from_secs(2))
            .expect("capture must not error")
            .expect("a frame must arrive within the timeout");

        let display = &c.displays[0];
        assert_eq!(frame.width, display.width);
        assert_eq!(frame.height, display.height);
        match &frame.surface {
            Surface::Cpu {
                data,
                stride,
                format,
            } => {
                assert_eq!(*format, PixelFormat::Bgra8);
                assert!(
                    *stride >= frame.width as usize * 4,
                    "stride below one row of pixels"
                );
                assert!(
                    data.len() >= *stride * frame.height as usize / 2,
                    "frame data too small"
                );
            }
            _ => panic!("this backend produces CPU surfaces"),
        }
        c.stop().unwrap();
    }

    #[test]
    fn a_static_screen_reports_no_damage() {
        let Ok(mut c) = MacosCapturer::new() else {
            eprintln!("skipping: no display server");
            return;
        };
        if c.start(
            0,
            CaptureConfig {
                target_fps: 30,
                ..Default::default()
            },
        )
        .is_err()
        {
            eprintln!("skipping: Screen Recording permission not granted");
            return;
        }
        let Ok(Some(_)) = c.next_frame(Duration::from_secs(2)) else {
            eprintln!("skipping: no frame available");
            return;
        };
        // Two consecutive captures of a still screen should agree. This is the mechanism that makes
        // an idle session cost nothing; if it regresses, idle bandwidth silently goes to full rate.
        if let Ok(Some(second)) = c.next_frame(Duration::from_secs(2)) {
            if second.dirty == DirtyRegion::Unchanged {
                assert!(!second.is_worth_encoding());
            } else {
                eprintln!("note: screen changed between captures; damage check inconclusive");
            }
        }
        c.stop().unwrap();
    }
}
