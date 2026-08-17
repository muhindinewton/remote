//! Screen capture — `docs/ARCHITECTURE.md` §3.
//!
//! Two structural decisions dominate this crate:
//!
//! **Frames are expressed so a GPU handle and a CPU buffer are both representable.** [`Surface`]
//! exists so the zero-copy path (D3D11 texture → NVENC, `IOSurface` → VideoToolbox, DMA-BUF →
//! VAAPI) is describable in the type system rather than bolted on in Phase 4. A design that assumed
//! CPU buffers would have to be rewritten to get zero-copy back.
//!
//! **Capture runs on a dedicated OS thread, never a tokio worker.** The platform APIs block, some
//! require thread affinity or a specific desktop, and blocking a runtime worker starves unrelated
//! tasks. Frames cross into async through [`FrameSink`], which is latest-frame-wins: if the encoder
//! is behind, the older frame is dropped. Queueing stale frames would be worse than useless —
//! delivering one late costs bandwidth *and* delays the frame the user actually wants.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod backend;
pub mod sink;

pub use sink::{FrameSink, FrameSource};

use std::time::Instant;

/// A display available for capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayInfo {
    /// Stable identifier carried on the wire.
    pub id: u8,
    /// Platform display handle.
    pub native_id: u64,
    /// Human-readable name.
    pub name: String,
    /// Left edge in the virtual desktop, in physical pixels.
    pub x: i32,
    /// Top edge in the virtual desktop, in physical pixels.
    pub y: i32,
    /// Width in physical pixels.
    pub width: u32,
    /// Height in physical pixels.
    pub height: u32,
    /// Backing scale factor: 2.0 on a Retina display.
    ///
    /// Stored as a permille integer so `DisplayInfo` stays `Eq` and comparable.
    pub scale_permille: u32,
    /// Whether this is the primary display.
    pub primary: bool,
}

impl DisplayInfo {
    /// The backing scale as a float.
    #[must_use]
    pub fn scale(&self) -> f64 {
        f64::from(self.scale_permille) / 1000.0
    }

    /// Logical (point) dimensions, as distinct from physical pixels.
    #[must_use]
    pub fn logical_size(&self) -> (u32, u32) {
        let s = self.scale().max(0.01);
        (
            (f64::from(self.width) / s).round() as u32,
            (f64::from(self.height) / s).round() as u32,
        )
    }

    /// The geometry the input layer needs to denormalise coordinates: `(id, x, y, width, height)`
    /// with the size in **layout points**, matching the origin.
    ///
    /// `width` and `height` on this struct are the backing store in physical pixels, because that
    /// is what capture and the encoder work in. Input is the other way round — macOS posts events
    /// in points — and handing the raw fields to the input layer is a 2x error on any Retina
    /// display, which presents as a pointer that tracks at double speed and sticks at the edge.
    #[must_use]
    pub fn geometry(&self) -> (u8, i32, i32, u32, u32) {
        let (w, h) = self.logical_size();
        (self.id, self.x, self.y, w, h)
    }
}

/// A rectangle in physical pixels, relative to the captured display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    /// Left edge.
    pub x: u32,
    /// Top edge.
    pub y: u32,
    /// Width.
    pub width: u32,
    /// Height.
    pub height: u32,
}

impl Rect {
    /// Area in pixels.
    #[must_use]
    pub fn area(&self) -> u64 {
        u64::from(self.width) * u64::from(self.height)
    }

    /// Whether this rectangle covers nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }
}

/// What changed since the previous frame.
///
/// Damage tracking is what lets an idle desktop cost nothing. On a 220 ms link that matters more
/// than it looks: an idle session leaves the whole pipe free for the burst when the user *does*
/// act, and stops the bandwidth estimate decaying through inactivity
/// (`docs/ARCHITECTURE.md` §3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirtyRegion {
    /// Everything changed — first frame, resolution change, or the backend cannot tell.
    Full,
    /// Only these rectangles changed.
    Rects(Vec<Rect>),
    /// Nothing changed. Skip conversion, encoding and transmission entirely.
    Unchanged,
}

impl DirtyRegion {
    /// Whether anything needs encoding.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        match self {
            DirtyRegion::Full => true,
            DirtyRegion::Rects(r) => r.iter().any(|r| !r.is_empty()),
            DirtyRegion::Unchanged => false,
        }
    }

    /// Total changed area in pixels, saturating for [`DirtyRegion::Full`].
    ///
    /// Overlapping rectangles are counted twice; this is a cheap heuristic for "is a full-frame
    /// encode cheaper than a partial one", not a precise measure.
    #[must_use]
    pub fn changed_pixels(&self, display: &DisplayInfo) -> u64 {
        match self {
            DirtyRegion::Full => u64::from(display.width) * u64::from(display.height),
            DirtyRegion::Rects(rects) => rects.iter().map(Rect::area).sum(),
            DirtyRegion::Unchanged => 0,
        }
    }

    /// Whether the changed area is large enough that a full-frame encode is simpler and no more
    /// expensive than tracking rectangles.
    #[must_use]
    pub fn should_promote_to_full(&self, display: &DisplayInfo) -> bool {
        let total = u64::from(display.width) * u64::from(display.height);
        total > 0 && self.changed_pixels(display) * 100 / total > 60
    }
}

/// Pixel layout of a CPU buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum PixelFormat {
    /// 8 bits per channel, blue first. What every desktop compositor hands us.
    Bgra8,
    /// 8 bits per channel, red first.
    Rgba8,
    /// Planar 4:2:0, what encoders want.
    Nv12,
}

impl PixelFormat {
    /// Bytes per pixel for packed formats; `None` for planar ones.
    #[must_use]
    pub fn bytes_per_pixel(self) -> Option<usize> {
        match self {
            PixelFormat::Bgra8 | PixelFormat::Rgba8 => Some(4),
            PixelFormat::Nv12 => None,
        }
    }
}

/// Where a frame's pixels actually live.
///
/// The enum exists so the zero-copy path is expressible. A frame that never touches the CPU is the
/// difference between a few milliseconds and a few tens of milliseconds per frame at 1080p, which
/// on the latency budget in `docs/ARCHITECTURE.md` §2.1 is worth more than any compression gain.
#[derive(Debug, Clone)]
pub enum Surface {
    /// A CPU-visible buffer.
    Cpu {
        /// Pixel data, shared so a frame can be handed on without copying.
        data: std::sync::Arc<[u8]>,
        /// Bytes per row, which is often larger than `width * bpp` because of alignment.
        stride: usize,
        /// Pixel layout.
        format: PixelFormat,
    },
    /// A macOS `IOSurface`, handed straight to VideoToolbox.
    ///
    /// Carried as an opaque handle; Phase 4 attaches the real type.
    #[cfg(target_os = "macos")]
    IoSurface {
        /// Opaque surface identifier.
        id: u32,
    },
}

impl Surface {
    /// Whether this surface can reach the encoder without a CPU copy.
    #[must_use]
    pub fn is_zero_copy(&self) -> bool {
        match self {
            Surface::Cpu { .. } => false,
            #[cfg(target_os = "macos")]
            Surface::IoSurface { .. } => true,
        }
    }
}

/// One captured frame.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Where the pixels are.
    pub surface: Surface,
    /// Display this came from.
    pub display_id: u8,
    /// Width in physical pixels.
    pub width: u32,
    /// Height in physical pixels.
    pub height: u32,
    /// When capture completed. Used to measure the capture-to-encode leg of the latency budget.
    pub captured_at: Instant,
    /// What changed since the previous frame.
    pub dirty: DirtyRegion,
    /// Monotonic counter, so dropped frames are countable rather than merely suspected.
    pub sequence: u64,
}

impl Frame {
    /// Age of this frame in milliseconds.
    ///
    /// The sink uses this to decide whether a frame is worth encoding at all: past a threshold it
    /// is cheaper to skip it and capture a fresh one.
    #[must_use]
    pub fn age_ms(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.captured_at).as_millis() as u64
    }

    /// Whether this frame carries anything worth encoding.
    #[must_use]
    pub fn is_worth_encoding(&self) -> bool {
        self.dirty.has_changes()
    }
}

/// Capture configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureConfig {
    /// Frames per second to aim for.
    pub target_fps: u32,
    /// Whether to compute dirty rectangles.
    pub track_damage: bool,
    /// Whether to composite the cursor into the frame.
    ///
    /// Default `false`: the cursor travels as metadata and is rendered client-side, which makes it
    /// track the pointer instantly instead of at video latency (`docs/ARCHITECTURE.md` §3.6).
    pub include_cursor: bool,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            target_fps: 60,
            track_damage: true,
            include_cursor: false,
        }
    }
}

/// Why capture failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaptureError {
    /// The OS refused, almost always a missing permission.
    ///
    /// On macOS this is TCC Screen Recording, which cannot be granted programmatically and
    /// **requires an application restart** after the user grants it. The host must treat
    /// "granted but not yet effective" as a first-class state rather than a transient error.
    #[error("screen capture permission denied: {0}")]
    PermissionDenied(String),
    /// No such display.
    #[error("display {0} is not available")]
    UnknownDisplay(u8),
    /// The capture session must be rebuilt.
    ///
    /// Routine, not exceptional: resolution changes, display reconfiguration, GPU switches on
    /// hybrid-graphics laptops and desktop switches all produce this. Treating it as fatal would
    /// end sessions on events users consider normal.
    #[error("capture session was lost and must be recreated: {0}")]
    SessionLost(String),
    /// No frame within the timeout. Usually means nothing on screen changed.
    #[error("capture timed out")]
    Timeout,
    /// Backend could not start.
    #[error("capture backend unavailable: {0}")]
    Unavailable(String),
    /// This platform has no implementation.
    #[error("screen capture is not implemented on this platform")]
    Unsupported,
}

impl CaptureError {
    /// Whether the caller should rebuild the session and continue rather than end the session.
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        matches!(self, CaptureError::SessionLost(_) | CaptureError::Timeout)
    }
}

/// The platform capture interface.
///
/// Implementations block. They run on a dedicated OS thread, never a tokio worker.
pub trait ScreenCapturer: Send {
    /// Enumerates available displays.
    fn displays(&self) -> Result<Vec<DisplayInfo>, CaptureError>;

    /// Begins capturing a display.
    fn start(&mut self, display_id: u8, config: CaptureConfig) -> Result<(), CaptureError>;

    /// Blocks until the next frame, or `timeout` elapses.
    ///
    /// Returns `Ok(None)` when nothing changed within the timeout, which is the common case on an
    /// idle desktop and must not be treated as an error.
    fn next_frame(&mut self, timeout: std::time::Duration) -> Result<Option<Frame>, CaptureError>;

    /// Stops capturing and releases resources.
    fn stop(&mut self) -> Result<(), CaptureError>;

    /// Backend name, for diagnostics.
    fn name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn display() -> DisplayInfo {
        DisplayInfo {
            id: 0,
            native_id: 1,
            name: "Test".into(),
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
            scale_permille: 2000,
            primary: true,
        }
    }

    #[test]
    fn retina_scaling_converts_between_points_and_pixels() {
        let d = display();
        assert_eq!(d.scale(), 2.0);
        assert_eq!(d.logical_size(), (960, 540));
    }

    #[test]
    fn a_zero_scale_cannot_divide_by_zero() {
        let d = DisplayInfo {
            scale_permille: 0,
            ..display()
        };
        let (w, h) = d.logical_size();
        assert!(
            w > 0 && h > 0,
            "a malformed scale must not produce a division blowup"
        );
    }

    #[test]
    fn unchanged_regions_skip_the_whole_pipeline() {
        assert!(!DirtyRegion::Unchanged.has_changes());
        assert!(DirtyRegion::Full.has_changes());
        assert!(!DirtyRegion::Rects(vec![]).has_changes());
        // A zero-area rectangle is not a change.
        assert!(!DirtyRegion::Rects(vec![Rect {
            x: 0,
            y: 0,
            width: 0,
            height: 10
        }])
        .has_changes());
    }

    #[test]
    fn changed_pixels_are_measured_for_the_encode_decision() {
        let d = display();
        assert_eq!(DirtyRegion::Unchanged.changed_pixels(&d), 0);
        assert_eq!(DirtyRegion::Full.changed_pixels(&d), 1920 * 1080);
        let rects = DirtyRegion::Rects(vec![Rect {
            x: 0,
            y: 0,
            width: 100,
            height: 100,
        }]);
        assert_eq!(rects.changed_pixels(&d), 10_000);
    }

    #[test]
    fn mostly_changed_frames_promote_to_a_full_encode() {
        let d = display();
        let small = DirtyRegion::Rects(vec![Rect {
            x: 0,
            y: 0,
            width: 100,
            height: 100,
        }]);
        assert!(!small.should_promote_to_full(&d));

        let large = DirtyRegion::Rects(vec![Rect {
            x: 0,
            y: 0,
            width: 1920,
            height: 800,
        }]);
        assert!(
            large.should_promote_to_full(&d),
            "tracking rects past ~60% is not worth it"
        );
    }

    #[test]
    fn recoverable_errors_are_distinguished_from_fatal_ones() {
        // Getting this wrong ends sessions on a monitor being plugged in.
        assert!(CaptureError::SessionLost("resolution changed".into()).is_recoverable());
        assert!(CaptureError::Timeout.is_recoverable());
        assert!(!CaptureError::PermissionDenied("tcc".into()).is_recoverable());
        assert!(!CaptureError::Unsupported.is_recoverable());
    }

    #[test]
    fn a_cpu_surface_is_not_zero_copy() {
        let s = Surface::Cpu {
            data: std::sync::Arc::from(vec![0u8; 16].into_boxed_slice()),
            stride: 16,
            format: PixelFormat::Bgra8,
        };
        assert!(!s.is_zero_copy());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_iosurface_is_zero_copy() {
        assert!(Surface::IoSurface { id: 1 }.is_zero_copy());
    }

    #[test]
    fn frames_report_their_age_and_worth() {
        let frame = Frame {
            surface: Surface::Cpu {
                data: std::sync::Arc::from(vec![0u8; 4].into_boxed_slice()),
                stride: 4,
                format: PixelFormat::Bgra8,
            },
            display_id: 0,
            width: 1,
            height: 1,
            captured_at: Instant::now(),
            dirty: DirtyRegion::Unchanged,
            sequence: 1,
        };
        assert!(frame.age_ms(Instant::now()) < 100);
        assert!(
            !frame.is_worth_encoding(),
            "an unchanged frame must not be encoded"
        );
    }

    #[test]
    fn the_default_config_keeps_the_cursor_out_of_the_video() {
        // Compositing the cursor would make every pointer movement feel a full round trip late.
        assert!(!CaptureConfig::default().include_cursor);
        assert!(CaptureConfig::default().track_damage);
    }

    #[test]
    fn geometry_reports_points_while_the_fields_report_pixels() {
        // The bug this pins, using a real Retina panel: 2940x1912 backing store at 2x is 1470x956
        // points. Handing the pixel figures to the input layer doubles every coordinate, so the
        // centre of the controller's view lands at the right-hand edge of the host's screen and
        // the whole right half pins there. It reads as a broken pointer, not a unit mismatch.
        let d = DisplayInfo {
            id: 0,
            native_id: 1,
            name: "Retina".into(),
            x: 0,
            y: 0,
            width: 2940,
            height: 1912,
            scale_permille: 2000,
            primary: true,
        };

        assert_eq!((d.width, d.height), (2940, 1912), "capture works in pixels");
        assert_eq!(d.logical_size(), (1470, 956), "input works in points");

        let (_, _, _, w, h) = d.geometry();
        assert_eq!(
            (w, h),
            (1470, 956),
            "geometry() feeds the input layer and must be in points"
        );
    }

    #[test]
    fn a_non_retina_display_is_unchanged_by_the_conversion() {
        // The mismatch is invisible at 1x, which is why it survived every test on a scaled panel.
        let d = DisplayInfo {
            id: 0,
            native_id: 1,
            name: "1080p".into(),
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
            scale_permille: 1000,
            primary: true,
        };
        assert_eq!(d.logical_size(), (1920, 1080));
        let (_, _, _, w, h) = d.geometry();
        assert_eq!((w, h), (1920, 1080));
    }
}
