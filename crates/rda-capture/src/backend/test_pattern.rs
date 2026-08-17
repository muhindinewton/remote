//! A synthetic capture source.
//!
//! Lets the whole host pipeline — capture thread, sink, encoder, transport — be exercised on a
//! machine with no display server, no capture permission, and in CI. Without it, every test that
//! touches the frame path would be skipped exactly where regressions hide.

use crate::{
    CaptureConfig, CaptureError, DirtyRegion, DisplayInfo, Frame, PixelFormat, Rect,
    ScreenCapturer, Surface,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Generates deterministic frames without touching any OS API.
pub struct TestPatternCapturer {
    display: DisplayInfo,
    started: bool,
    sequence: u64,
    /// Emit `Unchanged` on every frame, to exercise the idle path.
    pub always_static: bool,
    /// Fail the next `next_frame` call with this error, to exercise recovery.
    pub inject_error: Option<CaptureError>,
}

impl TestPatternCapturer {
    /// Builds a capturer for a synthetic display of the given size.
    #[must_use]
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            display: DisplayInfo {
                id: 0,
                native_id: 0,
                name: "Test Pattern".to_string(),
                x: 0,
                y: 0,
                width,
                height,
                scale_permille: 1000,
                primary: true,
            },
            started: false,
            sequence: 0,
            always_static: false,
            inject_error: None,
        }
    }

    /// A 640x360 capturer, small enough to keep tests fast.
    #[must_use]
    pub fn small() -> Self {
        Self::new(640, 360)
    }
}

impl ScreenCapturer for TestPatternCapturer {
    fn displays(&self) -> Result<Vec<DisplayInfo>, CaptureError> {
        Ok(vec![self.display.clone()])
    }

    fn start(&mut self, display_id: u8, _config: CaptureConfig) -> Result<(), CaptureError> {
        if display_id != self.display.id {
            return Err(CaptureError::UnknownDisplay(display_id));
        }
        self.started = true;
        Ok(())
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        if !self.started {
            return Err(CaptureError::Unavailable("capture not started".to_string()));
        }
        if let Some(e) = self.inject_error.take() {
            return Err(e);
        }

        let stride = self.display.width as usize * 4;
        let mut data = vec![0u8; stride * self.display.height as usize];
        // A gradient that shifts with the sequence number, so successive frames genuinely differ.
        let phase = (self.sequence % 256) as u8;
        for (i, chunk) in data.chunks_exact_mut(4).enumerate() {
            chunk[0] = (i % 256) as u8; // B
            chunk[1] = phase; // G
            chunk[2] = ((i / 256) % 256) as u8; // R
            chunk[3] = 0xFF; // A
        }

        let dirty = if self.always_static {
            DirtyRegion::Unchanged
        } else if self.sequence == 0 {
            DirtyRegion::Full
        } else {
            DirtyRegion::Rects(vec![Rect {
                x: 0,
                y: 0,
                width: self.display.width,
                height: 16,
            }])
        };

        let frame = Frame {
            surface: Surface::Cpu {
                data: Arc::from(data.into_boxed_slice()),
                stride,
                format: PixelFormat::Bgra8,
            },
            display_id: self.display.id,
            width: self.display.width,
            height: self.display.height,
            captured_at: Instant::now(),
            dirty,
            sequence: self.sequence,
        };
        self.sequence += 1;
        Ok(Some(frame))
    }

    fn stop(&mut self) -> Result<(), CaptureError> {
        self.started = false;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "test-pattern"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_produced_with_the_declared_geometry() {
        let mut c = TestPatternCapturer::small();
        c.start(0, CaptureConfig::default()).unwrap();
        let frame = c.next_frame(Duration::from_millis(10)).unwrap().unwrap();

        assert_eq!(frame.width, 640);
        assert_eq!(frame.height, 360);
        match &frame.surface {
            Surface::Cpu {
                data,
                stride,
                format,
            } => {
                assert_eq!(*format, PixelFormat::Bgra8);
                assert_eq!(*stride, 640 * 4);
                assert_eq!(data.len(), 640 * 4 * 360);
            }
            _ => panic!("expected a CPU surface"),
        }
    }

    #[test]
    fn capture_must_be_started_first() {
        let mut c = TestPatternCapturer::small();
        assert!(c.next_frame(Duration::from_millis(1)).is_err());
        c.start(0, CaptureConfig::default()).unwrap();
        assert!(c.next_frame(Duration::from_millis(1)).is_ok());
        c.stop().unwrap();
        assert!(c.next_frame(Duration::from_millis(1)).is_err());
    }

    #[test]
    fn the_first_frame_is_full_and_later_ones_are_partial() {
        let mut c = TestPatternCapturer::small();
        c.start(0, CaptureConfig::default()).unwrap();
        assert_eq!(
            c.next_frame(Duration::from_millis(1))
                .unwrap()
                .unwrap()
                .dirty,
            DirtyRegion::Full
        );
        let second = c.next_frame(Duration::from_millis(1)).unwrap().unwrap();
        assert!(matches!(second.dirty, DirtyRegion::Rects(_)));
        assert_eq!(second.sequence, 1);
    }

    #[test]
    fn static_mode_exercises_the_idle_path() {
        let mut c = TestPatternCapturer::small();
        c.always_static = true;
        c.start(0, CaptureConfig::default()).unwrap();
        let frame = c.next_frame(Duration::from_millis(1)).unwrap().unwrap();
        assert!(!frame.is_worth_encoding());
    }

    #[test]
    fn an_injected_error_surfaces_once_and_then_recovers() {
        let mut c = TestPatternCapturer::small();
        c.start(0, CaptureConfig::default()).unwrap();
        c.inject_error = Some(CaptureError::SessionLost("simulated".into()));

        let err = c.next_frame(Duration::from_millis(1)).unwrap_err();
        assert!(err.is_recoverable());
        assert!(
            c.next_frame(Duration::from_millis(1)).is_ok(),
            "recovery must be possible"
        );
    }
}
