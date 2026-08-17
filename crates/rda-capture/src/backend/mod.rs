//! Platform capture backends.
//!
//! | Platform | API | Status |
//! |---|---|---|
//! | macOS | `CGDisplayCreateImage` | Implemented. Phase 4 replaces it with ScreenCaptureKit for the zero-copy `IOSurface` path |
//! | Windows | DXGI Desktop Duplication | Phase 4 |
//! | Linux | PipeWire + `xdg-desktop-portal` | Phase 4 |

use crate::{CaptureError, ScreenCapturer};

#[cfg(target_os = "macos")]
pub mod macos;

pub mod test_pattern;

/// Builds the capture backend for this platform.
///
/// Returns [`CaptureError::Unsupported`] on platforms not yet implemented, rather than a backend
/// that yields black frames. A host that appears to share a screen and does not is worse than one
/// that refuses the session with a clear reason.
pub fn platform_capturer() -> Result<Box<dyn ScreenCapturer>, CaptureError> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(macos::MacosCapturer::new()?))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(CaptureError::Unsupported)
    }
}
