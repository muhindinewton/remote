//! Encoder backends.
//!
//! | Platform | Backend | Codecs |
//! |---|---|---|
//! | macOS | VideoToolbox (hardware media engine) | H.264, HEVC. **Not AV1** — Apple Silicon has no AV1 encoder |
//! | Windows | NVENC / QuickSync / AMF | Phase 5 |
//! | Linux | VAAPI | Phase 5 |
//!
//! [`recording::RecordingEncoder`] models the shape of a real encoder without touching hardware, so
//! rate control and packetising are testable on any machine and in CI.

use crate::encoder::{EncodeError, EncoderConfig, VideoEncoder};

pub mod recording;

#[cfg(target_os = "macos")]
pub mod videotoolbox;

/// Builds the best available hardware encoder for this platform.
///
/// Returns [`EncodeError::Unsupported`] rather than silently falling back to a software encoder: a
/// remote desktop that quietly burns a CPU core encoding in software is a performance mystery, not
/// a feature.
pub fn hardware_encoder(config: EncoderConfig) -> Result<Box<dyn VideoEncoder>, EncodeError> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(videotoolbox::VideoToolboxEncoder::new(config)?))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = config;
        Err(EncodeError::Unsupported)
    }
}
