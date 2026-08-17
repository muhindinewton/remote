//! Decoder backends.

use crate::decoder::{DecodeError, VideoDecoder};

#[cfg(target_os = "macos")]
pub mod videotoolbox;

/// Builds the best available hardware decoder for this platform.
pub fn hardware_decoder() -> Result<Box<dyn VideoDecoder>, DecodeError> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(videotoolbox::VideoToolboxDecoder::new()))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(DecodeError::Unsupported)
    }
}
