//! Decoder backends.
//!
//! Hardware where the platform has it, software everywhere else. The distinction matters for the
//! latency budget — a fixed-function block decodes 1080p in about 2 ms, the CPU in 5-15 ms — but it
//! must never decide *whether* a viewer works at all, which it did until the software backend
//! existed: off macOS, a session established, authenticated, and then died on its first frame.

use crate::decoder::{DecodeError, VideoDecoder};

#[cfg(target_os = "macos")]
pub mod videotoolbox;

pub mod software;

/// Builds the best decoder this platform offers, preferring hardware.
///
/// Falls back to software rather than failing, and says which it chose through
/// [`VideoDecoder::is_hardware`] so the caller can report it honestly.
pub fn best_decoder() -> Result<Box<dyn VideoDecoder>, DecodeError> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(videotoolbox::VideoToolboxDecoder::new()))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(Box::new(software::SoftwareDecoder::new()?))
    }
}

/// Builds a hardware decoder, or fails if this platform has none.
///
/// Kept separate from [`best_decoder`] so a caller that genuinely needs the hardware path — a
/// benchmark, a diagnostic — can ask for it and be told no, rather than silently measuring the CPU.
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

/// Builds a software decoder on any platform.
pub fn software_decoder() -> Result<Box<dyn VideoDecoder>, DecodeError> {
    Ok(Box::new(software::SoftwareDecoder::new()?))
}
