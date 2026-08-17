//! Software H.264 decoding, via openh264.
//!
//! **Why this exists.** Until it did, `rda-client` ran perfectly on Windows and Linux right up to
//! the first frame and then died with `video decoding is not implemented on this platform` — the
//! whole session established, authenticated, and threw away every frame it received. A viewer that
//! only runs on macOS is not a viewer.
//!
//! **Why software rather than Media Foundation or VA-API.** One implementation covers every
//! platform that is not macOS, builds from source with no system dependency to install, and is the
//! same code path on a developer's laptop and in CI. A hardware decoder per platform is the right
//! destination and is strictly more work; this is what makes the product usable today, and
//! [`crate::backend::best_decoder`] already prefers hardware wherever it exists.
//!
//! **What it costs.** Decoding 1080p in software runs roughly 5–15 ms per frame on a modern core
//! versus about 2 ms on a fixed-function block, and it burns CPU that a laptop pays for in battery.
//! That is a real cost and it belongs in the latency budget, but it is bounded and it is a cost
//! only the *viewer* pays — the host still encodes on hardware.

use crate::decoder::{DecodeError, DecodedFrame, VideoDecoder};
use openh264::decoder::Decoder;
use openh264::formats::YUVSource;

/// An H.264 decoder running on the CPU.
pub struct SoftwareDecoder {
    decoder: Decoder,
    /// Reused across frames so a 60 fps stream is not 60 allocations a second.
    scratch: Vec<u8>,
    /// Geometry of the last picture, used to notice a mid-stream resolution change.
    geometry: Option<(u32, u32)>,
    sequence: u64,
}

impl SoftwareDecoder {
    /// Creates a decoder.
    pub fn new() -> Result<Self, DecodeError> {
        let decoder = Decoder::new().map_err(|e| DecodeError::Unavailable(e.to_string()))?;
        Ok(Self {
            decoder,
            scratch: Vec::new(),
            geometry: None,
            sequence: 0,
        })
    }
}

impl VideoDecoder for SoftwareDecoder {
    fn decode(
        &mut self,
        data: &[u8],
        pts_us: u64,
        _is_keyframe: bool,
    ) -> Result<Vec<DecodedFrame>, DecodeError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        // openh264 wants a whole access unit and finds the NAL boundaries itself, which is what the
        // sender already produces: `rda_encode` emits Annex B with the parameter sets prepended to
        // every keyframe, so a receiver joining mid-stream becomes decodable at the first keyframe
        // without a side channel.
        let picture = match self.decoder.decode(data) {
            Ok(Some(picture)) => picture,
            // Not an error. The decoder buffers, and it discards everything until it has seen the
            // parameter sets — which is the normal state of a viewer that just connected.
            Ok(None) => return Ok(Vec::new()),
            Err(e) => {
                // openh264 reports its state as a bitmask in the error text: dsNoParamSets (0x10)
                // means no SPS/PPS has been seen, dsRefLost (0x02) means a reference frame is
                // missing. Both describe a decoder *waiting* for a keyframe rather than a broken
                // one, and both are the normal state of a viewer that joined mid-stream. Calling
                // them failures made the caller log a warning per frame and, worse, hid the one
                // thing that would fix it: asking the sender for a keyframe.
                //
                // Matched on text because the crate surfaces the native code that way; a mismatch
                // costs a needlessly hard error, never a wrong picture.
                let message = e.to_string();
                let waiting = self.geometry.is_none()
                    || message.contains("Native:18")
                    || message.contains("Native:16")
                    || message.contains("Native:2");
                if waiting {
                    return Err(DecodeError::AwaitingParameterSets);
                }
                return Err(DecodeError::Failed(message));
            }
        };

        let (width, height) = picture.dimensions();
        let (width, height) = (width as u32, height as u32);

        // A resolution change means the encoder was rebuilt — the degradation ladder does this — and
        // the caller has to rebuild its own surfaces to match rather than render a torn picture.
        if let Some(previous) = self.geometry {
            if previous != (width, height) {
                self.geometry = Some((width, height));
                return Err(DecodeError::FormatChanged);
            }
        }
        self.geometry = Some((width, height));

        // BGRA to match the VideoToolbox backend, because everything downstream — the PNG writer,
        // the window blit, the FFI surface handed to Flutter — is written against one layout, and
        // two layouts would mean two of each.
        let pixels = (width as usize) * (height as usize);
        self.scratch.resize(pixels * 4, 0);
        picture.write_rgba8(&mut self.scratch);
        for px in self.scratch.chunks_exact_mut(4) {
            px.swap(0, 2);
        }

        self.sequence += 1;
        Ok(vec![DecodedFrame {
            data: std::mem::take(&mut self.scratch),
            width,
            height,
            stride: width as usize * 4,
            pts_us,
            sequence: self.sequence,
        }])
    }

    fn reset(&mut self) {
        // openh264 has no reset entry point, so a fresh decoder is the reset. Failing to replace it
        // leaves the old reference frames in place, and decoding onto stale references is how a
        // recovered stream ends up smeared with the picture it was supposed to have discarded.
        if let Ok(decoder) = Decoder::new() {
            self.decoder = decoder;
        }
        self.geometry = None;
    }

    fn is_hardware(&self) -> bool {
        false
    }

    fn name(&self) -> &'static str {
        "openh264-software"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_frame_is_not_an_error() {
        let mut d = SoftwareDecoder::new().expect("decoder");
        assert!(d.decode(&[], 0, false).unwrap().is_empty());
    }

    #[test]
    fn garbage_before_any_parameter_set_reads_as_waiting() {
        // A viewer that joins mid-stream sees exactly this until the first keyframe, and it must
        // not be fatal — `is_recoverable` is what keeps the session alive.
        let mut d = SoftwareDecoder::new().expect("decoder");
        let result = d.decode(&[0, 0, 0, 1, 0x41, 0x9A, 0x00, 0xFF], 0, false);
        match result {
            Ok(frames) => assert!(frames.is_empty()),
            Err(e) => assert!(
                e.is_recoverable(),
                "a decoder still waiting for an SPS must be recoverable, got {e}"
            ),
        }
    }

    #[test]
    fn the_backend_reports_itself_as_software() {
        let d = SoftwareDecoder::new().expect("decoder");
        assert!(!d.is_hardware());
        assert_eq!(d.name(), "openh264-software");
    }

    #[test]
    fn reset_clears_the_geometry() {
        let mut d = SoftwareDecoder::new().expect("decoder");
        d.geometry = Some((1920, 1080));
        d.reset();
        assert!(d.geometry.is_none());
    }
}
