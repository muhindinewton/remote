//! The decoder interface.
//!
//! Output is **BGRA**, not NV12, because the destination is a GPU texture the UI toolkit will
//! sample. Asking VideoToolbox for BGRA lets the hardware do the colour conversion on the way out,
//! which is both faster and one less place for the range/matrix mismatch that turns a remote
//! desktop washed-out.

/// A decoded frame, ready to upload as a texture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    /// BGRA8 pixels, tightly packed at `stride` bytes per row.
    pub data: Vec<u8>,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bytes per row, which may exceed `width * 4` because the decoder aligns rows.
    pub stride: usize,
    /// Presentation timestamp in microseconds, carried through from the encoder.
    pub pts_us: u64,
    /// Monotonic counter of frames this decoder has produced.
    pub sequence: u64,
}

impl DecodedFrame {
    /// Size of the pixel buffer in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the frame carries no pixels.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Whether the buffer is large enough for the declared geometry.
    ///
    /// Checked before the frame crosses the FFI boundary: a short buffer handed to a texture
    /// upload is an out-of-bounds read in someone else's process.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        self.width > 0
            && self.height > 0
            && self.stride >= self.width as usize * 4
            && self.data.len() >= self.stride * self.height as usize
    }
}

/// Why decoding failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The decoder could not be created.
    #[error("decoder unavailable: {0}")]
    Unavailable(String),
    /// The bitstream did not contain the parameter sets needed to start decoding.
    ///
    /// Expected when a receiver joins mid-stream: nothing is decodable until a keyframe arrives.
    /// The caller asks for one rather than treating this as fatal.
    #[error("no parameter sets yet; waiting for a keyframe")]
    AwaitingParameterSets,
    /// The bitstream was malformed.
    #[error("malformed bitstream: {0}")]
    MalformedBitstream(String),
    /// The platform decoder returned an error.
    #[error("decode failed: {0}")]
    Failed(String),
    /// The stream's geometry changed and the session must be rebuilt.
    #[error("stream format changed; the session must be recreated")]
    FormatChanged,
    /// This platform has no implementation.
    #[error("video decoding is not implemented on this platform")]
    Unsupported,
}

impl DecodeError {
    /// Whether the caller should keep the session and continue.
    ///
    /// Waiting for parameter sets is the normal state of a receiver that just joined; treating it
    /// as fatal would make every session fail to start.
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            DecodeError::AwaitingParameterSets
                | DecodeError::MalformedBitstream(_)
                | DecodeError::FormatChanged
        )
    }

    /// Whether the caller should ask the sender for a keyframe.
    #[must_use]
    pub fn wants_keyframe(&self) -> bool {
        matches!(
            self,
            DecodeError::AwaitingParameterSets
                | DecodeError::MalformedBitstream(_)
                | DecodeError::FormatChanged
        )
    }
}

/// A video decoder.
///
/// Not `Send`: hardware decoder sessions are thread-affine, so the decoder lives on the thread that
/// owns the render loop.
pub trait VideoDecoder {
    /// Decodes one compressed frame.
    ///
    /// Returns zero frames when the decoder is still waiting for parameter sets, or when it has
    /// buffered the input — neither is an error.
    fn decode(
        &mut self,
        data: &[u8],
        pts_us: u64,
        is_keyframe: bool,
    ) -> Result<Vec<DecodedFrame>, DecodeError>;

    /// Drops all decoder state, e.g. after an unrecoverable loss.
    ///
    /// The next input must be a keyframe.
    fn reset(&mut self);

    /// Whether decoding runs on dedicated hardware.
    fn is_hardware(&self) -> bool;

    /// Backend name, for diagnostics.
    fn name(&self) -> &'static str;
}

/// Splits an Annex B bitstream into NAL units, without the start codes.
///
/// Handles both 3-byte and 4-byte start codes because encoders mix them: parameter sets often use
/// the 4-byte form and slices the 3-byte form, and a parser that assumes one silently drops the
/// other.
#[must_use]
pub fn split_annex_b(data: &[u8]) -> Vec<&[u8]> {
    let mut units = Vec::new();
    let mut starts = Vec::new();

    let mut i = 0;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 {
            if data[i + 2] == 1 {
                starts.push((i, 3));
                i += 3;
                continue;
            }
            if i + 4 <= data.len() && data[i + 2] == 0 && data[i + 3] == 1 {
                starts.push((i, 4));
                i += 4;
                continue;
            }
        }
        i += 1;
    }

    for (n, &(offset, code_len)) in starts.iter().enumerate() {
        let body = offset + code_len;
        let end = starts.get(n + 1).map_or(data.len(), |&(next, _)| next);
        if body < end {
            units.push(&data[body..end]);
        }
    }
    units
}

/// The H.264 NAL unit type of a unit body.
#[must_use]
pub fn nal_type(unit: &[u8]) -> Option<u8> {
    unit.first().map(|b| b & 0x1F)
}

/// H.264 NAL type for a sequence parameter set.
pub const NAL_SPS: u8 = 7;
/// H.264 NAL type for a picture parameter set.
pub const NAL_PPS: u8 = 8;
/// H.264 NAL type for an IDR slice.
pub const NAL_IDR: u8 = 5;

/// Whether a bitstream carries both parameter sets, and is therefore self-starting.
#[must_use]
pub fn has_parameter_sets(data: &[u8]) -> bool {
    let units = split_annex_b(data);
    units
        .iter()
        .filter_map(|u| nal_type(u))
        .any(|t| t == NAL_SPS)
        && units
            .iter()
            .filter_map(|u| nal_type(u))
            .any(|t| t == NAL_PPS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_validate_their_own_geometry() {
        let good = DecodedFrame {
            data: vec![0; 64 * 4 * 32],
            width: 64,
            height: 32,
            stride: 64 * 4,
            pts_us: 0,
            sequence: 0,
        };
        assert!(good.is_consistent());
        assert!(!good.is_empty());

        // A short buffer must be caught here rather than in someone else's texture upload.
        assert!(!DecodedFrame {
            data: vec![0; 10],
            ..good.clone()
        }
        .is_consistent());
        assert!(!DecodedFrame {
            stride: 4,
            ..good.clone()
        }
        .is_consistent());
        assert!(!DecodedFrame { width: 0, ..good }.is_consistent());
    }

    #[test]
    fn a_padded_stride_is_accepted() {
        // Decoders align rows; demanding a tight stride would reject valid output.
        let f = DecodedFrame {
            data: vec![0; 128 * 32],
            width: 30,
            height: 32,
            stride: 128,
            pts_us: 0,
            sequence: 0,
        };
        assert!(f.is_consistent());
    }

    #[test]
    fn waiting_for_a_keyframe_is_not_fatal() {
        // A receiver joining mid-stream starts here. Treating it as fatal would make every session
        // fail to start.
        let e = DecodeError::AwaitingParameterSets;
        assert!(e.is_recoverable());
        assert!(e.wants_keyframe());

        assert!(!DecodeError::Unsupported.is_recoverable());
        assert!(!DecodeError::Unavailable("x".into()).wants_keyframe());
    }

    #[test]
    fn annex_b_splits_on_both_start_code_lengths() {
        // Encoders mix them: parameter sets often use the 4-byte form and slices the 3-byte form.
        let stream = [
            0, 0, 0, 1, 0x67, 0xAA, // SPS, 4-byte start code
            0, 0, 1, 0x68, 0xBB, // PPS, 3-byte start code
            0, 0, 0, 1, 0x65, 0xCC, 0xDD, // IDR slice
        ];
        let units = split_annex_b(&stream);
        assert_eq!(units.len(), 3);
        assert_eq!(nal_type(units[0]), Some(NAL_SPS));
        assert_eq!(nal_type(units[1]), Some(NAL_PPS));
        assert_eq!(nal_type(units[2]), Some(NAL_IDR));
        assert_eq!(units[2], &[0x65, 0xCC, 0xDD]);
    }

    #[test]
    fn splitting_never_panics_on_hostile_input() {
        // This parses data from the network, so it must survive anything.
        for stream in [
            vec![],
            vec![0],
            vec![0, 0],
            vec![0, 0, 1],
            vec![0, 0, 0, 1],
            vec![0, 0, 1, 0, 0, 1],
            vec![0; 64],
            vec![0xFF; 64],
        ] {
            let _ = split_annex_b(&stream);
        }
    }

    #[test]
    fn an_empty_nal_unit_is_dropped_rather_than_emitted() {
        // Back-to-back start codes appear in padded streams; emitting a zero-length unit would
        // make `nal_type` return None and confuse the caller.
        let stream = [0, 0, 0, 1, 0, 0, 0, 1, 0x65, 0xAA];
        let units = split_annex_b(&stream);
        assert_eq!(units.len(), 1);
        assert_eq!(nal_type(units[0]), Some(NAL_IDR));
    }

    #[test]
    fn parameter_set_detection_needs_both_sps_and_pps() {
        let both = [0, 0, 0, 1, 0x67, 0xAA, 0, 0, 0, 1, 0x68, 0xBB];
        assert!(has_parameter_sets(&both));

        let sps_only = [0, 0, 0, 1, 0x67, 0xAA];
        assert!(
            !has_parameter_sets(&sps_only),
            "SPS alone cannot start a decoder"
        );

        let slice_only = [0, 0, 0, 1, 0x65, 0xAA];
        assert!(!has_parameter_sets(&slice_only));
    }
}
