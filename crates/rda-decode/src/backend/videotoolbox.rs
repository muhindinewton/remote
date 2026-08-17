//! Hardware H.264 decoding on macOS via VideoToolbox.
//!
//! The mirror of the encoder in `rda-encode`, with three differences that matter:
//!
//! - **The session cannot be created until parameter sets arrive.** A decoder needs the SPS and PPS
//!   to know the geometry and profile, and those live in the bitstream. A receiver that joins
//!   mid-stream therefore decodes nothing until the next keyframe — which is normal, and is why
//!   [`DecodeError::AwaitingParameterSets`] is recoverable rather than fatal.
//!
//! - **Annex B has to be converted back to AVCC.** VideoToolbox wants length-prefixed NAL units in
//!   a `CMBlockBuffer`, with the parameter sets held in the format description rather than in the
//!   stream. The encoder converted the other way for RTP; this undoes it.
//!
//! - **Output is BGRA, not NV12.** The destination is a GPU texture, so the hardware does the
//!   colour conversion on the way out — faster than doing it ourselves, and one less place for a
//!   range mismatch to wash the picture out.

#![allow(unsafe_code)]

use crate::decoder::{
    has_parameter_sets, nal_type, split_annex_b, DecodeError, DecodedFrame, VideoDecoder, NAL_PPS,
    NAL_SPS,
};
use objc2_core_foundation::CFRetained;
use objc2_core_media::{
    CMBlockBuffer, CMSampleBuffer, CMTime, CMTimeFlags, CMVideoFormatDescription,
};
use objc2_core_video::{
    CVImageBuffer, CVPixelBuffer, CVPixelBufferGetBaseAddress, CVPixelBufferGetBytesPerRow,
    CVPixelBufferGetHeight, CVPixelBufferGetWidth, CVPixelBufferLockBaseAddress,
    CVPixelBufferLockFlags, CVPixelBufferUnlockBaseAddress,
};
use objc2_video_toolbox::{VTDecodeFrameFlags, VTDecodeInfoFlags, VTDecompressionSession};
use std::cell::RefCell;
use std::ffi::c_void;
use std::ptr::NonNull;
use std::rc::Rc;
use tracing::{debug, warn};

/// `kCVPixelFormatType_32BGRA`, the four-character code `'BGRA'`.
///
/// Not `32` — that is `kCVPixelFormatType_32ARGB`, and asking for it yields a buffer whose channels
/// are one position out. The mistake is invisible in the numbers (they look like plausible colours)
/// and obvious on screen, which is exactly why the round-trip test compares against the source.
const PIXEL_FORMAT_BGRA: u32 = u32::from_be_bytes(*b"BGRA");

/// Length prefix size AVCC uses. Four bytes, matching what the encoder emits.
const NAL_LENGTH_SIZE: i32 = 4;

type OutputQueue = Rc<RefCell<Vec<DecodedFrame>>>;

struct CallbackContext {
    queue: OutputQueue,
    sequence: std::cell::Cell<u64>,
    pts_us: std::cell::Cell<u64>,
}

/// VideoToolbox hardware decoder.
pub struct VideoToolboxDecoder {
    session: Option<CFRetained<VTDecompressionSession>>,
    format: Option<CFRetained<CMVideoFormatDescription>>,
    context: Box<CallbackContext>,
    queue: OutputQueue,
    /// Parameter sets seen so far, retained so the session can be rebuilt on a format change.
    sps: Option<Vec<u8>>,
    pps: Option<Vec<u8>>,
}

impl VideoToolboxDecoder {
    /// Creates a decoder that is waiting for parameter sets.
    ///
    /// The session itself cannot exist yet — its geometry comes from the SPS.
    #[must_use]
    pub fn new() -> Self {
        let queue: OutputQueue = Rc::new(RefCell::new(Vec::new()));
        Self {
            session: None,
            format: None,
            context: Box::new(CallbackContext {
                queue: queue.clone(),
                sequence: std::cell::Cell::new(0),
                pts_us: std::cell::Cell::new(0),
            }),
            queue,
            sps: None,
            pps: None,
        }
    }

    /// Records any parameter sets present in this access unit.
    ///
    /// Returns `true` if they differ from what we already had, which means the session must be
    /// rebuilt — a resolution change mid-stream is routine when the ladder moves.
    fn absorb_parameter_sets(&mut self, data: &[u8]) -> bool {
        let mut changed = false;
        for unit in split_annex_b(data) {
            match nal_type(unit) {
                Some(NAL_SPS) if self.sps.as_deref() != Some(unit) => {
                    self.sps = Some(unit.to_vec());
                    changed = true;
                }
                Some(NAL_PPS) if self.pps.as_deref() != Some(unit) => {
                    self.pps = Some(unit.to_vec());
                    changed = true;
                }
                _ => {}
            }
        }
        changed
    }

    /// Builds the format description and decompression session from the stored parameter sets.
    fn build_session(&mut self) -> Result<(), DecodeError> {
        let (Some(sps), Some(pps)) = (self.sps.as_ref(), self.pps.as_ref()) else {
            return Err(DecodeError::AwaitingParameterSets);
        };

        // The API wants an array of non-null pointers, so build one explicitly rather than
        // transmuting a `*const u8` array and hoping the layouts agree.
        let (Some(sps_ptr), Some(pps_ptr)) = (
            NonNull::new(sps.as_ptr() as *mut u8),
            NonNull::new(pps.as_ptr() as *mut u8),
        ) else {
            return Err(DecodeError::MalformedBitstream(
                "empty parameter set".to_string(),
            ));
        };
        let mut pointers: [NonNull<u8>; 2] = [sps_ptr, pps_ptr];
        let mut sizes: [usize; 2] = [sps.len(), pps.len()];
        let mut format_ptr: *const CMVideoFormatDescription = std::ptr::null();

        // SAFETY: both parameter-set slices outlive the call, the pointer and size arrays have the
        // declared count of two, and the out-pointer is a valid local.
        let status = unsafe {
            objc2_core_media::CMVideoFormatDescriptionCreateFromH264ParameterSets(
                None,
                2,
                NonNull::from(&mut pointers).cast(),
                NonNull::from(&mut sizes).cast(),
                NAL_LENGTH_SIZE,
                NonNull::from(&mut format_ptr),
            )
        };
        if status != 0 || format_ptr.is_null() {
            return Err(DecodeError::MalformedBitstream(format!(
                "could not build a format description from the parameter sets: {status}"
            )));
        }
        // SAFETY: the call succeeded and handed us one owned reference.
        let format = unsafe {
            CFRetained::from_raw(NonNull::new_unchecked(
                format_ptr as *mut CMVideoFormatDescription,
            ))
        };

        // Ask for BGRA out: the hardware does the colour conversion on the way to the texture.
        let attributes = bgra_output_attributes();

        let callback = objc2_video_toolbox::VTDecompressionOutputCallbackRecord {
            decompressionOutputCallback: Some(output_callback),
            decompressionOutputRefCon: (&*self.context as *const CallbackContext
                as *mut CallbackContext)
                .cast::<c_void>(),
        };

        let mut session_ptr: *mut VTDecompressionSession = std::ptr::null_mut();
        // SAFETY: the format description is live; the callback record matches the required layout
        // and its refcon outlives the session, which `Drop` invalidates first.
        let status = unsafe {
            VTDecompressionSession::create(
                None,
                &format,
                None,
                attributes.as_deref(),
                &callback,
                NonNull::from(&mut session_ptr),
            )
        };
        if status != 0 || session_ptr.is_null() {
            return Err(DecodeError::Unavailable(format!(
                "VTDecompressionSessionCreate failed with status {status}"
            )));
        }

        // SAFETY: success plus a non-null pointer means one owned reference.
        self.session = Some(unsafe { CFRetained::from_raw(NonNull::new_unchecked(session_ptr)) });
        self.format = Some(format);
        Ok(())
    }

    /// Wraps AVCC data in a `CMSampleBuffer` the decoder will accept.
    fn make_sample_buffer(
        &self,
        avcc: &mut Vec<u8>,
        pts_us: u64,
    ) -> Result<CFRetained<CMSampleBuffer>, DecodeError> {
        let format: &CMVideoFormatDescription = self
            .format
            .as_deref()
            .ok_or(DecodeError::AwaitingParameterSets)?;

        // Let CoreMedia own the memory and copy into it, rather than lending it our `Vec`.
        // Borrowing would need `kCFAllocatorNull` and an argument about exactly how long the
        // sample buffer outlives the call — one copy per frame is a small price for removing a
        // whole class of lifetime bug from an `unsafe` block.
        let mut block_ptr: *mut CMBlockBuffer = std::ptr::null_mut();
        // SAFETY: a null memory block with `AssureMemoryNow` asks CoreMedia to allocate
        // `block_length` bytes itself; the out-pointer is a valid local.
        let status = unsafe {
            CMBlockBuffer::create_with_memory_block(
                None,
                std::ptr::null_mut(),
                avcc.len(),
                None,
                std::ptr::null(),
                0,
                avcc.len(),
                objc2_core_media::kCMBlockBufferAssureMemoryNowFlag,
                NonNull::from(&mut block_ptr),
            )
        };
        if status != 0 || block_ptr.is_null() {
            return Err(DecodeError::Failed(format!(
                "CMBlockBufferCreate failed: {status}"
            )));
        }
        // SAFETY: success plus non-null means one owned reference.
        let block = unsafe { CFRetained::from_raw(NonNull::new_unchecked(block_ptr)) };

        let Some(source) = NonNull::new(avcc.as_mut_ptr().cast::<c_void>()) else {
            return Err(DecodeError::MalformedBitstream(
                "empty access unit".to_string(),
            ));
        };
        // SAFETY: the block was allocated with exactly `avcc.len()` bytes, and the source has that
        // many readable bytes.
        let status = unsafe { CMBlockBuffer::replace_data_bytes(source, &block, 0, avcc.len()) };
        if status != 0 {
            return Err(DecodeError::Failed(format!(
                "CMBlockBufferReplaceDataBytes failed: {status}"
            )));
        }

        let timing = objc2_core_media::CMSampleTimingInfo {
            duration: CMTime {
                value: 0,
                timescale: 0,
                flags: CMTimeFlags::empty(),
                epoch: 0,
            },
            presentationTimeStamp: CMTime {
                value: pts_us as i64,
                timescale: 1_000_000,
                flags: CMTimeFlags::Valid,
                epoch: 0,
            },
            decodeTimeStamp: CMTime {
                value: 0,
                timescale: 0,
                flags: CMTimeFlags::empty(),
                epoch: 0,
            },
        };
        let sizes = [avcc.len()];
        let mut sample_ptr: *mut CMSampleBuffer = std::ptr::null_mut();

        // SAFETY: block buffer and format description are live; the timing and size arrays each
        // have the declared count of one.
        let status = unsafe {
            CMSampleBuffer::create(
                None,
                Some(&block),
                true,
                None,
                std::ptr::null_mut(),
                Some(format),
                1,
                1,
                &timing,
                1,
                sizes.as_ptr(),
                NonNull::from(&mut sample_ptr),
            )
        };
        if status != 0 || sample_ptr.is_null() {
            return Err(DecodeError::Failed(format!(
                "CMSampleBufferCreate failed: {status}"
            )));
        }
        // SAFETY: success plus non-null means one owned reference.
        Ok(unsafe { CFRetained::from_raw(NonNull::new_unchecked(sample_ptr)) })
    }
}

/// Builds the `destinationImageBufferAttributes` dictionary asking for BGRA output.
///
/// Uses `from_slices` rather than the raw `CFDictionaryCreate`, because the raw form needs the
/// `kCFType*CallBacks` tables to make the dictionary *retain* its keys and values. Passing null
/// callbacks — the obvious-looking choice — leaves the dictionary holding pointers to objects that
/// are freed as soon as this function returns, and VideoToolbox then dereferences them.
fn bgra_output_attributes() -> Option<CFRetained<objc2_core_foundation::CFDictionary>> {
    use objc2_core_foundation::{CFDictionary, CFNumber, CFString};

    let key = CFString::from_str("PixelFormatType");
    let value = CFNumber::new_i32(PIXEL_FORMAT_BGRA as i32);
    let mut keys: [*const c_void; 1] = [(&*key) as *const CFString as *const c_void];
    let mut values: [*const c_void; 1] = [(&*value) as *const CFNumber as *const c_void];

    // SAFETY: the arrays hold one element each and outlive the call. The `kCFType*CallBacks` tables
    // are what make the dictionary retain its contents — with null callbacks it would hold raw
    // pointers to `key` and `value`, which are freed when this function returns and which
    // VideoToolbox would then dereference.
    unsafe {
        CFDictionary::new(
            None,
            keys.as_mut_ptr(),
            values.as_mut_ptr(),
            1,
            &objc2_core_foundation::kCFTypeDictionaryKeyCallBacks,
            &objc2_core_foundation::kCFTypeDictionaryValueCallBacks,
        )
    }
}

/// VideoToolbox's decoded-frame callback.
///
/// # Safety
///
/// Called with the refcon supplied at session creation, which points at a `CallbackContext` that
/// outlives the session.
unsafe extern "C-unwind" fn output_callback(
    refcon: *mut c_void,
    _source_frame_refcon: *mut c_void,
    status: i32,
    _flags: VTDecodeInfoFlags,
    image_buffer: *mut CVImageBuffer,
    _pts: CMTime,
    _duration: CMTime,
) {
    if refcon.is_null() {
        return;
    }
    // SAFETY: the refcon is the pointer given at session creation, and the context outlives the
    // session because `Drop` invalidates the session first.
    let context = unsafe { &*(refcon as *const CallbackContext) };

    if status != 0 || image_buffer.is_null() {
        if status != 0 {
            warn!(status, "VideoToolbox reported a decode error");
        }
        return;
    }

    // SAFETY: a non-null image buffer with a success status is a valid CVPixelBuffer for the
    // duration of this callback.
    let pixels = unsafe { &*(image_buffer as *const CVPixelBuffer) };

    // ReadOnly avoids invalidating any cached GPU copy of the buffer.
    // SAFETY: the buffer is valid; the unlock below is symmetric with the same flags, which
    // CoreVideo requires.
    let lock = unsafe { CVPixelBufferLockBaseAddress(pixels, CVPixelBufferLockFlags::ReadOnly) };
    if lock != 0 {
        warn!(lock, "could not lock the decoded pixel buffer");
        return;
    }

    let width = CVPixelBufferGetWidth(pixels) as u32;
    let height = CVPixelBufferGetHeight(pixels) as u32;
    let stride = CVPixelBufferGetBytesPerRow(pixels);
    let base = CVPixelBufferGetBaseAddress(pixels);

    if let Some(base) = NonNull::new(base.cast::<u8>()) {
        let len = stride * height as usize;
        let mut data = vec![0u8; len];
        // SAFETY: the buffer is locked and CoreVideo guarantees `stride * height` readable bytes;
        // the destination was just allocated at exactly that size and cannot overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(base.as_ptr(), data.as_mut_ptr(), len);
        }

        let sequence = context.sequence.get();
        context.sequence.set(sequence + 1);
        context.queue.borrow_mut().push(DecodedFrame {
            data,
            width,
            height,
            stride,
            pts_us: context.pts_us.get(),
            sequence,
        });
    } else {
        warn!("decoded pixel buffer has no base address");
    }

    // SAFETY: symmetric with the lock above, with the same flags as CoreVideo requires.
    unsafe {
        CVPixelBufferUnlockBaseAddress(pixels, CVPixelBufferLockFlags::ReadOnly);
    }
}

/// Rewrites Annex B start codes as AVCC 4-byte length prefixes, dropping parameter sets.
///
/// Parameter sets live in the format description for AVCC, so leaving them in the sample data makes
/// some decoder generations reject the frame outright.
#[must_use]
pub fn annex_b_to_avcc(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for unit in split_annex_b(data) {
        if matches!(nal_type(unit), Some(NAL_SPS) | Some(NAL_PPS)) {
            continue;
        }
        out.extend_from_slice(&(unit.len() as u32).to_be_bytes());
        out.extend_from_slice(unit);
    }
    out
}

impl Default for VideoToolboxDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl VideoDecoder for VideoToolboxDecoder {
    fn decode(
        &mut self,
        data: &[u8],
        pts_us: u64,
        _is_keyframe: bool,
    ) -> Result<Vec<DecodedFrame>, DecodeError> {
        // A resolution change mid-stream is routine when the ladder moves, and it arrives as new
        // parameter sets. Rebuilding rather than erroring is what makes that seamless.
        if self.absorb_parameter_sets(data) && self.session.is_some() {
            debug!("parameter sets changed; rebuilding the decompression session");
            self.session = None;
            self.format = None;
        }

        if self.session.is_none() {
            if !has_parameter_sets(data) && self.sps.is_none() {
                return Err(DecodeError::AwaitingParameterSets);
            }
            self.build_session()?;
        }

        let mut avcc = annex_b_to_avcc(data);
        if avcc.is_empty() {
            // Parameter sets only, with no slice: nothing to decode, and not an error.
            return Ok(Vec::new());
        }

        self.context.pts_us.set(pts_us);
        let sample = self.make_sample_buffer(&mut avcc, pts_us)?;
        let session = self.session.as_ref().expect("session was just built");

        // SAFETY: session and sample buffer are live; the flags request synchronous decoding so the
        // callback fires before this returns and `avcc` stays alive throughout.
        let status = unsafe {
            session.decode_frame(
                &sample,
                VTDecodeFrameFlags::empty(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(DecodeError::Failed(format!(
                "decode_frame failed: {status}"
            )));
        }

        // SAFETY: the session is live; an invalid time flushes everything pending.
        let status = unsafe { session.wait_for_asynchronous_frames() };
        if status != 0 {
            debug!(status, "waiting for asynchronous frames returned non-zero");
        }

        Ok(std::mem::take(&mut *self.queue.borrow_mut()))
    }

    fn reset(&mut self) {
        self.session = None;
        self.format = None;
        self.sps = None;
        self.pps = None;
        self.queue.borrow_mut().clear();
    }

    fn is_hardware(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "macos-videotoolbox"
    }
}

impl Drop for VideoToolboxDecoder {
    fn drop(&mut self) {
        // Invalidate before the callback context is freed, so no in-flight callback can reach a
        // dangling refcon.
        if let Some(session) = &self.session {
            // SAFETY: the session is live and this is the only place it is invalidated.
            unsafe {
                session.invalidate();
            }
        }
        // Keep the context borrowed until after `invalidate`, so the compiler cannot reorder its
        // drop ahead of the session teardown.
        let _keep_alive = &self.context;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn annex_b_converts_to_avcc_and_strips_parameter_sets() {
        // Parameter sets belong in the format description for AVCC; leaving them in the sample data
        // makes some decoder generations reject the frame.
        let stream = [
            0, 0, 0, 1, 0x67, 0xAA, // SPS
            0, 0, 0, 1, 0x68, 0xBB, // PPS
            0, 0, 0, 1, 0x65, 0xCC, 0xDD, // IDR slice
        ];
        let avcc = annex_b_to_avcc(&stream);
        assert_eq!(avcc, vec![0, 0, 0, 3, 0x65, 0xCC, 0xDD]);
    }

    #[test]
    fn a_stream_of_only_parameter_sets_produces_no_sample_data() {
        let stream = [0, 0, 0, 1, 0x67, 0xAA, 0, 0, 0, 1, 0x68, 0xBB];
        assert!(annex_b_to_avcc(&stream).is_empty());
    }

    #[test]
    fn conversion_survives_hostile_input() {
        for stream in [vec![], vec![0, 0, 1], vec![0xFF; 32], vec![0; 32]] {
            let _ = annex_b_to_avcc(&stream);
        }
    }

    #[test]
    fn a_new_decoder_waits_for_parameter_sets() {
        // A receiver joining mid-stream starts here, and it is not an error.
        let mut d = VideoToolboxDecoder::new();
        let slice_only = [0, 0, 0, 1, 0x65, 0xAA, 0xBB];
        let err = d.decode(&slice_only, 0, false).unwrap_err();
        assert_eq!(err, DecodeError::AwaitingParameterSets);
        assert!(err.is_recoverable());
        assert!(err.wants_keyframe());
    }

    #[test]
    fn reset_discards_the_parameter_sets() {
        let mut d = VideoToolboxDecoder::new();
        d.sps = Some(vec![0x67, 0xAA]);
        d.pps = Some(vec![0x68, 0xBB]);
        d.reset();
        assert!(d.sps.is_none());
        assert!(d.pps.is_none());
        assert!(d.session.is_none());
    }

    #[test]
    fn changed_parameter_sets_are_detected() {
        // A resolution change arrives as new parameter sets and must rebuild the session rather
        // than decode garbage.
        let mut d = VideoToolboxDecoder::new();
        let first = [0, 0, 0, 1, 0x67, 0xAA, 0, 0, 0, 1, 0x68, 0xBB];
        assert!(d.absorb_parameter_sets(&first));
        assert!(
            !d.absorb_parameter_sets(&first),
            "identical sets are not a change"
        );

        let second = [0, 0, 0, 1, 0x67, 0xCC, 0, 0, 0, 1, 0x68, 0xBB];
        assert!(d.absorb_parameter_sets(&second));
    }
}
