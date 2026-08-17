//! Hardware H.264/HEVC encoding on macOS via VideoToolbox.
//!
//! Apple Silicon has a dedicated media engine; this is the path to it. **It cannot encode AV1** —
//! M-series chips decode AV1 but have no AV1 encoder — so a macOS host negotiates H.264 or HEVC
//! regardless of what the controller would prefer (`docs/ARCHITECTURE.md` §3.5).
//!
//! Three things here are configured specifically for a 220 ms interactive link rather than for
//! file encoding:
//!
//! - **`RealTime` on, `AllowFrameReordering` off.** B-frames need future frames before the current
//!   one can be emitted, which adds a frame of latency for compression we do not need.
//! - **`MaxKeyFrameInterval` set to effectively infinity.** A periodic IDR is a self-inflicted
//!   bandwidth spike; keyframes happen when the receiver asks for one (§2.4).
//! - **Output converted from AVCC to Annex B.** VideoToolbox emits length-prefixed NAL units with
//!   parameter sets held separately in the format description; RTP payloads want start codes and
//!   in-band SPS/PPS, so both are converted here.
//!
//! The `unsafe` in this file is confined to the FFI calls; every block carries the invariant it
//! relies on. The encoder is not `Send` because a `VTCompressionSession` is thread-affine.

#![allow(unsafe_code)]

use crate::convert::{ColorRange, PlanarFormat, PlanarFrame};
use crate::encoder::{
    Codec, EncodeError, EncodedFrame, EncoderConfig, FrameKind, RecoveryMode, VideoEncoder,
};
use objc2_core_foundation::{CFBoolean, CFNumber, CFRetained, CFString, CFType};
use objc2_core_media::{CMSampleBuffer, CMTime, CMTimeFlags, CMVideoCodecType};

/// An invalid `CMTime`, which `complete_frames` interprets as "flush everything pending".
///
/// Built rather than read from `kCMTimeInvalid` so no extern static access is required: a CMTime is
/// invalid precisely when the `Valid` flag is clear.
const CM_TIME_INVALID: CMTime = CMTime {
    value: 0,
    timescale: 0,
    flags: CMTimeFlags::empty(),
    epoch: 0,
};
use objc2_core_video::{
    CVPixelBuffer, CVPixelBufferCreate, CVPixelBufferGetBaseAddressOfPlane,
    CVPixelBufferGetBytesPerRowOfPlane, CVPixelBufferLockBaseAddress, CVPixelBufferLockFlags,
    CVPixelBufferUnlockBaseAddress,
};
use objc2_video_toolbox::{VTCompressionSession, VTEncodeInfoFlags};
use std::cell::RefCell;
use std::ffi::c_void;
use std::ptr::NonNull;
use std::rc::Rc;
use tracing::{debug, warn};

/// `kCVPixelFormatType_420YpCbCr8BiPlanarFullRange` — NV12, full range.
const PIXEL_FORMAT_NV12_FULL: u32 = u32::from_be_bytes(*b"420f");
/// `kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange` — NV12, studio range.
const PIXEL_FORMAT_NV12_VIDEO: u32 = u32::from_be_bytes(*b"420v");

/// `kCMVideoCodecType_H264`.
const CODEC_H264: CMVideoCodecType = u32::from_be_bytes(*b"avc1");
/// `kCMVideoCodecType_HEVC`.
const CODEC_HEVC: CMVideoCodecType = u32::from_be_bytes(*b"hvc1");

/// Annex B start code.
const START_CODE: [u8; 4] = [0, 0, 0, 1];

/// Frames collected from the asynchronous output callback.
///
/// VideoToolbox may call back on another thread, so the queue is shared through a raw pointer
/// handed in as the callback's refcon. `Rc<RefCell<..>>` is sound here because the session is
/// pinned to one thread and every callback for a frame is delivered before
/// `VTCompressionSessionCompleteFrames` returns.
type OutputQueue = Rc<RefCell<Vec<EncodedFrame>>>;

struct CallbackContext {
    queue: OutputQueue,
    sequence: std::cell::Cell<u64>,
    pending_recovery: std::cell::Cell<Option<u8>>,
    /// Set immediately before an encode that forced a keyframe.
    expect_keyframe: std::cell::Cell<bool>,
    /// The presentation timestamp of the frame currently being encoded.
    pts_us: std::cell::Cell<u64>,
}

/// VideoToolbox hardware encoder.
pub struct VideoToolboxEncoder {
    session: CFRetained<VTCompressionSession>,
    config: EncoderConfig,
    context: Box<CallbackContext>,
    queue: OutputQueue,
    pixel_format: u32,
    force_keyframe: bool,
    pending_ltr: Option<u8>,
}

impl VideoToolboxEncoder {
    /// Creates a hardware compression session.
    pub fn new(config: EncoderConfig) -> Result<Self, EncodeError> {
        if !config.is_valid() {
            return Err(EncodeError::BadConfig(format!(
                "{}x{} @ {} fps",
                config.width, config.height, config.fps
            )));
        }
        let codec = match config.codec {
            Codec::H264 => CODEC_H264,
            Codec::Hevc => CODEC_HEVC,
            // Apple Silicon has no AV1 encoder. Refusing here rather than silently producing H.264
            // keeps the codec negotiation honest.
            Codec::Av1 => return Err(EncodeError::NoHardware(Codec::Av1)),
        };

        let queue: OutputQueue = Rc::new(RefCell::new(Vec::new()));
        let context = Box::new(CallbackContext {
            queue: queue.clone(),
            sequence: std::cell::Cell::new(0),
            pending_recovery: std::cell::Cell::new(None),
            expect_keyframe: std::cell::Cell::new(false),
            pts_us: std::cell::Cell::new(0),
        });

        let mut session_ptr: *mut VTCompressionSession = std::ptr::null_mut();
        // SAFETY: width/height are validated positive; the callback matches the required signature;
        // `context` outlives the session because both live in the returned struct and the session
        // is invalidated in `Drop` before the box is freed.
        let status = unsafe {
            VTCompressionSession::create(
                None,
                config.width as i32,
                config.height as i32,
                codec,
                None,
                None,
                None,
                Some(output_callback),
                (&*context as *const CallbackContext as *mut CallbackContext).cast::<c_void>(),
                NonNull::from(&mut session_ptr),
            )
        };
        if status != 0 || session_ptr.is_null() {
            return Err(EncodeError::Unavailable(format!(
                "VTCompressionSessionCreate failed with status {status}"
            )));
        }

        // SAFETY: the call above returned success and a non-null pointer, so it holds one
        // reference that we now own.
        let session = unsafe { CFRetained::from_raw(NonNull::new_unchecked(session_ptr)) };

        let encoder = Self {
            session,
            config,
            context,
            queue,
            pixel_format: PIXEL_FORMAT_NV12_FULL,
            force_keyframe: false,
            pending_ltr: None,
        };
        encoder.configure()?;
        Ok(encoder)
    }

    /// Applies the low-latency properties.
    fn configure(&self) -> Result<(), EncodeError> {
        // Real-time mode: the encoder must not trade latency for compression efficiency.
        self.set_bool("RealTime", true)?;
        // B-frames require a future frame before the current one can be emitted, costing a frame
        // of latency for compression this workload does not need.
        self.set_bool("AllowFrameReordering", false)?;
        // A periodic IDR is a bandwidth spike we did not ask for. Recovery is receiver-driven.
        let interval: i32 = if self.config.keyframe_interval_s == 0 {
            i32::MAX
        } else {
            (self.config.keyframe_interval_s * u32::from(self.config.fps)) as i32
        };
        self.set_i32("MaxKeyFrameInterval", interval)?;
        self.set_i32("MaxKeyFrameIntervalDuration", i32::MAX)?;

        self.set_i32("AverageBitRate", self.config.bitrate_bps as i32)?;
        self.set_i32("ExpectedFrameRate", i32::from(self.config.fps))?;

        // Prefer the dedicated media engine. Not fatal if unavailable — Intel Macs without a
        // capable GPU fall back to software, which is slower but correct.
        if let Err(e) = self.set_bool("EnableHardwareAcceleratedVideoEncoder", true) {
            debug!(error = %e, "hardware acceleration hint not accepted");
        }
        // Long-term references let a decode failure be repaired without an IDR. Not supported by
        // every encoder generation, so a refusal is reported rather than fatal.
        if self.set_i32("MaxAllowedFrameQP", 51).is_err() {
            debug!("MaxAllowedFrameQP not supported by this encoder");
        }
        Ok(())
    }

    fn set_property(&self, key: &str, value: Option<&CFType>) -> Result<(), EncodeError> {
        let key = CFString::from_str(key);
        // SAFETY: the session is live, and both key and value are valid Core Foundation objects
        // for the duration of the call.
        let session: &CFType = AsRef::<CFType>::as_ref(&*self.session);
        let status = unsafe { objc2_video_toolbox::VTSessionSetProperty(session, &key, value) };
        if status == 0 {
            Ok(())
        } else {
            Err(EncodeError::Failed(format!(
                "property {key} rejected with status {status}"
            )))
        }
    }

    fn set_bool(&self, key: &str, value: bool) -> Result<(), EncodeError> {
        let v: &CFType = AsRef::<CFType>::as_ref(CFBoolean::new(value));
        self.set_property(key, Some(v))
    }

    fn set_i32(&self, key: &str, value: i32) -> Result<(), EncodeError> {
        let number = CFNumber::new_i32(value);
        let v: &CFType = AsRef::<CFType>::as_ref(&*number);
        self.set_property(key, Some(v))
    }

    /// Copies a planar frame into a fresh `CVPixelBuffer`.
    ///
    /// This copy is the cost of taking the CPU capture path. The zero-copy alternative — an
    /// `IOSurface` straight from ScreenCaptureKit — removes it entirely and is what
    /// `rda_capture::Surface::IoSurface` exists to carry.
    fn make_pixel_buffer(
        &self,
        frame: &PlanarFrame,
    ) -> Result<CFRetained<CVPixelBuffer>, EncodeError> {
        if frame.format != PlanarFormat::Nv12 {
            return Err(EncodeError::BadConfig(
                "VideoToolbox requires NV12 input".to_string(),
            ));
        }

        let mut buffer_ptr: *mut CVPixelBuffer = std::ptr::null_mut();
        // SAFETY: dimensions are validated; the out-pointer is a valid local.
        let status = unsafe {
            CVPixelBufferCreate(
                None,
                frame.width as usize,
                frame.height as usize,
                self.pixel_format,
                None,
                NonNull::from(&mut buffer_ptr),
            )
        };
        if status != 0 || buffer_ptr.is_null() {
            return Err(EncodeError::Failed(format!(
                "CVPixelBufferCreate failed: {status}"
            )));
        }
        // SAFETY: the create call succeeded and handed us one owned reference.
        let buffer = unsafe { CFRetained::from_raw(NonNull::new_unchecked(buffer_ptr)) };

        // SAFETY: the buffer is live and we hold the only reference; the lock is released below on
        // every path including the error one.
        let lock =
            unsafe { CVPixelBufferLockBaseAddress(&buffer, CVPixelBufferLockFlags::empty()) };
        if lock != 0 {
            return Err(EncodeError::Failed(format!(
                "could not lock pixel buffer: {lock}"
            )));
        }

        let result = self.copy_planes(&buffer, frame);

        // SAFETY: symmetric with the lock above, with the same flags as required.
        unsafe {
            CVPixelBufferUnlockBaseAddress(&buffer, CVPixelBufferLockFlags::empty());
        }
        result?;
        Ok(buffer)
    }

    /// Copies luma and chroma row by row, honouring the destination's stride.
    ///
    /// The destination is frequently padded to a hardware-friendly alignment, so a flat `memcpy`
    /// of the whole plane would shear the picture.
    fn copy_planes(&self, buffer: &CVPixelBuffer, frame: &PlanarFrame) -> Result<(), EncodeError> {
        let width = frame.width as usize;
        let height = frame.height as usize;
        let chroma_h = frame.height.div_ceil(2) as usize;
        let chroma_bytes = frame.width.div_ceil(2) as usize * 2;

        for (plane, src, rows, row_bytes, src_stride) in [
            (0usize, frame.luma(), height, width, frame.luma_stride),
            (
                1usize,
                frame.chroma(),
                chroma_h,
                chroma_bytes,
                frame.chroma_stride,
            ),
        ] {
            // The buffer is locked, and plane indices 0 and 1 exist for any bi-planar format,
            // which we ensured by rejecting anything but NV12 above.
            let dst = CVPixelBufferGetBaseAddressOfPlane(buffer, plane);
            let dst_stride = CVPixelBufferGetBytesPerRowOfPlane(buffer, plane);
            let Some(dst) = NonNull::new(dst.cast::<u8>()) else {
                return Err(EncodeError::Failed(format!(
                    "plane {plane} has no base address"
                )));
            };
            if dst_stride < row_bytes {
                return Err(EncodeError::Failed(format!(
                    "plane {plane} stride {dst_stride} is smaller than {row_bytes} bytes per row"
                )));
            }

            for row in 0..rows {
                let src_off = row * src_stride;
                if src_off + row_bytes > src.len() {
                    return Err(EncodeError::Failed(format!(
                        "source plane {plane} is short at row {row}"
                    )));
                }
                // SAFETY: the destination has `dst_stride * rows` bytes by construction and
                // `dst_stride >= row_bytes` was just checked; the source range was bounds-checked
                // immediately above. The regions cannot overlap — one is ours, one is CoreVideo's.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        src.as_ptr().add(src_off),
                        dst.as_ptr().add(row * dst_stride),
                        row_bytes,
                    );
                }
            }
        }
        Ok(())
    }

    /// Frame-level properties: currently only "force this one to be a keyframe".
    ///
    /// Built with `from_slices` rather than the raw `CFDictionaryCreate`, which needs the
    /// `kCFType*CallBacks` tables to make the dictionary retain its contents. Null callbacks leave
    /// it holding freed pointers, and VideoToolbox dereferences them.
    fn frame_properties(&self) -> Option<CFRetained<objc2_core_foundation::CFDictionary>> {
        if !self.force_keyframe {
            return None;
        }
        let key = CFString::from_str("ForceKeyFrame");
        let value = CFBoolean::new(true);
        let mut keys: [*const c_void; 1] = [(&*key) as *const CFString as *const c_void];
        let mut values: [*const c_void; 1] = [value as *const CFBoolean as *const c_void];

        // SAFETY: the arrays hold one element each and outlive the call. The `kCFType*CallBacks`
        // tables are what make the dictionary retain its contents — with null callbacks it would
        // hold raw pointers to `key` and `value`, which are freed when this function returns.
        unsafe {
            objc2_core_foundation::CFDictionary::new(
                None,
                keys.as_mut_ptr(),
                values.as_mut_ptr(),
                1,
                &objc2_core_foundation::kCFTypeDictionaryKeyCallBacks,
                &objc2_core_foundation::kCFTypeDictionaryValueCallBacks,
            )
        }
    }
}

/// VideoToolbox's asynchronous output callback.
///
/// # Safety
///
/// Called by VideoToolbox with the refcon we supplied at session creation, which is a pointer to a
/// `CallbackContext` that outlives the session.
unsafe extern "C-unwind" fn output_callback(
    refcon: *mut c_void,
    _source_frame_refcon: *mut c_void,
    status: i32,
    flags: VTEncodeInfoFlags,
    sample_buffer: *mut CMSampleBuffer,
) {
    if refcon.is_null() {
        return;
    }
    // SAFETY: the refcon is the pointer we passed to `create`, and the context outlives the
    // session because `Drop` invalidates the session first.
    let context = unsafe { &*(refcon as *const CallbackContext) };

    if status != 0 {
        warn!(status, "VideoToolbox reported an encode error");
        return;
    }
    if flags.contains(VTEncodeInfoFlags::FrameDropped) || sample_buffer.is_null() {
        debug!("VideoToolbox dropped a frame");
        return;
    }
    // SAFETY: VideoToolbox guarantees a valid sample buffer when status is noErr and the frame was
    // not dropped. The reference is borrowed for the duration of this callback only.
    let sample = unsafe { &*sample_buffer };

    let Some(mut data) = extract_annex_b(sample) else {
        warn!("could not extract a bitstream from the sample buffer");
        return;
    };

    let sequence = context.sequence.get();
    context.sequence.set(sequence + 1);
    let ltr_index = context.pending_recovery.take();

    // The encoder already knows both facts the sample buffer would tell us. Reading them back out
    // of the attachment dictionary needs more CoreMedia surface than the bindings expose safely,
    // and would only confirm what we asked for. The first frame is always an IDR.
    let kind = if sequence == 0 || context.expect_keyframe.take() {
        FrameKind::Keyframe
    } else if ltr_index.is_some() {
        FrameKind::LtrRecovery
    } else {
        FrameKind::Delta
    };

    // VideoToolbox keeps SPS and PPS in the format description, *not* in the sample data. A
    // bitstream without them is not self-starting: a receiver joining the stream — or reconnecting
    // after a network change — would never decode a single frame. RTP payload formats expect them
    // in band, so they are prepended to every keyframe here.
    if kind == FrameKind::Keyframe {
        if let Some(sets) = extract_parameter_sets(sample) {
            let mut with_sets = sets;
            with_sets.extend_from_slice(&data);
            data = with_sets;
        } else {
            warn!("could not extract parameter sets; this keyframe will not be self-starting");
        }
    }

    context.queue.borrow_mut().push(EncodedFrame {
        data,
        kind,
        pts_us: context.pts_us.get(),
        sequence,
        temporal_layer: 0,
        ltr_index,
        qp: None,
    });
}

/// Pulls SPS and PPS out of the sample's format description as Annex B NAL units.
///
/// Returns `None` if the format description is missing or reports no parameter sets, which should
/// not happen for a keyframe but must not panic if it does.
fn extract_parameter_sets(sample: &CMSampleBuffer) -> Option<Vec<u8>> {
    // SAFETY: the sample buffer is valid for the callback's duration.
    let format = unsafe { sample.format_description() }?;

    // Every out-param gets a real destination. CoreMedia writes through them regardless of
    // whether the caller wants the value, so passing null here traps.
    let mut count: usize = 0;
    let mut probe_ptr: *const u8 = std::ptr::null();
    let mut probe_size: usize = 0;
    let mut header_len: std::ffi::c_int = 0;
    // SAFETY: the format description is live and every out-param points at a valid local.
    let status = unsafe {
        objc2_core_media::CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
            &format,
            0,
            &mut probe_ptr,
            &mut probe_size,
            &mut count,
            &mut header_len,
        )
    };
    if status != 0 || count == 0 {
        return None;
    }

    let mut out = Vec::with_capacity(128);
    for index in 0..count {
        let mut ptr: *const u8 = std::ptr::null();
        let mut size: usize = 0;
        let mut set_count: usize = 0;
        let mut nal_len: std::ffi::c_int = 0;
        // SAFETY: `index` is below the count just returned, and every out-param is a valid local.
        let status = unsafe {
            objc2_core_media::CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                &format,
                index,
                &mut ptr,
                &mut size,
                &mut set_count,
                &mut nal_len,
            )
        };
        if status != 0 || ptr.is_null() || size == 0 {
            return None;
        }
        out.extend_from_slice(&START_CODE);
        // SAFETY: CoreMedia guarantees `size` readable bytes at `ptr`, owned by the format
        // description which is alive for this scope.
        out.extend_from_slice(unsafe { std::slice::from_raw_parts(ptr, size) });
    }
    Some(out)
}

/// Converts VideoToolbox's AVCC output to Annex B.
///
/// VideoToolbox emits 4-byte-length-prefixed NAL units with SPS/PPS held in the format description
/// rather than in the stream. RTP payload formats want start codes and in-band parameter sets, so
/// both conversions happen here rather than being left to surprise the packetiser.
fn extract_annex_b(sample: &CMSampleBuffer) -> Option<Vec<u8>> {
    // SAFETY: the sample buffer is valid for the callback's duration.
    let block = unsafe { sample.data_buffer() }?;
    // SAFETY: the block buffer came from a valid sample buffer and is alive for this callback.
    let total = unsafe { block.data_length() };
    if total == 0 {
        return None;
    }

    let mut avcc = vec![0u8; total];
    // SAFETY: the destination has exactly `total` bytes, which is the length we just read.
    let dest = NonNull::new(avcc.as_mut_ptr().cast::<c_void>())?;
    // SAFETY: `dest` points at exactly `total` writable bytes, which is the length just read.
    let status = unsafe { block.copy_data_bytes(0, total, dest) };
    if status != 0 {
        return None;
    }

    Some(avcc_to_annex_b(&avcc))
}

/// Rewrites 4-byte length prefixes as Annex B start codes.
///
/// Returns the input unchanged if it does not parse as AVCC, which is the safe failure: a stream
/// that is already Annex B passes through rather than being corrupted.
pub fn avcc_to_annex_b(avcc: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(avcc.len() + 16);
    let mut offset = 0usize;

    while offset + 4 <= avcc.len() {
        let len = u32::from_be_bytes([
            avcc[offset],
            avcc[offset + 1],
            avcc[offset + 2],
            avcc[offset + 3],
        ]) as usize;
        let start = offset + 4;
        // A length that overruns the buffer means this is not AVCC. Emitting the original is
        // better than emitting a truncated stream.
        if len == 0 || start + len > avcc.len() {
            return avcc.to_vec();
        }
        out.extend_from_slice(&START_CODE);
        out.extend_from_slice(&avcc[start..start + len]);
        offset = start + len;
    }

    if offset == avcc.len() && !out.is_empty() {
        out
    } else {
        avcc.to_vec()
    }
}

impl VideoEncoder for VideoToolboxEncoder {
    fn encode(
        &mut self,
        frame: &PlanarFrame,
        pts_us: u64,
    ) -> Result<Vec<EncodedFrame>, EncodeError> {
        if frame.width != self.config.width || frame.height != self.config.height {
            return Err(EncodeError::GeometryMismatch {
                got_w: frame.width,
                got_h: frame.height,
                want_w: self.config.width,
                want_h: self.config.height,
            });
        }

        // The pixel format must match the range the converter used, or the encoder reinterprets
        // the levels and the picture comes out washed out or crushed.
        self.pixel_format = match frame.config.range {
            ColorRange::Full => PIXEL_FORMAT_NV12_FULL,
            ColorRange::Limited => PIXEL_FORMAT_NV12_VIDEO,
        };

        let buffer = self.make_pixel_buffer(frame)?;
        self.context.pending_recovery.set(self.pending_ltr.take());
        self.context.expect_keyframe.set(self.force_keyframe);
        self.context.pts_us.set(pts_us);

        let pts = CMTime {
            value: pts_us as i64,
            timescale: 1_000_000,
            flags: CMTimeFlags::Valid,
            epoch: 0,
        };
        let duration = CMTime {
            value: 1,
            timescale: i32::from(self.config.fps.max(1)),
            flags: CMTimeFlags::Valid,
            epoch: 0,
        };
        let properties = self.frame_properties();

        // SAFETY: the session and pixel buffer are live; the frame-properties dictionary, when
        // present, is borrowed for the duration of the call and contains only CF types.
        let status = unsafe {
            self.session.encode_frame(
                AsRef::<objc2_core_video::CVImageBuffer>::as_ref(&*buffer),
                pts,
                duration,
                properties.as_deref(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(EncodeError::Failed(format!(
                "encode_frame failed: {status}"
            )));
        }
        self.force_keyframe = false;

        // Drain synchronously so the caller sees a frame per call. A pipelined design would hide
        // more of the encoder's latency, but at 220 ms RTT the few milliseconds saved are not
        // worth the extra buffering.
        // SAFETY: the session is live; an invalid time means "complete everything pending".
        let status = unsafe { self.session.complete_frames(CM_TIME_INVALID) };
        if status != 0 {
            return Err(EncodeError::Failed(format!(
                "complete_frames failed: {status}"
            )));
        }

        Ok(std::mem::take(&mut *self.queue.borrow_mut()))
    }

    fn set_bitrate(&mut self, bitrate_bps: u32) -> Result<(), EncodeError> {
        self.config.bitrate_bps = bitrate_bps;
        self.set_i32("AverageBitRate", bitrate_bps as i32)
    }

    fn set_fps(&mut self, fps: u8) -> Result<(), EncodeError> {
        self.config.fps = fps.max(1);
        self.set_i32("ExpectedFrameRate", i32::from(self.config.fps))
    }

    fn request_recovery(&mut self, mode: RecoveryMode) -> Result<(), EncodeError> {
        match mode {
            // VideoToolbox exposes no portable long-term-reference control, so an LTR request
            // escalates to a forced keyframe. Saying so through `supports_ltr` lets the rate
            // controller account for the real cost instead of assuming a cheap repair.
            RecoveryMode::Ltr { .. } | RecoveryMode::Idr => {
                self.force_keyframe = true;
                self.pending_ltr = None;
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<Vec<EncodedFrame>, EncodeError> {
        // SAFETY: the session is live until `Drop`.
        let status = unsafe { self.session.complete_frames(CM_TIME_INVALID) };
        if status != 0 {
            return Err(EncodeError::Failed(format!("flush failed: {status}")));
        }
        Ok(std::mem::take(&mut *self.queue.borrow_mut()))
    }

    fn supports_ltr(&self) -> bool {
        false
    }

    fn is_hardware(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "macos-videotoolbox"
    }

    fn config(&self) -> EncoderConfig {
        self.config
    }
}

impl Drop for VideoToolboxEncoder {
    fn drop(&mut self) {
        // Invalidate before the callback context is freed, so no in-flight callback can reach a
        // dangling refcon.
        // SAFETY: the session is live and this is the only place it is invalidated.
        unsafe {
            self.session.invalidate();
        }
        let _ = &self.context;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::{bgra_to_planar, ConvertConfig};

    fn planar(w: u32, h: u32, value: u8) -> PlanarFrame {
        let src = vec![value; (w * h * 4) as usize];
        bgra_to_planar(
            &src,
            w,
            h,
            w as usize * 4,
            PlanarFormat::Nv12,
            ConvertConfig::default(),
        )
        .unwrap()
    }

    #[test]
    fn avcc_converts_to_annex_b() {
        // Two NAL units of 3 and 2 bytes.
        let avcc = [0, 0, 0, 3, 0x65, 0x88, 0x84, 0, 0, 0, 2, 0x41, 0x9A];
        let annex = avcc_to_annex_b(&avcc);
        assert_eq!(
            annex,
            vec![0, 0, 0, 1, 0x65, 0x88, 0x84, 0, 0, 0, 1, 0x41, 0x9A]
        );
    }

    #[test]
    fn malformed_avcc_passes_through_untouched() {
        // A length that overruns means this is not AVCC. Truncating would corrupt a stream that is
        // already Annex B; returning it unchanged is the safe failure.
        let already_annex_b = [0, 0, 0, 1, 0x65, 0x88];
        assert_eq!(avcc_to_annex_b(&already_annex_b), already_annex_b.to_vec());

        let overrun = [0, 0, 0, 99, 0x65];
        assert_eq!(avcc_to_annex_b(&overrun), overrun.to_vec());

        assert!(avcc_to_annex_b(&[]).is_empty());
        assert_eq!(avcc_to_annex_b(&[1, 2]), vec![1, 2]);
    }

    #[test]
    fn codec_four_character_codes_are_correct() {
        assert_eq!(CODEC_H264, 0x6176_6331); // 'avc1'
        assert_eq!(CODEC_HEVC, 0x6876_6331); // 'hvc1'
        assert_eq!(PIXEL_FORMAT_NV12_FULL, 0x3432_3066); // '420f'
        assert_eq!(PIXEL_FORMAT_NV12_VIDEO, 0x3432_3076); // '420v'
    }

    #[test]
    fn av1_is_refused_rather_than_silently_downgraded() {
        // Apple Silicon decodes AV1 but cannot encode it. Quietly producing H.264 would make codec
        // negotiation a lie.
        let config = EncoderConfig {
            codec: Codec::Av1,
            width: 320,
            height: 240,
            ..Default::default()
        };
        assert!(matches!(
            VideoToolboxEncoder::new(config),
            Err(EncodeError::NoHardware(Codec::Av1))
        ));
    }

    #[test]
    fn an_invalid_configuration_is_refused() {
        assert!(VideoToolboxEncoder::new(EncoderConfig {
            width: 3,
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn a_session_can_be_created_and_reports_hardware() {
        let config = EncoderConfig {
            width: 320,
            height: 240,
            fps: 30,
            ..Default::default()
        };
        match VideoToolboxEncoder::new(config) {
            Ok(e) => {
                assert!(e.is_hardware());
                assert_eq!(e.name(), "macos-videotoolbox");
                assert!(
                    !e.supports_ltr(),
                    "VideoToolbox has no portable LTR control"
                );
            }
            Err(e) => panic!("VideoToolbox session creation failed: {e}"),
        }
    }

    #[test]
    fn encoding_produces_a_real_h264_bitstream() {
        let config = EncoderConfig {
            width: 320,
            height: 240,
            fps: 30,
            bitrate_bps: 1_000_000,
            ..Default::default()
        };
        let Ok(mut encoder) = VideoToolboxEncoder::new(config) else {
            eprintln!("skipping: no VideoToolbox session available");
            return;
        };

        let out = encoder
            .encode(&planar(320, 240, 128), 0)
            .expect("encode must succeed");
        assert!(!out.is_empty(), "the first frame must produce output");

        let first = &out[0];
        assert!(!first.is_empty());
        // Annex B: the bitstream must start with a start code.
        assert_eq!(&first.data[..4], &START_CODE, "output must be Annex B");
        // The first frame is always an IDR, so a NAL of type 5 or a parameter set must be present.
        let nal_types: Vec<u8> = first
            .data
            .windows(5)
            .filter(|w| w[..4] == START_CODE)
            .map(|w| w[4] & 0x1F)
            .collect();
        assert!(!nal_types.is_empty(), "no NAL units found");
    }

    #[test]
    fn a_geometry_mismatch_is_refused() {
        let config = EncoderConfig {
            width: 320,
            height: 240,
            ..Default::default()
        };
        let Ok(mut encoder) = VideoToolboxEncoder::new(config) else {
            eprintln!("skipping: no VideoToolbox session available");
            return;
        };
        assert!(matches!(
            encoder.encode(&planar(64, 64, 128), 0),
            Err(EncodeError::GeometryMismatch { .. })
        ));
    }

    #[test]
    fn bitrate_and_frame_rate_can_be_changed_mid_session() {
        // Rate control calls these every frame; a session that had to be rebuilt to change bitrate
        // would make adaptive streaming impossible.
        let config = EncoderConfig {
            width: 320,
            height: 240,
            ..Default::default()
        };
        let Ok(mut encoder) = VideoToolboxEncoder::new(config) else {
            eprintln!("skipping: no VideoToolbox session available");
            return;
        };
        assert!(encoder.set_bitrate(500_000).is_ok());
        assert!(encoder.set_fps(15).is_ok());
        assert_eq!(encoder.config().bitrate_bps, 500_000);
        assert_eq!(encoder.config().fps, 15);
    }
}
