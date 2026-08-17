//! The client handle: session lifecycle, frame delivery and telemetry.
//!
//! The frame path is the part that matters for rendering. [`rda_client_poll_frame`] advances the
//! jitter buffer and decodes at most one frame; [`rda_client_frame_data`] then hands out a *borrowed*
//! pointer to the pixels. Nothing is copied, so the UI can upload straight into a texture — which is
//! what keeps a 60 fps render loop off the UI thread's allocator.
//!
//! The borrow is valid only until the next `poll_frame` on the same client. That is a real
//! constraint and the Dart side must respect it, so it is stated on every function that returns one.

use crate::error::{borrow_str, clear_last_error, set_last_error};
use crate::{
    RdaStatus, RDA_ERR_DECODE, RDA_ERR_INVALID_ARGUMENT, RDA_ERR_NO_FRAME, RDA_ERR_NULL_ARGUMENT,
    RDA_OK,
};
use rda_decode::decoder::{DecodedFrame, VideoDecoder};
use rda_decode::jitter::{JitterBuffer, PlayoutDecision};
use rda_encode::EncodedFrame;
use rda_proto::ids::DeviceId;
use std::ffi::{c_char, c_void};

/// Opaque client handle.
///
/// Not `Send`: the hardware decoder is thread-affine, and Flutter's FFI calls arrive on one
/// isolate thread anyway.
pub struct RdaClient {
    decoder: Box<dyn VideoDecoder>,
    jitter: JitterBuffer,
    /// The most recently decoded frame, kept alive so its pixels can be borrowed.
    current: Option<DecodedFrame>,
    peer: Option<DeviceId>,
    telemetry: rda_telemetry::LinkTelemetry,
    frames_rendered: u64,
    keyframe_requests: u64,
}

impl RdaClient {
    fn new() -> Result<Self, String> {
        let decoder = rda_decode::backend::hardware_decoder()
            .map_err(|e| format!("no hardware decoder available: {e}"))?;
        Ok(Self {
            decoder,
            jitter: JitterBuffer::new(),
            current: None,
            peer: None,
            telemetry: rda_telemetry::LinkTelemetry::new(),
            frames_rendered: 0,
            keyframe_requests: 0,
        })
    }
}

/// Turns a raw handle into a reference, or records an error and returns `None`.
///
/// # Safety
///
/// `handle` must be null or a pointer returned by [`rda_client_create`] that has not been destroyed.
unsafe fn client<'a>(handle: *mut RdaClient) -> Option<&'a mut RdaClient> {
    if handle.is_null() {
        set_last_error("client handle was null");
        return None;
    }
    // SAFETY: the caller guarantees a live handle from `rda_client_create`, and clients are used
    // from a single thread so no other reference can exist.
    Some(unsafe { &mut *handle })
}

/// Creates a client.
///
/// Returns null on failure; call [`crate::rda_last_error`] for the reason. The most common one is a
/// platform with no hardware decoder, which is worth surfacing rather than silently falling back to
/// software and burning a core.
#[no_mangle]
pub extern "C" fn rda_client_create() -> *mut RdaClient {
    clear_last_error();
    match RdaClient::new() {
        Ok(c) => Box::into_raw(Box::new(c)),
        Err(e) => {
            set_last_error(e);
            std::ptr::null_mut()
        }
    }
}

/// Destroys a client. Null is accepted and ignored.
///
/// # Safety
///
/// `handle` must have come from [`rda_client_create`] and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn rda_client_destroy(handle: *mut RdaClient) {
    if handle.is_null() {
        return;
    }
    // SAFETY: the caller guarantees the handle came from `Box::into_raw` and is destroyed once.
    drop(unsafe { Box::from_raw(handle) });
}

/// Sets the peer this client is connected to.
///
/// # Safety
///
/// `device_id` must be a nul-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn rda_client_set_peer(
    handle: *mut RdaClient,
    device_id: *const c_char,
) -> RdaStatus {
    clear_last_error();
    // SAFETY: the caller guarantees a live handle.
    let Some(client) = (unsafe { client(handle) }) else {
        return RDA_ERR_NULL_ARGUMENT;
    };
    // SAFETY: the caller guarantees a nul-terminated string.
    let Some(text) = (unsafe { borrow_str(device_id) }) else {
        return RDA_ERR_NULL_ARGUMENT;
    };

    match DeviceId::parse(text) {
        Ok(id) => {
            client.peer = Some(id);
            RDA_OK
        }
        Err(e) => {
            set_last_error(format!("invalid device id: {e}"));
            RDA_ERR_INVALID_ARGUMENT
        }
    }
}

/// Submits a compressed frame that arrived from the transport.
///
/// The frame enters the jitter buffer; it is decoded later by [`rda_client_poll_frame`], when its
/// playout deadline arrives.
///
/// # Safety
///
/// `data` must point at `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn rda_client_submit_frame(
    handle: *mut RdaClient,
    data: *const u8,
    len: usize,
    pts_us: u64,
    is_keyframe: bool,
    temporal_layer: u8,
    now_ms: u64,
) -> RdaStatus {
    clear_last_error();
    // SAFETY: the caller guarantees a live handle.
    let Some(client) = (unsafe { client(handle) }) else {
        return RDA_ERR_NULL_ARGUMENT;
    };
    if data.is_null() || len == 0 {
        set_last_error("frame data was null or empty");
        return RDA_ERR_NULL_ARGUMENT;
    }
    // A frame larger than this is not something the encoder produced; refuse it rather than
    // allocating whatever a caller asks for.
    if len > 64 * 1024 * 1024 {
        set_last_error(format!("frame of {len} bytes is implausibly large"));
        return RDA_ERR_INVALID_ARGUMENT;
    }

    // SAFETY: the caller guarantees `len` readable bytes at `data`.
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    let frame = EncodedFrame {
        data: bytes.to_vec(),
        kind: if is_keyframe {
            rda_encode::FrameKind::Keyframe
        } else {
            rda_encode::FrameKind::Delta
        },
        pts_us,
        sequence: 0,
        temporal_layer,
        ltr_index: None,
        qp: None,
    };

    if client.jitter.push(frame, now_ms) {
        RDA_OK
    } else {
        // Rejection is routine — a late or reordered frame — so it is not an error code.
        RDA_OK
    }
}

/// Advances playout and decodes at most one frame.
///
/// Returns [`RDA_OK`] when a new frame is ready, or [`RDA_ERR_NO_FRAME`] when nothing is due yet.
/// The latter is the common case at 60 fps against a 30 fps stream and must not be treated as an
/// error by the caller.
///
/// # Safety
///
/// `handle` must be a live client.
#[no_mangle]
pub unsafe extern "C" fn rda_client_poll_frame(handle: *mut RdaClient, now_ms: u64) -> RdaStatus {
    clear_last_error();
    // SAFETY: the caller guarantees a live handle.
    let Some(client) = (unsafe { client(handle) }) else {
        return RDA_ERR_NULL_ARGUMENT;
    };

    let PlayoutDecision::Play(frame) = client.jitter.poll(now_ms) else {
        return RDA_ERR_NO_FRAME;
    };

    let is_keyframe = frame.kind.is_random_access_point();
    match client
        .decoder
        .decode(&frame.data, frame.pts_us, is_keyframe)
    {
        Ok(mut decoded) => match decoded.pop() {
            Some(picture) => {
                client.current = Some(picture);
                client.frames_rendered += 1;
                client.telemetry.frames.decoded += 1;
                RDA_OK
            }
            None => RDA_ERR_NO_FRAME,
        },
        Err(e) => {
            client.telemetry.frames.dropped += 1;
            if e.wants_keyframe() {
                client.keyframe_requests += 1;
            }
            set_last_error(format!("decode failed: {e}"));
            RDA_ERR_DECODE
        }
    }
}

/// Whether the client wants the sender to emit a keyframe.
///
/// Reading this clears the flag. The caller is expected to translate it into a `RequestKeyframe`
/// control frame — which the rate controller may answer with a cheap LTR recovery rather than a
/// full IDR (`docs/ARCHITECTURE.md` §2.2).
///
/// # Safety
///
/// `handle` must be a live client.
#[no_mangle]
pub unsafe extern "C" fn rda_client_take_keyframe_request(handle: *mut RdaClient) -> bool {
    // SAFETY: the caller guarantees a live handle.
    let Some(client) = (unsafe { client(handle) }) else {
        return false;
    };
    let wanted = client.keyframe_requests > 0;
    client.keyframe_requests = 0;
    wanted
}

/// Width of the current frame in pixels, or zero if there is none.
///
/// # Safety
///
/// `handle` must be a live client.
#[no_mangle]
pub unsafe extern "C" fn rda_client_frame_width(handle: *mut RdaClient) -> u32 {
    // SAFETY: the caller guarantees a live handle.
    unsafe { client(handle) }
        .and_then(|c| c.current.as_ref())
        .map_or(0, |f| f.width)
}

/// Height of the current frame in pixels, or zero if there is none.
///
/// # Safety
///
/// `handle` must be a live client.
#[no_mangle]
pub unsafe extern "C" fn rda_client_frame_height(handle: *mut RdaClient) -> u32 {
    // SAFETY: the caller guarantees a live handle.
    unsafe { client(handle) }
        .and_then(|c| c.current.as_ref())
        .map_or(0, |f| f.height)
}

/// Bytes per row of the current frame, which may exceed `width * 4`.
///
/// Ignoring this and assuming a tight stride shears the image diagonally.
///
/// # Safety
///
/// `handle` must be a live client.
#[no_mangle]
pub unsafe extern "C" fn rda_client_frame_stride(handle: *mut RdaClient) -> usize {
    // SAFETY: the caller guarantees a live handle.
    unsafe { client(handle) }
        .and_then(|c| c.current.as_ref())
        .map_or(0, |f| f.stride)
}

/// Borrows the current frame's BGRA pixels, or returns null if there is none.
///
/// **The pointer is valid only until the next [`rda_client_poll_frame`] on this client.** It is
/// borrowed, not transferred: the caller must not free it, and must upload or copy before polling
/// again. That constraint is what lets the render path avoid a copy per frame.
///
/// # Safety
///
/// `handle` must be a live client. The returned pointer must not outlive the next `poll_frame`.
#[no_mangle]
pub unsafe extern "C" fn rda_client_frame_data(handle: *mut RdaClient) -> *const u8 {
    // SAFETY: the caller guarantees a live handle.
    let Some(client) = (unsafe { client(handle) }) else {
        return std::ptr::null();
    };
    match &client.current {
        // Re-check consistency at the boundary: a short buffer handed to a texture upload is an
        // out-of-bounds read in someone else's process.
        Some(frame) if frame.is_consistent() => frame.data.as_ptr(),
        Some(_) => {
            set_last_error("current frame failed its geometry check");
            std::ptr::null()
        }
        None => std::ptr::null(),
    }
}

/// Size of the current frame's pixel buffer in bytes.
///
/// # Safety
///
/// `handle` must be a live client.
#[no_mangle]
pub unsafe extern "C" fn rda_client_frame_len(handle: *mut RdaClient) -> usize {
    // SAFETY: the caller guarantees a live handle.
    unsafe { client(handle) }
        .and_then(|c| c.current.as_ref())
        .map_or(0, |f| f.data.len())
}

/// Live telemetry, for the status bar.
///
/// A plain struct rather than accessors so the whole snapshot crosses the boundary in one call —
/// eight FFI calls per frame to render a status line would be its own performance problem.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RdaTelemetry {
    /// Smoothed round-trip time in milliseconds.
    pub rtt_ms: u32,
    /// Packet loss in parts per thousand.
    pub loss_permille: u16,
    /// Jitter buffer target in milliseconds.
    pub playout_delay_ms: u32,
    /// Bandwidth estimate in bits per second.
    pub bwe_bps: u32,
    /// Frames displayed.
    pub frames_rendered: u64,
    /// Frames the jitter buffer discarded as too late.
    pub frames_dropped: u64,
    /// Whether media is traversing a TURN relay rather than a direct path.
    pub relayed: bool,
}

/// Reads current telemetry.
///
/// # Safety
///
/// `handle` must be a live client and `out` must point at a writable [`RdaTelemetry`].
#[no_mangle]
pub unsafe extern "C" fn rda_client_telemetry(
    handle: *mut RdaClient,
    out: *mut RdaTelemetry,
) -> RdaStatus {
    clear_last_error();
    // SAFETY: the caller guarantees a live handle.
    let Some(client) = (unsafe { client(handle) }) else {
        return RDA_ERR_NULL_ARGUMENT;
    };
    if out.is_null() {
        set_last_error("telemetry output pointer was null");
        return RDA_ERR_NULL_ARGUMENT;
    }

    let jitter = client.jitter.stats();
    let snapshot = RdaTelemetry {
        rtt_ms: client.telemetry.rtt.smoothed_ms().unwrap_or(0),
        loss_permille: client.telemetry.loss.permille(),
        playout_delay_ms: client.jitter.target_ms(),
        bwe_bps: client.telemetry.bwe_bps,
        frames_rendered: client.frames_rendered,
        frames_dropped: jitter.dropped_late + jitter.dropped_overflow,
        relayed: client.telemetry.relayed,
    };

    // SAFETY: the caller guarantees `out` points at a writable `RdaTelemetry`.
    unsafe {
        std::ptr::write(out, snapshot);
    }
    RDA_OK
}

/// Feeds transport statistics in, so the status bar reflects the real link.
///
/// # Safety
///
/// `handle` must be a live client.
#[no_mangle]
pub unsafe extern "C" fn rda_client_update_link(
    handle: *mut RdaClient,
    rtt_ms: u32,
    loss_permille: u16,
    bwe_bps: u32,
    relayed: bool,
    now_ms: u64,
) -> RdaStatus {
    clear_last_error();
    // SAFETY: the caller guarantees a live handle.
    let Some(client) = (unsafe { client(handle) }) else {
        return RDA_ERR_NULL_ARGUMENT;
    };
    if loss_permille > 1000 {
        set_last_error("loss must be expressed in parts per thousand");
        return RDA_ERR_INVALID_ARGUMENT;
    }

    if rtt_ms > 0 {
        client.telemetry.rtt.sample(rtt_ms, now_ms);
    }
    client.telemetry.loss.sample(
        1000 - u32::from(loss_permille),
        u32::from(loss_permille),
        now_ms,
    );
    client.telemetry.bwe_bps = bwe_bps;
    client.telemetry.relayed = relayed;
    RDA_OK
}

/// Clears decoder and buffer state after an unrecoverable loss.
///
/// # Safety
///
/// `handle` must be a live client.
#[no_mangle]
pub unsafe extern "C" fn rda_client_reset(handle: *mut RdaClient) -> RdaStatus {
    clear_last_error();
    // SAFETY: the caller guarantees a live handle.
    let Some(client) = (unsafe { client(handle) }) else {
        return RDA_ERR_NULL_ARGUMENT;
    };
    client.decoder.reset();
    client.jitter.reset();
    client.current = None;
    client.keyframe_requests += 1;
    RDA_OK
}

/// Whether this client is decoding on hardware.
///
/// # Safety
///
/// `handle` must be a live client.
#[no_mangle]
pub unsafe extern "C" fn rda_client_is_hardware(handle: *mut RdaClient) -> bool {
    // SAFETY: the caller guarantees a live handle.
    unsafe { client(handle) }.is_some_and(|c| c.decoder.is_hardware())
}

/// Reserved for a future zero-copy texture path. Currently always null.
///
/// Declared now so the Dart binding's shape does not change when the platform texture path lands.
///
/// # Safety
///
/// `handle` must be a live client.
#[no_mangle]
pub unsafe extern "C" fn rda_client_native_texture(handle: *mut RdaClient) -> *mut c_void {
    let _ = handle;
    std::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// Builds a client, or skips the test where no hardware decoder exists.
    fn client_or_skip() -> Option<*mut RdaClient> {
        let handle = rda_client_create();
        if handle.is_null() {
            eprintln!("skipping: no hardware decoder available");
            return None;
        }
        Some(handle)
    }

    /// Encodes one real keyframe, for the tests that need a decodable bitstream.
    fn keyframe() -> Option<Vec<u8>> {
        use rda_encode::convert::{bgra_to_planar, ConvertConfig, PlanarFormat};
        use rda_encode::EncoderConfig;

        let (w, h) = (320u32, 240u32);
        let config = EncoderConfig {
            width: w,
            height: h,
            fps: 30,
            ..Default::default()
        };
        let mut encoder = rda_encode::backend::hardware_encoder(config).ok()?;
        let src = vec![128u8; (w * h * 4) as usize];
        let planar = bgra_to_planar(
            &src,
            w,
            h,
            w as usize * 4,
            PlanarFormat::Nv12,
            ConvertConfig::default(),
        )
        .ok()?;
        encoder
            .encode(&planar, 0)
            .ok()?
            .first()
            .map(|f| f.data.clone())
    }

    // --- null safety -------------------------------------------------------------------------

    #[test]
    fn every_entry_point_tolerates_a_null_handle() {
        // Dart passes null after a hot restart. Dereferencing it would crash the whole app.
        let null = std::ptr::null_mut();
        // SAFETY: null is explicitly permitted by the contract.
        unsafe {
            assert_eq!(
                rda_client_set_peer(null, std::ptr::null()),
                RDA_ERR_NULL_ARGUMENT
            );
            assert_eq!(
                rda_client_submit_frame(null, std::ptr::null(), 0, 0, false, 0, 0),
                RDA_ERR_NULL_ARGUMENT
            );
            assert_eq!(rda_client_poll_frame(null, 0), RDA_ERR_NULL_ARGUMENT);
            assert_eq!(
                rda_client_telemetry(null, std::ptr::null_mut()),
                RDA_ERR_NULL_ARGUMENT
            );
            assert_eq!(rda_client_reset(null), RDA_ERR_NULL_ARGUMENT);
            assert_eq!(
                rda_client_update_link(null, 0, 0, 0, false, 0),
                RDA_ERR_NULL_ARGUMENT
            );
            assert_eq!(rda_client_frame_width(null), 0);
            assert_eq!(rda_client_frame_height(null), 0);
            assert_eq!(rda_client_frame_stride(null), 0);
            assert_eq!(rda_client_frame_len(null), 0);
            assert!(rda_client_frame_data(null).is_null());
            assert!(!rda_client_is_hardware(null));
            assert!(!rda_client_take_keyframe_request(null));
            assert!(rda_client_native_texture(null).is_null());
            // Destroying null must be a no-op, not a crash.
            rda_client_destroy(null);
        }
    }

    #[test]
    fn a_client_can_be_created_and_destroyed() {
        let Some(handle) = client_or_skip() else {
            return;
        };
        // SAFETY: the handle came from `rda_client_create`.
        unsafe {
            assert!(rda_client_is_hardware(handle));
            rda_client_destroy(handle);
        }
    }

    // --- arguments ---------------------------------------------------------------------------

    #[test]
    fn a_malformed_device_id_is_refused_with_an_explanation() {
        let Some(handle) = client_or_skip() else {
            return;
        };
        let bad = CString::new("not-a-device-id-at-all").unwrap();
        // SAFETY: live handle, valid nul-terminated string.
        unsafe {
            assert_eq!(
                rda_client_set_peer(handle, bad.as_ptr()),
                RDA_ERR_INVALID_ARGUMENT
            );
            assert!(
                !crate::rda_last_error().is_null(),
                "the caller must learn why"
            );

            let good = CString::new("K7M2-9QXR-4TVB").unwrap();
            assert_eq!(rda_client_set_peer(handle, good.as_ptr()), RDA_OK);
            rda_client_destroy(handle);
        }
    }

    #[test]
    fn an_implausibly_large_frame_is_refused_before_allocating() {
        let Some(handle) = client_or_skip() else {
            return;
        };
        let byte = 0u8;
        // SAFETY: the length is a lie, but the function must reject it before reading anything.
        unsafe {
            assert_eq!(
                rda_client_submit_frame(handle, &byte, usize::MAX, 0, true, 0, 0),
                RDA_ERR_INVALID_ARGUMENT
            );
            rda_client_destroy(handle);
        }
    }

    #[test]
    fn out_of_range_loss_is_refused() {
        let Some(handle) = client_or_skip() else {
            return;
        };
        // SAFETY: live handle.
        unsafe {
            assert_eq!(
                rda_client_update_link(handle, 220, 5000, 1_000_000, false, 0),
                RDA_ERR_INVALID_ARGUMENT
            );
            assert_eq!(
                rda_client_update_link(handle, 220, 50, 1_000_000, false, 0),
                RDA_OK
            );
            rda_client_destroy(handle);
        }
    }

    // --- the frame path ----------------------------------------------------------------------

    #[test]
    fn polling_an_empty_client_reports_no_frame_rather_than_failing() {
        // At 60 fps against a 30 fps stream this is the common case, every other tick.
        let Some(handle) = client_or_skip() else {
            return;
        };
        // SAFETY: live handle.
        unsafe {
            assert_eq!(rda_client_poll_frame(handle, 0), RDA_ERR_NO_FRAME);
            assert!(rda_client_frame_data(handle).is_null());
            rda_client_destroy(handle);
        }
    }

    #[test]
    fn a_real_keyframe_flows_through_to_borrowable_pixels() {
        let Some(handle) = client_or_skip() else {
            return;
        };
        let Some(bitstream) = keyframe() else {
            // SAFETY: live handle.
            unsafe { rda_client_destroy(handle) };
            eprintln!("skipping: no hardware encoder to produce a bitstream");
            return;
        };

        // SAFETY: live handle; the bitstream slice outlives the call.
        unsafe {
            assert_eq!(
                rda_client_submit_frame(
                    handle,
                    bitstream.as_ptr(),
                    bitstream.len(),
                    0,
                    true,
                    0,
                    1_000
                ),
                RDA_OK
            );

            // Poll past the jitter buffer's target delay.
            let mut status = RDA_ERR_NO_FRAME;
            for step in 0..40u64 {
                status = rda_client_poll_frame(handle, 1_000 + step * 10);
                if status == RDA_OK {
                    break;
                }
            }
            assert_eq!(
                status, RDA_OK,
                "a submitted keyframe must eventually decode"
            );

            let width = rda_client_frame_width(handle);
            let height = rda_client_frame_height(handle);
            let stride = rda_client_frame_stride(handle);
            let len = rda_client_frame_len(handle);
            let data = rda_client_frame_data(handle);

            assert_eq!(width, 320);
            assert_eq!(height, 240);
            assert!(
                stride >= width as usize * 4,
                "stride below one row of pixels"
            );
            assert!(
                len >= stride * height as usize,
                "buffer shorter than its geometry"
            );
            assert!(
                !data.is_null(),
                "pixels must be borrowable for the texture upload"
            );

            rda_client_destroy(handle);
        }
    }

    #[test]
    fn telemetry_round_trips_through_the_boundary() {
        let Some(handle) = client_or_skip() else {
            return;
        };
        let mut out = RdaTelemetry::default();
        // SAFETY: live handle and a writable output struct.
        unsafe {
            assert_eq!(
                rda_client_update_link(handle, 220, 35, 4_000_000, true, 1_000),
                RDA_OK
            );
            assert_eq!(rda_client_telemetry(handle, &mut out), RDA_OK);

            assert_eq!(out.rtt_ms, 220);
            assert_eq!(out.loss_permille, 35);
            assert_eq!(out.bwe_bps, 4_000_000);
            assert!(out.relayed);
            assert!(
                out.playout_delay_ms > 0,
                "the buffer always targets some delay"
            );

            rda_client_destroy(handle);
        }
    }

    #[test]
    fn a_reset_asks_for_a_keyframe() {
        // After an unrecoverable loss the client has no decodable state, so it must say so rather
        // than waiting silently for a keyframe that nobody will send.
        let Some(handle) = client_or_skip() else {
            return;
        };
        // SAFETY: live handle.
        unsafe {
            assert_eq!(rda_client_reset(handle), RDA_OK);
            assert!(rda_client_take_keyframe_request(handle));
            assert!(
                !rda_client_take_keyframe_request(handle),
                "reading must clear the flag"
            );
            rda_client_destroy(handle);
        }
    }

    #[test]
    fn creating_and_destroying_repeatedly_does_not_leak_handles() {
        // A Flutter hot restart does exactly this.
        for _ in 0..20 {
            let handle = rda_client_create();
            if handle.is_null() {
                return;
            }
            // SAFETY: each handle is destroyed exactly once.
            unsafe { rda_client_destroy(handle) };
        }
    }
}
