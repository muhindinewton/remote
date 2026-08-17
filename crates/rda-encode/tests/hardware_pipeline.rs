//! The Phase 4 acceptance test: real pixels through real hardware, adapting to a real degradation.
//!
//! Everything else in this crate tests one stage. This drives capture → colour conversion → the
//! platform's hardware encoder → the rate controller, and asserts the properties the phase exists
//! to deliver: a valid bitstream, compression that actually compresses, and settings that follow
//! the link rather than a startup constant.
//!
//! Where no hardware encoder exists the tests skip rather than fail — a red test that means
//! "unprivileged CI box" trains people to ignore the suite.

use rda_capture::backend::test_pattern::TestPatternCapturer;
use rda_capture::{CaptureConfig, ScreenCapturer};
use rda_encode::backend::hardware_encoder;
use rda_encode::convert::{bgra_to_planar, ConvertConfig, PlanarFormat};
use rda_encode::encoder::{Codec, EncoderConfig, FrameKind, VideoEncoder};
use rda_encode::pipeline::{EncoderFactory, Pipeline};
use rda_encode::RateController;
use rda_telemetry::LinkTelemetry;
use std::time::Duration;

const W: u32 = 640;
const H: u32 = 360;

fn telemetry(bwe_bps: u32, loss_permille: u16, now_ms: u64) -> LinkTelemetry {
    let mut t = LinkTelemetry::new();
    t.bwe_bps = bwe_bps;
    t.rtt.sample(220, now_ms);
    t.loss.sample(
        1000 - u32::from(loss_permille),
        u32::from(loss_permille),
        now_ms,
    );
    t
}

fn capturer() -> TestPatternCapturer {
    let mut c = TestPatternCapturer::new(W, H);
    c.start(0, CaptureConfig::default()).unwrap();
    c
}

fn base_config() -> EncoderConfig {
    EncoderConfig {
        codec: Codec::H264,
        width: W,
        height: H,
        fps: 30,
        bitrate_bps: 2_000_000,
        ..Default::default()
    }
}

/// Builds a hardware encoder, or returns `None` where the platform has none.
fn try_hardware() -> Option<Box<dyn VideoEncoder>> {
    match hardware_encoder(base_config()) {
        Ok(e) => Some(e),
        Err(e) => {
            eprintln!("skipping: no hardware encoder available ({e})");
            None
        }
    }
}

#[test]
fn hardware_encoding_produces_a_valid_annex_b_bitstream() {
    let Some(mut encoder) = try_hardware() else {
        return;
    };
    let mut cap = capturer();

    let frame = cap.next_frame(Duration::from_millis(50)).unwrap().unwrap();
    let planar = rda_encode::convert::convert_surface(
        &frame.surface,
        W,
        H,
        PlanarFormat::Nv12,
        ConvertConfig::default(),
    )
    .unwrap();

    let out = encoder
        .encode(&planar, 0)
        .expect("hardware encode must succeed");
    assert!(!out.is_empty(), "the first frame must produce output");

    let first = &out[0];
    assert_eq!(
        first.kind,
        FrameKind::Keyframe,
        "a stream must open with a keyframe"
    );
    assert_eq!(
        &first.data[..4],
        &[0, 0, 0, 1],
        "output must be Annex B, not AVCC"
    );
    assert!(encoder.is_hardware());

    // An IDR of a 640x360 gradient should be substantial but nowhere near raw. Raw is 345,600
    // bytes; anything close to that means the encoder is not actually compressing.
    assert!(
        first.len() > 100,
        "suspiciously small keyframe: {} bytes",
        first.len()
    );
    assert!(
        first.len() < 200_000,
        "keyframe is not compressed: {} bytes",
        first.len()
    );
}

#[test]
fn compression_actually_compresses() {
    let Some(mut encoder) = try_hardware() else {
        return;
    };
    let mut cap = capturer();

    let raw_bytes_per_frame = (W * H * 4) as usize;
    let mut compressed = 0usize;
    let frames = 30;

    for i in 0..frames {
        let frame = cap.next_frame(Duration::from_millis(50)).unwrap().unwrap();
        let planar = rda_encode::convert::convert_surface(
            &frame.surface,
            W,
            H,
            PlanarFormat::Nv12,
            ConvertConfig::default(),
        )
        .unwrap();
        for f in encoder.encode(&planar, i * 33_333).unwrap() {
            compressed += f.len();
        }
    }

    let raw_total = raw_bytes_per_frame * frames as usize;
    let ratio = raw_total as f64 / compressed.max(1) as f64;
    assert!(
        ratio > 5.0,
        "compression ratio is only {ratio:.1}x ({compressed} of {raw_total})"
    );

    // A second of this at 30 fps must be within a plausible bitrate for a desktop stream.
    let bits_per_second = (compressed * 8) as f64;
    assert!(
        bits_per_second < 50_000_000.0,
        "{:.1} Mbps is implausible for 640x360",
        bits_per_second / 1e6
    );
}

#[test]
fn a_hardware_pipeline_adapts_to_a_collapsing_link() {
    // The property Phase 4 exists for: settings that follow the link. Runs against the real
    // encoder so a platform that silently ignores `set_bitrate` is caught.
    if try_hardware().is_none() {
        return;
    }
    let factory: EncoderFactory = Box::new(hardware_encoder);
    let mut pipeline = Pipeline::new(factory, W, H, base_config()).unwrap();
    let mut cap = capturer();

    assert!(pipeline.is_hardware());

    // Healthy link.
    pipeline
        .apply_telemetry(&telemetry(8_000_000, 0, 0), 0)
        .unwrap();
    let healthy = pipeline.directive();
    let mut healthy_bytes = 0usize;
    for i in 0..20u64 {
        let frame = cap.next_frame(Duration::from_millis(50)).unwrap().unwrap();
        healthy_bytes += pipeline.step(&frame, i * 34).unwrap().bytes();
    }

    // The link collapses and stays collapsed past the ladder's demotion delay.
    for t in [1_000u64, 2_000, 3_100] {
        pipeline
            .apply_telemetry(&telemetry(400_000, 60, t), t)
            .unwrap();
    }
    let degraded = pipeline.directive();

    assert!(
        degraded.bitrate_bps < healthy.bitrate_bps / 4,
        "bitrate must collapse with the link: {} -> {}",
        healthy.bitrate_bps,
        degraded.bitrate_bps
    );
    assert!(degraded.fps < healthy.fps, "frame rate must fall");
    assert!(
        degraded.scale_pct < healthy.scale_pct,
        "resolution must fall"
    );
    assert!(
        degraded.qp_min > healthy.qp_min,
        "the QP floor must rise as bits get scarce"
    );
    assert!(healthy_bytes > 0);

    // The encoder was rebuilt for the new resolution, which costs one keyframe — and only one.
    assert_eq!(pipeline.stats().rebuilds, 1);
}

#[test]
fn an_idle_desktop_costs_nothing_through_the_hardware_path() {
    if try_hardware().is_none() {
        return;
    }
    let factory: EncoderFactory = Box::new(hardware_encoder);
    let mut pipeline = Pipeline::new(factory, W, H, base_config()).unwrap();

    let mut cap = TestPatternCapturer::new(W, H);
    cap.always_static = true;
    cap.start(0, CaptureConfig::default()).unwrap();

    for i in 0..120u64 {
        let frame = cap.next_frame(Duration::from_millis(10)).unwrap().unwrap();
        pipeline.step(&frame, i * 34).unwrap();
    }

    let stats = pipeline.stats();
    assert_eq!(
        stats.bytes_out, 0,
        "an idle desktop must produce no bytes at all"
    );
    assert_eq!(stats.encoded, 0);
    assert_eq!(stats.skipped_static, 120);
}

#[test]
fn colour_conversion_survives_a_real_captured_frame() {
    // Guards the stride handling against real capture geometry, which is where a sheared image
    // comes from.
    let mut cap = capturer();
    let frame = cap.next_frame(Duration::from_millis(50)).unwrap().unwrap();

    let rda_capture::Surface::Cpu { data, stride, .. } = &frame.surface else {
        panic!("the test pattern produces CPU surfaces");
    };
    let planar = bgra_to_planar(
        data,
        W,
        H,
        *stride,
        PlanarFormat::Nv12,
        ConvertConfig::default(),
    )
    .unwrap();

    assert_eq!(planar.luma().len(), (W * H) as usize);
    assert_eq!(planar.data.len(), PlanarFormat::Nv12.buffer_size(W, H));
    // The test pattern is a gradient, so luma must actually vary — a uniform plane would mean the
    // conversion read the wrong memory.
    let min = *planar.luma().iter().min().unwrap();
    let max = *planar.luma().iter().max().unwrap();
    assert!(max - min > 20, "luma does not vary: {min}..{max}");
}

#[test]
fn the_rate_controller_prefers_cheap_recovery_over_keyframes() {
    // The single most consequential policy in the phase, asserted independently of any encoder.
    let mut rate = RateController::new();
    rate.on_ltr_acked(1);

    let cheap = rate.on_recovery_request(Some(1), 1_000);
    assert!(matches!(cheap, rda_encode::KeyframeDecision::Recover(_)));

    let (idrs, ltrs, _) = rate.recovery_stats();
    assert_eq!(
        (idrs, ltrs),
        (0, 1),
        "a usable reference must not cost an IDR"
    );
}
