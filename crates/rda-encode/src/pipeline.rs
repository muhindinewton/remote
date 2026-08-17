//! The frame pipeline: capture → convert → rate control → encode.
//!
//! Everything here is sequencing and policy. Two behaviours are the reason it is a type rather than
//! a loop written at the call site:
//!
//! **An unchanged frame costs nothing.** On a static desktop the pipeline stops at the damage
//! check — no conversion, no encode, no packet. On a 220 ms link that leaves the whole pipe free
//! for the burst when the user does act, and stops the bandwidth estimate decaying through
//! inactivity (`docs/ARCHITECTURE.md` §3.3).
//!
//! **A resolution change rebuilds the encoder, and rebuilds cost a keyframe.** The ladder can
//! change `scale_pct` on any frame; honouring that literally would rebuild the session — and emit
//! an IDR — several times a second during a bad patch. The pipeline therefore applies resolution
//! changes only when they are large enough to be worth the IDR, and applies bitrate changes
//! immediately, because those are free.

use crate::convert::{convert_surface, ConvertConfig, PlanarFormat};
use crate::encoder::{EncodeError, EncodedFrame, EncoderConfig, VideoEncoder};
use crate::rate::{EncoderDirective, KeyframeDecision, RateController};
use rda_capture::Frame;
use rda_telemetry::LinkTelemetry;
use tracing::{debug, info};

/// Minimum change in scale before the encoder is rebuilt, in percentage points.
///
/// Every rebuild costs an IDR — 15–30× a P frame — so reacting to every small ladder movement would
/// spend more bandwidth on keyframes than the resolution change saves.
pub const SCALE_CHANGE_THRESHOLD_PCT: u8 = 10;

/// What one pipeline step did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    /// Nothing changed on screen; the frame was dropped before conversion.
    Skipped,
    /// The frame was encoded.
    Encoded(Vec<EncodedFrame>),
    /// The frame was dropped to hold the target frame rate.
    Paced,
}

impl StepOutcome {
    /// The frames produced, if any.
    #[must_use]
    pub fn frames(&self) -> &[EncodedFrame] {
        match self {
            StepOutcome::Encoded(f) => f,
            _ => &[],
        }
    }

    /// Total bytes produced.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.frames().iter().map(EncodedFrame::len).sum()
    }
}

/// Cumulative pipeline counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PipelineStats {
    /// Frames offered by capture.
    pub offered: u64,
    /// Frames skipped because nothing changed.
    pub skipped_static: u64,
    /// Frames dropped to hold the target frame rate.
    pub paced_out: u64,
    /// Frames encoded.
    pub encoded: u64,
    /// Bytes of compressed output.
    pub bytes_out: u64,
    /// Encoder rebuilds caused by resolution changes.
    pub rebuilds: u64,
    /// Keyframes emitted.
    pub keyframes: u64,
}

impl PipelineStats {
    /// Mean compressed frame size, or zero before anything has been encoded.
    #[must_use]
    pub fn mean_frame_bytes(&self) -> u64 {
        self.bytes_out.checked_div(self.encoded).unwrap_or(0)
    }

    /// Fraction of offered frames that were actually encoded.
    #[must_use]
    pub fn encode_ratio(&self) -> f64 {
        if self.offered == 0 {
            0.0
        } else {
            self.encoded as f64 / self.offered as f64
        }
    }
}

/// How the pipeline builds encoders when the resolution changes.
pub type EncoderFactory =
    Box<dyn FnMut(EncoderConfig) -> Result<Box<dyn VideoEncoder>, EncodeError>>;

/// Drives one video stream.
pub struct Pipeline {
    encoder: Box<dyn VideoEncoder>,
    factory: EncoderFactory,
    rate: RateController,
    convert: ConvertConfig,
    native_width: u32,
    native_height: u32,
    directive: EncoderDirective,
    last_encode_ms: Option<u64>,
    stats: PipelineStats,
}

impl Pipeline {
    /// Builds a pipeline over an encoder factory.
    ///
    /// The factory rather than a single encoder because a resolution change requires a new session
    /// on every platform — the dimensions are fixed at creation.
    pub fn new(
        mut factory: EncoderFactory,
        native_width: u32,
        native_height: u32,
        base: EncoderConfig,
    ) -> Result<Self, EncodeError> {
        let encoder = factory(base)?;
        let rate = RateController::new();
        Ok(Self {
            directive: rate.current(),
            encoder,
            factory,
            rate,
            convert: ConvertConfig::default(),
            native_width,
            native_height,
            last_encode_ms: None,
            stats: PipelineStats::default(),
        })
    }

    /// Cumulative counters.
    #[must_use]
    pub fn stats(&self) -> PipelineStats {
        self.stats
    }

    /// The settings currently in force.
    #[must_use]
    pub fn directive(&self) -> EncoderDirective {
        self.directive
    }

    /// The active encoder's name, for diagnostics.
    #[must_use]
    pub fn encoder_name(&self) -> &'static str {
        self.encoder.name()
    }

    /// Whether encoding is running on dedicated hardware.
    #[must_use]
    pub fn is_hardware(&self) -> bool {
        self.encoder.is_hardware()
    }

    /// Records a receiver acknowledgement of a long-term reference.
    pub fn on_ltr_acked(&mut self, index: u8) {
        self.rate.on_ltr_acked(index);
    }

    /// Handles a receiver's recovery request.
    ///
    /// Returns what was decided so the caller can log it. A [`KeyframeDecision::Suppressed`] is a
    /// normal outcome during a loss episode, not an error.
    pub fn on_recovery_request(
        &mut self,
        receiver_ltr: Option<u8>,
        now_ms: u64,
    ) -> Result<KeyframeDecision, EncodeError> {
        let decision = self.rate.on_recovery_request(receiver_ltr, now_ms);
        match decision {
            KeyframeDecision::Recover(mode) => self.encoder.request_recovery(mode)?,
            KeyframeDecision::Idr => {
                self.encoder
                    .request_recovery(crate::encoder::RecoveryMode::Idr)?;
            }
            KeyframeDecision::Suppressed => {
                debug!("recovery request coalesced with the previous one");
            }
        }
        Ok(decision)
    }

    /// Folds telemetry into the encoder settings.
    ///
    /// Bitrate and frame rate are applied immediately — they are free. A resolution change rebuilds
    /// the session, so it waits for [`SCALE_CHANGE_THRESHOLD_PCT`].
    pub fn apply_telemetry(
        &mut self,
        telemetry: &LinkTelemetry,
        now_ms: u64,
    ) -> Result<(), EncodeError> {
        let next = self.rate.update(telemetry, now_ms);
        let previous = self.directive;
        self.directive = next;

        if next.bitrate_bps != previous.bitrate_bps {
            self.encoder.set_bitrate(next.bitrate_bps)?;
        }
        if next.fps != previous.fps {
            self.encoder.set_fps(next.fps)?;
        }

        if next.scale_pct.abs_diff(previous.scale_pct) >= SCALE_CHANGE_THRESHOLD_PCT {
            self.rebuild_for_scale(next)?;
        }
        Ok(())
    }

    fn rebuild_for_scale(&mut self, directive: EncoderDirective) -> Result<(), EncodeError> {
        let (w, h) = directive.scaled_dimensions(self.native_width, self.native_height);
        let current = self.encoder.config();
        if (w, h) == (current.width, current.height) {
            return Ok(());
        }

        let config = EncoderConfig {
            width: w,
            height: h,
            bitrate_bps: directive.bitrate_bps,
            fps: directive.fps,
            temporal_layers: directive.temporal_layers,
            ..current
        }
        .with_even_dimensions();

        info!(
            from = format!("{}x{}", current.width, current.height),
            to = format!("{w}x{h}"),
            "rebuilding encoder for a resolution change"
        );
        self.encoder = (self.factory)(config)?;
        self.stats.rebuilds += 1;
        Ok(())
    }

    /// Runs one captured frame through the pipeline.
    pub fn step(&mut self, frame: &Frame, now_ms: u64) -> Result<StepOutcome, EncodeError> {
        self.stats.offered += 1;

        // A static desktop stops here: no conversion, no encode, no packet.
        if !frame.is_worth_encoding() {
            self.stats.skipped_static += 1;
            return Ok(StepOutcome::Skipped);
        }

        // Hold the target frame rate. Encoding above it wastes CPU on frames the ladder has already
        // decided the link cannot carry.
        let min_interval = 1000 / u64::from(self.directive.fps.max(1));
        if let Some(last) = self.last_encode_ms {
            if now_ms.saturating_sub(last) < min_interval {
                self.stats.paced_out += 1;
                return Ok(StepOutcome::Paced);
            }
        }

        let config = self.encoder.config();
        let planar = convert_surface(
            &frame.surface,
            config.width,
            config.height,
            PlanarFormat::Nv12,
            self.convert,
        )
        .map_err(|e| EncodeError::Failed(format!("colour conversion failed: {e}")))?;

        let encoded = self.encoder.encode(&planar, now_ms * 1000)?;

        self.last_encode_ms = Some(now_ms);
        self.stats.encoded += 1;
        self.stats.bytes_out += encoded.iter().map(|f| f.len() as u64).sum::<u64>();
        self.stats.keyframes += encoded
            .iter()
            .filter(|f| f.kind == crate::encoder::FrameKind::Keyframe)
            .count() as u64;

        Ok(StepOutcome::Encoded(encoded))
    }

    /// Flushes anything the encoder still holds.
    pub fn flush(&mut self) -> Result<Vec<EncodedFrame>, EncodeError> {
        self.encoder.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::recording::RecordingEncoder;
    use crate::encoder::FrameKind;
    use rda_capture::backend::test_pattern::TestPatternCapturer;
    use rda_capture::{CaptureConfig, ScreenCapturer};

    fn factory() -> EncoderFactory {
        Box::new(|config| {
            RecordingEncoder::new(config).map(|e| Box::new(e) as Box<dyn VideoEncoder>)
        })
    }

    fn pipeline(w: u32, h: u32) -> Pipeline {
        Pipeline::new(
            factory(),
            w,
            h,
            EncoderConfig {
                width: w,
                height: h,
                fps: 60,
                ..Default::default()
            },
        )
        .unwrap()
    }

    fn capturer(w: u32, h: u32) -> TestPatternCapturer {
        let mut c = TestPatternCapturer::new(w, h);
        c.start(0, CaptureConfig::default()).unwrap();
        c
    }

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

    #[test]
    fn a_captured_frame_becomes_a_compressed_frame() {
        let mut p = pipeline(64, 64);
        let mut c = capturer(64, 64);
        let frame = c
            .next_frame(std::time::Duration::from_millis(10))
            .unwrap()
            .unwrap();

        let outcome = p.step(&frame, 0).unwrap();
        assert!(!outcome.frames().is_empty());
        assert_eq!(outcome.frames()[0].kind, FrameKind::Keyframe);
        assert!(outcome.bytes() > 0);
        assert_eq!(p.stats().encoded, 1);
    }

    #[test]
    fn an_unchanged_frame_never_reaches_the_encoder() {
        // The saving that makes an idle session free. If this regresses, an idle desktop silently
        // consumes full bitrate.
        let mut p = pipeline(64, 64);
        let mut c = TestPatternCapturer::new(64, 64);
        c.always_static = true;
        c.start(0, CaptureConfig::default()).unwrap();

        let frame = c
            .next_frame(std::time::Duration::from_millis(10))
            .unwrap()
            .unwrap();
        assert_eq!(p.step(&frame, 0).unwrap(), StepOutcome::Skipped);
        assert_eq!(p.stats().encoded, 0);
        assert_eq!(p.stats().skipped_static, 1);
        assert_eq!(p.stats().bytes_out, 0);
    }

    #[test]
    fn frames_above_the_target_rate_are_paced_out() {
        let mut p = pipeline(64, 64);
        let mut c = capturer(64, 64);

        // At 60 fps the interval is ~16 ms, so three frames 1 ms apart yield one encode.
        for (i, t) in [0u64, 1, 2].iter().enumerate() {
            let frame = c
                .next_frame(std::time::Duration::from_millis(10))
                .unwrap()
                .unwrap();
            let outcome = p.step(&frame, *t).unwrap();
            if i == 0 {
                assert!(matches!(outcome, StepOutcome::Encoded(_)));
            } else {
                assert_eq!(outcome, StepOutcome::Paced);
            }
        }
        assert_eq!(p.stats().encoded, 1);
        assert_eq!(p.stats().paced_out, 2);
    }

    #[test]
    fn bitrate_follows_telemetry_immediately() {
        let mut p = pipeline(64, 64);
        p.apply_telemetry(&telemetry(8_000_000, 0, 0), 0).unwrap();
        let high = p.directive().bitrate_bps;

        p.apply_telemetry(&telemetry(700_000, 0, 100), 100).unwrap();
        assert!(
            p.directive().bitrate_bps < high / 4,
            "the cut must land at once"
        );
    }

    #[test]
    fn a_small_scale_change_does_not_rebuild_the_encoder() {
        // Every rebuild costs an IDR, so reacting to every ladder twitch would spend more on
        // keyframes than the resolution change saves.
        let mut p = pipeline(1920, 1080);
        p.apply_telemetry(&telemetry(10_000_000, 0, 0), 0).unwrap();
        let before = p.stats().rebuilds;

        // Rung 0 -> 1 keeps scale at 100%.
        p.apply_telemetry(&telemetry(5_000_000, 0, 3_000), 3_000)
            .unwrap();
        assert_eq!(p.stats().rebuilds, before);
    }

    #[test]
    fn a_large_scale_change_rebuilds_the_encoder() {
        let mut p = pipeline(1920, 1080);
        p.apply_telemetry(&telemetry(10_000_000, 0, 0), 0).unwrap();
        assert_eq!(p.directive().scale_pct, 100);

        // Sustained collapse drives the ladder down past the threshold.
        p.apply_telemetry(&telemetry(500_000, 0, 100), 100).unwrap();
        p.apply_telemetry(&telemetry(500_000, 0, 3_000), 3_000)
            .unwrap();

        assert!(p.directive().scale_pct <= 50);
        assert_eq!(p.stats().rebuilds, 1);
    }

    #[test]
    fn an_acknowledged_reference_avoids_a_keyframe() {
        let mut p = pipeline(64, 64);
        p.on_ltr_acked(2);
        let decision = p.on_recovery_request(Some(2), 1_000).unwrap();
        assert!(matches!(decision, KeyframeDecision::Recover(_)));

        let mut c = capturer(64, 64);
        let frame = c
            .next_frame(std::time::Duration::from_millis(10))
            .unwrap()
            .unwrap();
        let out = p.step(&frame, 1_000).unwrap();
        assert_eq!(out.frames()[0].kind, FrameKind::LtrRecovery);
    }

    #[test]
    fn recovery_requests_are_coalesced() {
        let mut p = pipeline(64, 64);
        assert_eq!(
            p.on_recovery_request(None, 1_000).unwrap(),
            KeyframeDecision::Idr
        );
        assert_eq!(
            p.on_recovery_request(None, 1_100).unwrap(),
            KeyframeDecision::Suppressed
        );
    }

    #[test]
    fn an_idle_session_produces_no_bytes_over_many_frames() {
        // The end-to-end statement of the idle case, over a realistic number of frames.
        let mut p = pipeline(64, 64);
        let mut c = TestPatternCapturer::new(64, 64);
        c.always_static = true;
        c.start(0, CaptureConfig::default()).unwrap();

        for i in 0..300u64 {
            let frame = c
                .next_frame(std::time::Duration::from_millis(1))
                .unwrap()
                .unwrap();
            p.step(&frame, i * 16).unwrap();
        }
        assert_eq!(p.stats().bytes_out, 0);
        assert_eq!(p.stats().offered, 300);
        assert_eq!(p.stats().encode_ratio(), 0.0);
    }

    #[test]
    fn a_busy_session_produces_a_plausible_bitrate() {
        let mut p = pipeline(64, 64);
        let mut c = capturer(64, 64);
        p.apply_telemetry(&telemetry(2_000_000, 0, 0), 0).unwrap();

        // One second at 60 fps.
        for i in 0..60u64 {
            let frame = c
                .next_frame(std::time::Duration::from_millis(1))
                .unwrap()
                .unwrap();
            p.step(&frame, i * 17).unwrap();
        }

        let s = p.stats();
        assert!(s.encoded > 50, "only {} frames encoded", s.encoded);
        assert_eq!(
            s.keyframes, 1,
            "steady state must contain exactly one keyframe"
        );
        assert!(s.mean_frame_bytes() > 0);
        assert!(s.encode_ratio() > 0.8);
    }

    #[test]
    fn stats_account_for_every_offered_frame() {
        let mut p = pipeline(64, 64);
        let mut c = capturer(64, 64);
        for i in 0..40u64 {
            let frame = c
                .next_frame(std::time::Duration::from_millis(1))
                .unwrap()
                .unwrap();
            p.step(&frame, i).unwrap();
        }
        let s = p.stats();
        assert_eq!(s.offered, s.encoded + s.paced_out + s.skipped_static);
    }
}
