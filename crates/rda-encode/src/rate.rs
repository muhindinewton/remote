//! Adaptive bitrate control — `docs/ARCHITECTURE.md` §2.6, §2.7, §2.9.
//!
//! The control loop that turns a bandwidth estimate into encoder settings. Four rules shape it,
//! and every one of them exists because of the 220 ms path:
//!
//! **Cut immediately, recover slowly.** A rate cut has to land within one frame; a promotion can
//! wait ten seconds. The asymmetry is deliberate — degrading late is far more visible than
//! upgrading late, and on this path a spurious promotion costs several seconds of loss to undo.
//!
//! **FEC comes out of the video budget, not on top of it.** At 10% loss the FEC schedule adds ~35%
//! overhead. Sizing video at the full estimate and then adding FEC means exceeding the link by a
//! third *exactly when it is already failing*. [`RateController`] divides instead.
//!
//! **Bitrate and resolution move together.** Halving the bitrate without cutting resolution just
//! raises QP until the picture turns to mush; text becomes unreadable long before motion does. The
//! ladder cuts pixels and frames as well as bits.
//!
//! **An IDR is a budgeted event.** When one is unavoidable, the controller halves the target for
//! its duration so the burst is absorbed rather than dumped into a link that is already congested.

use crate::encoder::RecoveryMode;
use rda_telemetry::{fec_schedule, LadderController, LadderRung, LinkTelemetry};

/// Fraction of the bandwidth estimate video may claim.
///
/// The remainder covers audio, the control and input channels, RTCP, and headroom. Sending at
/// 100% of the estimate guarantees queueing, and queue depth is latency (§2.7).
pub const VIDEO_SHARE: f64 = 0.85;

/// Floor below which video is not worth sending at all.
pub const MIN_BITRATE_BPS: u32 = 120_000;

/// Ceiling, to stop a wildly optimistic estimate from saturating a link.
pub const MAX_BITRATE_BPS: u32 = 25_000_000;

/// Minimum interval between honoured IDR requests.
pub const IDR_MIN_INTERVAL_MS: u64 = 1_000;

/// How long the bitrate stays halved after an IDR, so the burst is paced rather than dumped.
pub const IDR_BUDGET_MS: u64 = 200;

/// What the encoder should be doing right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderDirective {
    /// Target bitrate in bits per second, already net of FEC overhead.
    pub bitrate_bps: u32,
    /// Target frame rate.
    pub fps: u8,
    /// Resolution scale as a percentage of native.
    pub scale_pct: u8,
    /// Number of temporal layers.
    pub temporal_layers: u8,
    /// Lowest permitted quantisation parameter. Lower means better quality and more bits.
    pub qp_min: u8,
    /// Highest permitted quantisation parameter.
    pub qp_max: u8,
    /// Whether video has collapsed to periodic stills, with input and control still alive.
    pub stills_only: bool,
    /// Which ladder rung this came from.
    pub rung: u8,
}

impl EncoderDirective {
    /// Encoded dimensions for a native size, rounded to even values for 4:2:0.
    #[must_use]
    pub fn scaled_dimensions(&self, native_w: u32, native_h: u32) -> (u32, u32) {
        let w = (u64::from(native_w) * u64::from(self.scale_pct) / 100) as u32;
        let h = (u64::from(native_h) * u64::from(self.scale_pct) / 100) as u32;
        ((w & !1).max(16), (h & !1).max(16))
    }

    /// Approximate bits available per frame at this directive.
    #[must_use]
    pub fn bits_per_frame(&self) -> u32 {
        self.bitrate_bps / u32::from(self.fps.max(1))
    }
}

/// Whether a keyframe request should be honoured, and how.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyframeDecision {
    /// Emit a recovery frame against a long-term reference. Cheap.
    Recover(RecoveryMode),
    /// Emit a full IDR, and pace it.
    Idr,
    /// Refuse. A request arrived inside the rate-limit window and was coalesced with the last one.
    ///
    /// Refusing matters: a receiver that keeps asking during a loss episode would otherwise drive
    /// exactly the IDR storm that caused the loss.
    Suppressed,
}

/// Turns link telemetry into encoder settings.
#[derive(Debug, Clone)]
pub struct RateController {
    ladder: LadderController,
    last_idr_ms: Option<u64>,
    idr_budget_until_ms: u64,
    current: EncoderDirective,
    /// Highest acknowledged long-term reference, from `LtrAck` on the control channel.
    acked_ltr: Option<u8>,
    idr_count: u64,
    ltr_recovery_count: u64,
    suppressed_count: u64,
}

impl Default for RateController {
    fn default() -> Self {
        Self::new()
    }
}

impl RateController {
    /// A controller starting at full quality.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ladder: LadderController::new(),
            last_idr_ms: None,
            idr_budget_until_ms: 0,
            current: directive_for(rda_telemetry::LADDER[0], 4_000_000, 0.0),
            acked_ltr: None,
            idr_count: 0,
            ltr_recovery_count: 0,
            suppressed_count: 0,
        }
    }

    /// Records that the receiver acknowledged decoding a long-term reference.
    ///
    /// The encoder must not *rely* on an LTR until this arrives: recovering against a reference the
    /// receiver never got produces a frame it still cannot decode, and costs another round trip to
    /// discover (§9.4).
    pub fn on_ltr_acked(&mut self, index: u8) {
        self.acked_ltr = Some(index);
    }

    /// The last acknowledged reference, if any.
    #[must_use]
    pub fn acked_ltr(&self) -> Option<u8> {
        self.acked_ltr
    }

    /// Folds in the latest telemetry and returns the settings to apply.
    ///
    /// Called every frame. The ladder supplies hysteresis so a flapping estimate does not
    /// oscillate the picture.
    pub fn update(&mut self, telemetry: &LinkTelemetry, now_ms: u64) -> EncoderDirective {
        let loss = telemetry.loss.fraction();
        let rung = self.ladder.update(telemetry.bwe_bps, loss, now_ms);

        // Video's share of the estimate...
        let mut budget = (f64::from(telemetry.bwe_bps) * VIDEO_SHARE) as u32;

        // ...then FEC comes *out* of it. Adding redundancy on top would exceed the link by the
        // overhead percentage precisely when loss is what made us add redundancy.
        let overhead = fec_schedule(loss).approximate_overhead();
        budget = (f64::from(budget) / (1.0 + overhead)) as u32;

        // An IDR was just emitted: hold the target down so its burst is absorbed.
        if now_ms < self.idr_budget_until_ms {
            budget /= 2;
        }

        self.current = directive_for(rung, budget.clamp(MIN_BITRATE_BPS, MAX_BITRATE_BPS), loss);
        self.current
    }

    /// The settings currently in force.
    #[must_use]
    pub fn current(&self) -> EncoderDirective {
        self.current
    }

    /// Decides how to answer a receiver's recovery request.
    ///
    /// Prefers an LTR recovery whenever the receiver holds an acknowledged reference. Falls back to
    /// an IDR only when it does not — and rate-limits those to one per second, coalescing the rest.
    pub fn on_recovery_request(
        &mut self,
        receiver_ltr: Option<u8>,
        now_ms: u64,
    ) -> KeyframeDecision {
        // The receiver names a reference and we have seen it acknowledged: repair cheaply.
        if let (Some(index), Some(acked)) = (receiver_ltr, self.acked_ltr) {
            if index == acked {
                self.ltr_recovery_count += 1;
                return KeyframeDecision::Recover(RecoveryMode::Ltr { index });
            }
        }

        // No usable reference, so an IDR is genuinely needed — but not more than once a second.
        if let Some(last) = self.last_idr_ms {
            if now_ms.saturating_sub(last) < IDR_MIN_INTERVAL_MS {
                self.suppressed_count += 1;
                return KeyframeDecision::Suppressed;
            }
        }

        self.last_idr_ms = Some(now_ms);
        self.idr_budget_until_ms = now_ms + IDR_BUDGET_MS;
        self.idr_count += 1;
        KeyframeDecision::Idr
    }

    /// Counters for telemetry: IDRs emitted, LTR recoveries, suppressed requests.
    ///
    /// A high IDR count relative to LTR recoveries means the acknowledgement path is not working,
    /// which is invisible from picture quality alone but very visible in bandwidth.
    #[must_use]
    pub fn recovery_stats(&self) -> (u64, u64, u64) {
        (
            self.idr_count,
            self.ltr_recovery_count,
            self.suppressed_count,
        )
    }
}

/// Maps a ladder rung and a bitrate budget onto encoder settings.
fn directive_for(rung: LadderRung, bitrate_bps: u32, loss: f64) -> EncoderDirective {
    // QP floor rises as the ladder descends: at low rungs there are not enough bits to justify a
    // low QP, and letting the encoder chase one just makes it drop frames instead.
    let (qp_min, qp_max) = match rung.rung {
        0 => (18, 40),
        1 => (24, 44),
        2 => (26, 46),
        3 => (28, 48),
        4 => (30, 49),
        _ => (32, 51),
    };

    EncoderDirective {
        bitrate_bps,
        fps: rung.fps,
        scale_pct: rung.scale_pct,
        temporal_layers: rung.temporal_layers,
        qp_min,
        // Under heavy loss, allow the encoder further up the QP range rather than dropping frames.
        // A soft picture that keeps moving beats a sharp one that stutters.
        qp_max: if loss > 0.10 { 51 } else { qp_max },
        stills_only: rung.stills_only,
        rung: rung.rung,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn telemetry(bwe_bps: u32, loss_permille: u16, now_ms: u64) -> LinkTelemetry {
        let mut t = LinkTelemetry::new();
        t.bwe_bps = bwe_bps;
        t.rtt.sample(220, now_ms);
        // The loss estimator works in received/lost counts, so express the rate that way.
        t.loss.sample(
            1000 - u32::from(loss_permille),
            u32::from(loss_permille),
            now_ms,
        );
        t
    }

    #[test]
    fn video_only_claims_a_share_of_the_estimate() {
        // Sending at 100% of the estimate guarantees queueing, and queue depth is latency.
        let mut c = RateController::new();
        let d = c.update(&telemetry(10_000_000, 0, 0), 0);
        assert!(d.bitrate_bps < 10_000_000);
        assert!(d.bitrate_bps > 8_000_000, "got {}", d.bitrate_bps);
    }

    #[test]
    fn fec_overhead_is_taken_out_of_the_budget_not_added_to_it() {
        // The mistake this guards: sizing video at the full estimate and then adding 35% FEC, so
        // the link is exceeded by a third exactly when loss is what prompted the redundancy.
        let mut clean = RateController::new();
        let clean_rate = clean.update(&telemetry(4_000_000, 0, 0), 0).bitrate_bps;

        let mut lossy = RateController::new();
        let lossy_rate = lossy.update(&telemetry(4_000_000, 70, 0), 0).bitrate_bps;

        assert!(
            lossy_rate < clean_rate,
            "heavy loss must shrink the video budget: {lossy_rate} vs {clean_rate}"
        );
        // 50% base-layer FEC is roughly 30% overall overhead, so expect roughly a 1/1.3 reduction.
        let ratio = f64::from(lossy_rate) / f64::from(clean_rate);
        assert!(
            (0.65..0.85).contains(&ratio),
            "unexpected reduction ratio {ratio}"
        );
    }

    #[test]
    fn congestion_cuts_bitrate_within_one_update() {
        // The cut has to land immediately; waiting for the ladder's hysteresis would spend seconds
        // over-sending into a link that has already failed.
        let mut c = RateController::new();
        c.update(&telemetry(8_000_000, 0, 0), 0);
        let after = c.update(&telemetry(600_000, 0, 0), 100);
        assert!(
            after.bitrate_bps < 700_000,
            "bitrate must follow the estimate at once"
        );
    }

    #[test]
    fn resolution_and_frame_rate_fall_with_bitrate() {
        // Cutting bits alone just raises QP until text is unreadable. The ladder cuts pixels too.
        let mut c = RateController::new();
        let full = c.update(&telemetry(10_000_000, 0, 0), 0);
        assert_eq!(full.scale_pct, 100);
        assert_eq!(full.fps, 60);

        // Sustained pressure for longer than the demotion delay.
        c.update(&telemetry(500_000, 0, 1_000), 1_000);
        let low = c.update(&telemetry(500_000, 0, 4_000), 4_000);
        assert!(low.scale_pct < 100, "resolution must drop");
        assert!(low.fps < 60, "frame rate must drop");
        assert!(
            low.qp_min > full.qp_min,
            "QP floor must rise as bits get scarce"
        );
    }

    #[test]
    fn recovery_slower_than_degradation() {
        let mut c = RateController::new();
        c.update(&telemetry(10_000_000, 0, 0), 0);

        // Degrade: takes effect after the 2 s demotion delay.
        c.update(&telemetry(500_000, 0, 100), 100);
        assert_eq!(c.update(&telemetry(500_000, 0, 2_500), 2_500).rung, 5);

        // Recover: still degraded well after the same interval has passed.
        assert_eq!(c.update(&telemetry(10_000_000, 0, 5_000), 5_000).rung, 5);
        assert_eq!(c.update(&telemetry(10_000_000, 0, 16_000), 16_000).rung, 0);
    }

    #[test]
    fn catastrophic_loss_collapses_to_stills_while_input_survives() {
        let mut c = RateController::new();
        c.update(&telemetry(10_000_000, 300, 0), 0);
        let d = c.update(&telemetry(10_000_000, 300, 3_000), 3_000);
        assert!(d.stills_only, "past 25% loss the video plane gives up");
        assert_eq!(d.fps, 1);
        // The session is still alive: bitrate stays above the floor, and input rides other
        // channels entirely.
        assert!(d.bitrate_bps >= MIN_BITRATE_BPS);
    }

    #[test]
    fn bitrate_is_clamped_at_both_ends() {
        let mut c = RateController::new();
        assert!(c.update(&telemetry(1, 0, 0), 0).bitrate_bps >= MIN_BITRATE_BPS);
        assert!(c.update(&telemetry(u32::MAX, 0, 0), 0).bitrate_bps <= MAX_BITRATE_BPS);
    }

    // --- recovery policy ---------------------------------------------------------------------

    #[test]
    fn an_acknowledged_reference_is_repaired_without_an_idr() {
        // The mechanism that breaks the IDR spiral: 2-4x a P frame instead of 15-30x.
        let mut c = RateController::new();
        c.on_ltr_acked(3);
        assert_eq!(
            c.on_recovery_request(Some(3), 1_000),
            KeyframeDecision::Recover(RecoveryMode::Ltr { index: 3 })
        );
        let (idrs, ltrs, _) = c.recovery_stats();
        assert_eq!((idrs, ltrs), (0, 1), "no IDR should have been spent");
    }

    #[test]
    fn an_unacknowledged_reference_falls_back_to_an_idr() {
        // Recovering against a reference the receiver never got produces a frame it still cannot
        // decode, and costs another round trip to find out.
        let mut c = RateController::new();
        c.on_ltr_acked(1);
        assert_eq!(c.on_recovery_request(Some(7), 1_000), KeyframeDecision::Idr);
    }

    #[test]
    fn a_receiver_with_no_reference_gets_an_idr() {
        let mut c = RateController::new();
        assert_eq!(c.on_recovery_request(None, 1_000), KeyframeDecision::Idr);
    }

    #[test]
    fn repeated_requests_are_coalesced_into_one_idr_per_second() {
        // Without this, a receiver hammering requests during a loss episode drives exactly the IDR
        // storm that caused the loss.
        let mut c = RateController::new();
        assert_eq!(c.on_recovery_request(None, 1_000), KeyframeDecision::Idr);
        for t in [1_100, 1_500, 1_999] {
            assert_eq!(c.on_recovery_request(None, t), KeyframeDecision::Suppressed);
        }
        assert_eq!(c.on_recovery_request(None, 2_001), KeyframeDecision::Idr);

        let (idrs, _, suppressed) = c.recovery_stats();
        assert_eq!((idrs, suppressed), (2, 3));
    }

    #[test]
    fn ltr_recovery_is_never_rate_limited() {
        // It is cheap, so throttling it would trade a small cost for a visibly broken picture.
        let mut c = RateController::new();
        c.on_ltr_acked(2);
        for t in [1_000, 1_010, 1_020, 1_030] {
            assert!(matches!(
                c.on_recovery_request(Some(2), t),
                KeyframeDecision::Recover(_)
            ));
        }
        assert_eq!(c.recovery_stats().0, 0);
    }

    #[test]
    fn an_idr_paces_itself_by_halving_the_budget() {
        // The burst is smeared across the following frames instead of being dumped into a link
        // that is already congested.
        let mut c = RateController::new();
        let before = c.update(&telemetry(4_000_000, 0, 0), 0).bitrate_bps;

        assert_eq!(c.on_recovery_request(None, 1_000), KeyframeDecision::Idr);
        let during = c.update(&telemetry(4_000_000, 0, 1_050), 1_050).bitrate_bps;
        assert!(
            during < before / 2 + 1,
            "IDR must be paced: {during} vs {before}"
        );

        // The budget returns once the burst has passed.
        let after = c.update(&telemetry(4_000_000, 0, 1_300), 1_300).bitrate_bps;
        assert_eq!(after, before);
    }

    // --- directive arithmetic ------------------------------------------------------------------

    #[test]
    fn scaled_dimensions_stay_even_and_never_collapse() {
        let d = EncoderDirective {
            bitrate_bps: 1_000_000,
            fps: 30,
            scale_pct: 75,
            temporal_layers: 2,
            qp_min: 28,
            qp_max: 48,
            stills_only: false,
            rung: 3,
        };
        let (w, h) = d.scaled_dimensions(1920, 1080);
        assert_eq!((w, h), (1440, 810));
        assert_eq!(w % 2, 0);
        assert_eq!(h % 2, 0);

        // Even an absurd scale must produce something an encoder accepts.
        let tiny = EncoderDirective { scale_pct: 1, ..d };
        let (w, h) = tiny.scaled_dimensions(64, 64);
        assert!(w >= 16 && h >= 16 && w % 2 == 0 && h % 2 == 0);
    }

    #[test]
    fn bits_per_frame_never_divides_by_zero() {
        let d = EncoderDirective {
            bitrate_bps: 3_000_000,
            fps: 0,
            scale_pct: 100,
            temporal_layers: 1,
            qp_min: 20,
            qp_max: 40,
            stills_only: false,
            rung: 0,
        };
        assert_eq!(d.bits_per_frame(), 3_000_000);
        assert_eq!(EncoderDirective { fps: 30, ..d }.bits_per_frame(), 100_000);
    }

    #[test]
    fn heavy_loss_widens_the_qp_ceiling_rather_than_dropping_frames() {
        // A soft picture that keeps moving beats a sharp one that stutters.
        let mut c = RateController::new();
        let clean = c.update(&telemetry(4_000_000, 0, 0), 0);
        let lossy = c.update(&telemetry(4_000_000, 150, 100), 100);
        assert_eq!(lossy.qp_max, 51);
        assert!(clean.qp_max < 51);
    }
}
