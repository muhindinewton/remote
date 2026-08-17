//! Live link telemetry, and the policy decisions that depend on it.
//!
//! This crate does two things:
//!
//! 1. **Measures** RTT, loss, jitter and frame drops over sliding windows.
//! 2. **Decides**, from those measurements, the three things `docs/ARCHITECTURE.md` says must be
//!    decided differently on a 220 ms path than on a LAN: whether a NACK is worth sending (§2.2),
//!    how much FEC to add (§2.3), and which rung of the degradation ladder to sit on (§2.9).
//!
//! Keeping the decisions here rather than scattered through the transport is deliberate — they are
//! pure functions of measured state, so they are unit-testable without a network.
//!
//! No clock is read anywhere in this crate. Time is always passed in, which makes every behaviour
//! reproducible in a test without sleeping.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::VecDeque;

/// How long a sample stays in the loss window.
pub const LOSS_WINDOW_MS: u64 = 2_000;
/// How long a sample stays in the jitter window.
pub const JITTER_WINDOW_MS: u64 = 10_000;
/// How long the BBR-style minimum-RTT estimate is held before it is allowed to rise.
pub const MIN_RTT_WINDOW_MS: u64 = 10_000;

// ---------------------------------------------------------------------------------------------
// RTT
// ---------------------------------------------------------------------------------------------

/// Round-trip time estimator.
///
/// Smoothed RTT and variance follow RFC 6298; the windowed minimum is the BBR-style signal, which
/// is far more robust than a delay gradient on a path whose queueing delay is noisy
/// (`docs/ARCHITECTURE.md` §2.6).
#[derive(Debug, Clone, Default)]
pub struct RttEstimator {
    srtt_ms: Option<f64>,
    rttvar_ms: f64,
    latest_ms: u32,
    min_samples: VecDeque<(u64, u32)>,
}

impl RttEstimator {
    /// A fresh estimator with no samples.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an RTT sample taken at `now_ms`.
    pub fn sample(&mut self, rtt_ms: u32, now_ms: u64) {
        self.latest_ms = rtt_ms;
        let r = f64::from(rtt_ms);
        match self.srtt_ms {
            None => {
                self.srtt_ms = Some(r);
                self.rttvar_ms = r / 2.0;
            }
            Some(srtt) => {
                // RFC 6298 §5.3 with the standard alpha = 1/8, beta = 1/4.
                self.rttvar_ms = 0.75 * self.rttvar_ms + 0.25 * (srtt - r).abs();
                self.srtt_ms = Some(0.875 * srtt + 0.125 * r);
            }
        }

        self.min_samples.push_back((now_ms, rtt_ms));
        while let Some(&(t, _)) = self.min_samples.front() {
            if now_ms.saturating_sub(t) > MIN_RTT_WINDOW_MS {
                self.min_samples.pop_front();
            } else {
                break;
            }
        }
    }

    /// Smoothed RTT in milliseconds, or `None` before the first sample.
    #[must_use]
    pub fn smoothed_ms(&self) -> Option<u32> {
        self.srtt_ms.map(|v| v.round() as u32)
    }

    /// RTT variance in milliseconds.
    #[must_use]
    pub fn variance_ms(&self) -> u32 {
        self.rttvar_ms.round() as u32
    }

    /// Most recent raw sample.
    #[must_use]
    pub fn latest_ms(&self) -> u32 {
        self.latest_ms
    }

    /// Minimum RTT observed in the last [`MIN_RTT_WINDOW_MS`].
    ///
    /// This is the propagation-delay estimate: the closest we can get to "what this path costs with
    /// no queue in it".
    #[must_use]
    pub fn min_ms(&self) -> Option<u32> {
        self.min_samples.iter().map(|&(_, v)| v).min()
    }

    /// Queueing delay: how far the current RTT sits above the windowed minimum.
    ///
    /// On a transcontinental path this is the honest congestion signal — the absolute RTT is
    /// dominated by distance and says nothing about whether a queue is building.
    #[must_use]
    pub fn queueing_delay_ms(&self) -> u32 {
        match (self.smoothed_ms(), self.min_ms()) {
            (Some(s), Some(m)) => s.saturating_sub(m),
            _ => 0,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Loss and jitter
// ---------------------------------------------------------------------------------------------

/// Sliding-window packet loss estimator.
#[derive(Debug, Clone, Default)]
pub struct LossEstimator {
    events: VecDeque<(u64, u32, u32)>, // (timestamp, received, lost)
    total_received: u64,
    total_lost: u64,
}

impl LossEstimator {
    /// A fresh estimator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a feedback report covering `received` delivered and `lost` missing packets.
    pub fn sample(&mut self, received: u32, lost: u32, now_ms: u64) {
        self.events.push_back((now_ms, received, lost));
        self.total_received += u64::from(received);
        self.total_lost += u64::from(lost);
        while let Some(&(t, _, _)) = self.events.front() {
            if now_ms.saturating_sub(t) > LOSS_WINDOW_MS {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    /// Loss over the sliding window, in parts per thousand.
    ///
    /// Per-mille rather than a float because it is what goes on the wire in `QosReport`.
    #[must_use]
    pub fn permille(&self) -> u16 {
        let (recv, lost) = self
            .events
            .iter()
            .fold((0u64, 0u64), |(r, l), &(_, rr, ll)| {
                (r + u64::from(rr), l + u64::from(ll))
            });
        let total = recv + lost;
        if total == 0 {
            return 0;
        }
        ((lost * 1000) / total).min(1000) as u16
    }

    /// Loss over the sliding window as a fraction in `0.0..=1.0`.
    #[must_use]
    pub fn fraction(&self) -> f64 {
        f64::from(self.permille()) / 1000.0
    }

    /// Total packets accounted for since the session began.
    #[must_use]
    pub fn totals(&self) -> (u64, u64) {
        (self.total_received, self.total_lost)
    }
}

/// Inter-arrival jitter estimator.
///
/// Tracks a percentile rather than only RFC 3550's smoothed value, because the jitter buffer is
/// sized off a high percentile: the mean tells you nothing about the packet that arrives late
/// enough to cause a visible stutter.
#[derive(Debug, Clone, Default)]
pub struct JitterEstimator {
    samples: VecDeque<(u64, u32)>,
    smoothed: f64,
}

impl JitterEstimator {
    /// A fresh estimator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one inter-arrival deviation in milliseconds.
    pub fn sample(&mut self, deviation_ms: u32, now_ms: u64) {
        // RFC 3550 §6.4.1 smoothing.
        self.smoothed += (f64::from(deviation_ms) - self.smoothed) / 16.0;
        self.samples.push_back((now_ms, deviation_ms));
        while let Some(&(t, _)) = self.samples.front() {
            if now_ms.saturating_sub(t) > JITTER_WINDOW_MS {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    /// RFC 3550 smoothed jitter, in milliseconds.
    #[must_use]
    pub fn smoothed_ms(&self) -> u32 {
        self.smoothed.round() as u32
    }

    /// The requested percentile of the windowed jitter distribution.
    ///
    /// `p` is in `0.0..=1.0`; the jitter buffer uses p95.
    #[must_use]
    pub fn percentile_ms(&self, p: f64) -> u32 {
        if self.samples.is_empty() {
            return 0;
        }
        let mut v: Vec<u32> = self.samples.iter().map(|&(_, d)| d).collect();
        v.sort_unstable();
        let idx = ((v.len() - 1) as f64 * p.clamp(0.0, 1.0)).round() as usize;
        v[idx]
    }

    /// Number of samples currently in the window.
    #[must_use]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Returns `true` if no samples are in the window.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}

// ---------------------------------------------------------------------------------------------
// Sequence tracking
// ---------------------------------------------------------------------------------------------

/// How far out of order a sequence number may arrive and still be counted as delivered.
///
/// Beyond this the tracker treats it as a wrap or a reset rather than a very late packet. At 30 fps
/// with frames fragmented into a handful of pieces, 256 is several seconds of stream — far more
/// reordering than an SCTP association will ever produce, and far less than half the `u16` space,
/// so it cannot be confused with a wrap.
pub const MAX_REORDER: u16 = 256;

/// Turns a stream of wire sequence numbers into delivered/lost counts.
///
/// Loss has to be measured somewhere, and this is the only place it is observable: the receiver
/// sees the gaps. The sender cannot know, and the transport will not say — SCTP reports nothing
/// upward about messages it abandoned under `max_packet_life_time`, which is precisely the
/// mechanism by which video fragments go missing.
///
/// Sequence numbers wrap, so comparison uses RFC 1982 serial arithmetic rather than `<`. Getting
/// that wrong produces a loss estimate that is correct for eleven minutes and then reports 100 %
/// loss forever, which is a genuinely hard bug to find in the field.
#[derive(Debug, Clone, Default)]
pub struct SequenceTracker {
    highest: Option<u16>,
    /// Delivered since the last [`SequenceTracker::take`].
    received: u32,
    /// Inferred missing since the last [`SequenceTracker::take`].
    lost: u32,
}

impl SequenceTracker {
    /// A fresh tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one arrival.
    ///
    /// A gap is counted as loss the moment a newer sequence number arrives, and a later arrival
    /// within [`MAX_REORDER`] cancels one unit of that loss. Counting optimistically and correcting
    /// downward keeps the estimate responsive: waiting for a reorder window to close before
    /// admitting loss would delay every rate cut by that window, and on this corridor a late rate
    /// cut is a stalled session.
    pub fn observe(&mut self, sequence: u16) {
        self.received += 1;
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            return;
        };

        let advance = sequence.wrapping_sub(highest);
        if advance == 0 {
            // A duplicate of the newest. Not loss, and not progress.
            return;
        }
        if advance <= MAX_REORDER {
            // Moved forward: everything skipped over is missing, for now.
            self.lost += u32::from(advance - 1);
            self.highest = Some(sequence);
        } else if highest.wrapping_sub(sequence) <= MAX_REORDER {
            // Arrived late, filling a hole we already counted against ourselves.
            self.lost = self.lost.saturating_sub(1);
        } else {
            // Neither near the head nor plausibly reordered: the peer restarted its numbering.
            // Resynchronise rather than reporting tens of thousands of phantom losses.
            self.highest = Some(sequence);
        }
    }

    /// Returns and clears the counts accumulated since the last call.
    pub fn take(&mut self) -> (u32, u32) {
        let counts = (self.received, self.lost);
        self.received = 0;
        self.lost = 0;
        counts
    }
}

// ---------------------------------------------------------------------------------------------
// Bandwidth estimation
// ---------------------------------------------------------------------------------------------

/// Lowest rate the estimator will propose, in bits per second.
///
/// Below this the ladder is already at stills-only and cutting further buys nothing: the floor
/// exists so a transient loss spike cannot drive the estimate to zero and strand the session with
/// no path back up.
pub const MIN_BITRATE_BPS: u32 = 150_000;

/// Highest rate the estimator will propose, in bits per second.
pub const MAX_BITRATE_BPS: u32 = 12_000_000;

/// How often the estimate may change.
///
/// One update per RTT is the useful ceiling — reacting faster than feedback arrives means reacting
/// to the same information twice — and on this corridor an RTT is about a quarter of a second.
pub const BITRATE_UPDATE_INTERVAL_MS: u64 = 250;

/// Loss-based send-rate estimator.
///
/// **What this is.** The loss-based half of Google Congestion Control (draft-ietf-rmcat-gcc-02
/// §5.5), which is a published algorithm with three rules: below 2 % loss the link is under-used
/// and the rate rises 5 %; above 10 % the link is over-used and the rate falls by half the loss
/// fraction; between the two the rate holds, because that band is where a loss-tolerant video
/// stream is supposed to live.
///
/// **What this is not.** GCC's other half — the delay-based controller, with the arrival-time
/// filter and overuse detector — is absent, and that is the half that reacts *before* a queue
/// overflows rather than after. Implementing it needs per-packet arrival timing from TWCC, which
/// requires RTP; webrtc-rs supplies the TWCC transport but no estimator on top of it, and reports
/// `available_outgoing_bitrate` as a hardcoded zero. So this exists because nothing underneath
/// provides it, and the delay signal it does use — see [`BitrateEstimator::observe_delay`] — is a
/// coarse substitute rather than the real thing.
///
/// The consequence to expect: on a link that buffers deeply, loss arrives late, so this reacts late.
/// It will hold a session together; it will not hold latency down the way a delay-based controller
/// does.
#[derive(Debug, Clone)]
pub struct BitrateEstimator {
    estimate_bps: u32,
    last_update_ms: Option<u64>,
    /// Set when the receiver's buffer is growing, which suppresses increase for one update.
    delay_pressure: bool,
    last_playout_ms: Option<u32>,
}

impl Default for BitrateEstimator {
    fn default() -> Self {
        Self::new(1_500_000)
    }
}

impl BitrateEstimator {
    /// Starts at `initial_bps`, clamped to the permitted range.
    #[must_use]
    pub fn new(initial_bps: u32) -> Self {
        Self {
            estimate_bps: initial_bps.clamp(MIN_BITRATE_BPS, MAX_BITRATE_BPS),
            last_update_ms: None,
            delay_pressure: false,
            last_playout_ms: None,
        }
    }

    /// The current estimate.
    #[must_use]
    pub fn estimate_bps(&self) -> u32 {
        self.estimate_bps
    }

    /// Feeds in the receiver's playout delay, which stands in for a delay-based overuse signal.
    ///
    /// The receiver's jitter buffer grows when inter-arrival spread grows, and inter-arrival spread
    /// grows when a queue is filling somewhere on the path. It is a lagging and indirect signal —
    /// the buffer is also responding to ordinary jitter — so it is used only to *withhold an
    /// increase*, never to force a cut. Treating it as proof of congestion would make the estimator
    /// cut rate on a merely jittery link, which is most of this corridor most of the time.
    pub fn observe_delay(&mut self, playout_delay_ms: u32) {
        if let Some(previous) = self.last_playout_ms {
            // A fifth again as deep, and at least 20 ms more: growth big enough not to be noise.
            self.delay_pressure =
                playout_delay_ms > previous + 20 && playout_delay_ms * 5 > previous * 6;
        }
        self.last_playout_ms = Some(playout_delay_ms);
    }

    /// Folds in a loss measurement and returns the updated estimate.
    ///
    /// Rate-limited to [`BITRATE_UPDATE_INTERVAL_MS`]; calls inside that window return the current
    /// estimate unchanged.
    pub fn update(&mut self, loss_fraction: f64, now_ms: u64) -> u32 {
        if let Some(last) = self.last_update_ms {
            if now_ms.saturating_sub(last) < BITRATE_UPDATE_INTERVAL_MS {
                return self.estimate_bps;
            }
        }
        self.last_update_ms = Some(now_ms);

        let current = f64::from(self.estimate_bps);
        let next = if loss_fraction > 0.10 {
            // Over-used. The multiplier is bounded below by 0.5 so a catastrophic report cannot
            // collapse the estimate in a single step.
            current * (1.0 - 0.5 * loss_fraction).max(0.5)
        } else if loss_fraction < 0.02 && !self.delay_pressure {
            current * 1.05
        } else {
            current
        };

        self.estimate_bps = (next as u32).clamp(MIN_BITRATE_BPS, MAX_BITRATE_BPS);
        self.estimate_bps
    }
}

// ---------------------------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------------------------

/// Video frame accounting.
#[derive(Debug, Clone, Copy, Default)]
pub struct FrameStats {
    /// Frames handed to the decoder.
    pub decoded: u64,
    /// Frames dropped because they were undecodable or missed their deadline.
    pub dropped: u64,
    /// Frames deliberately skipped because they were discardable enhancement layers.
    ///
    /// Counted separately from `dropped`: skipping a top-layer frame is the loss-resilience design
    /// working as intended, not a failure, and conflating the two makes the metric useless.
    pub skipped_discardable: u64,
    /// Keyframes received.
    pub keyframes: u64,
}

impl FrameStats {
    /// Fraction of frames lost that were *not* discardable, in `0.0..=1.0`.
    #[must_use]
    pub fn harmful_drop_rate(&self) -> f64 {
        let total = self.decoded + self.dropped;
        if total == 0 {
            0.0
        } else {
            self.dropped as f64 / total as f64
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Aggregate
// ---------------------------------------------------------------------------------------------

/// The complete live picture of one session's link.
#[derive(Debug, Clone, Default)]
pub struct LinkTelemetry {
    /// Round-trip time.
    pub rtt: RttEstimator,
    /// Packet loss.
    pub loss: LossEstimator,
    /// Inter-arrival jitter.
    pub jitter: JitterEstimator,
    /// Frame accounting.
    pub frames: FrameStats,
    /// Current bandwidth estimate in bits per second.
    pub bwe_bps: u32,
    /// Current jitter buffer target in milliseconds.
    pub playout_delay_ms: u32,
    /// Whether media is flowing over a TURN relay rather than peer-to-peer.
    pub relayed: bool,
}

impl LinkTelemetry {
    /// A fresh telemetry set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Renders the one-line status used by the live telemetry display.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "rtt {:>3}ms (min {:>3}, q {:>2}) | loss {:>4.1}% | jitter p95 {:>2}ms | \
             bwe {:>5.1}Mbps | buf {:>3}ms | frames {}+{} drop {} skip | {}",
            self.rtt.smoothed_ms().unwrap_or(0),
            self.rtt.min_ms().unwrap_or(0),
            self.rtt.queueing_delay_ms(),
            self.loss.fraction() * 100.0,
            self.jitter.percentile_ms(0.95),
            f64::from(self.bwe_bps) / 1_000_000.0,
            self.playout_delay_ms,
            self.frames.decoded,
            self.frames.dropped,
            self.frames.skipped_discardable,
            if self.relayed { "RELAY" } else { "P2P" },
        )
    }

    /// Builds the wire-format telemetry report.
    #[must_use]
    pub fn to_qos_report(&self) -> rda_proto::control::QosReport {
        rda_proto::control::QosReport {
            rtt_ms: self.rtt.smoothed_ms().unwrap_or(0).min(u32::from(u16::MAX)) as u16,
            jitter_ms: self.jitter.percentile_ms(0.95).min(u32::from(u16::MAX)) as u16,
            loss_permille: self.loss.permille(),
            frames_decoded: self.frames.decoded.min(u64::from(u16::MAX)) as u16,
            frames_dropped: self.frames.dropped.min(u64::from(u16::MAX)) as u16,
            render_fps_q8: 0,
            playout_delay_ms: self.playout_delay_ms.min(u32::from(u16::MAX)) as u16,
            decode_time_us: 0,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Policy: NACK
// ---------------------------------------------------------------------------------------------

/// Processing slack added to the NACK deadline calculation, in milliseconds.
///
/// Covers the retransmission request being generated, queued, and the replacement packet being
/// depacketised at the far end.
pub const RTX_PROCESSING_SLACK_MS: u32 = 5;

/// Why a retransmission request was or was not sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NackDecision {
    /// Send it — the repaired packet will arrive before the frame is due.
    Send,
    /// Skip: the repair could not arrive in time. FEC and loss-resilient encoding absorb this
    /// instead (`docs/ARCHITECTURE.md` §2.3, §2.4).
    TooLate,
    /// Skip: the frame is a discardable enhancement layer that nothing else references.
    Discardable,
}

/// Decides whether a NACK is worth sending — `docs/ARCHITECTURE.md` §2.2.
///
/// The rule is `now + RTT + slack + 0.5 × jitter_stddev < playout_deadline`. At 220 ms RTT with a
/// 30 ms buffer this is false for essentially every ordinary frame, which is the intended result:
/// a retransmission that arrives after its frame was due has cost bandwidth for nothing.
///
/// `is_reference` frames get the deadline extended by the buffer depth again, because losing a
/// reference corrupts everything that depends on it — there, waiting is cheaper than the alternative.
#[must_use]
pub fn should_nack(
    rtt: &RttEstimator,
    jitter: &JitterEstimator,
    ms_until_playout: u32,
    is_reference: bool,
    is_discardable: bool,
) -> NackDecision {
    if is_discardable && !is_reference {
        return NackDecision::Discardable;
    }
    let rtt_ms = rtt.smoothed_ms().unwrap_or(0);
    let jitter_allowance = jitter.percentile_ms(0.95) / 2;
    let cost = rtt_ms + RTX_PROCESSING_SLACK_MS + jitter_allowance;

    // A reference frame is worth waiting for beyond its nominal deadline: a brief stall beats
    // propagating corruption through every frame that references it.
    let deadline = if is_reference {
        ms_until_playout.saturating_add(rtt_ms)
    } else {
        ms_until_playout
    };

    if cost < deadline {
        NackDecision::Send
    } else {
        NackDecision::TooLate
    }
}

// ---------------------------------------------------------------------------------------------
// Policy: FEC
// ---------------------------------------------------------------------------------------------

/// Forward error correction redundancy for one moment in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecSchedule {
    /// Redundancy percentage applied to the base temporal layer.
    pub base_layer_pct: u8,
    /// Redundancy percentage applied to enhancement layers.
    pub enhancement_pct: u8,
    /// Extra percentage points added on top for keyframes and long-term references.
    pub reference_bonus_pct: u8,
}

impl FecSchedule {
    /// Approximate total bandwidth overhead as a fraction of the media rate.
    ///
    /// Assumes roughly a 60/40 split of bytes between base and enhancement layers, which is
    /// representative for L1T3 on desktop content — an estimate, not a measurement.
    #[must_use]
    pub fn approximate_overhead(self) -> f64 {
        (f64::from(self.base_layer_pct) * 0.6 + f64::from(self.enhancement_pct) * 0.4) / 100.0
    }
}

/// Selects FEC redundancy for a measured loss rate — `docs/ARCHITECTURE.md` §2.3.
///
/// Unequal error protection is the point: uniform FEC spends bandwidth protecting frames whose loss
/// nobody would notice.
#[must_use]
pub fn fec_schedule(loss_fraction: f64) -> FecSchedule {
    let pct = loss_fraction * 100.0;
    if pct < 0.5 {
        FecSchedule {
            base_layer_pct: 0,
            enhancement_pct: 0,
            reference_bonus_pct: 20,
        }
    } else if pct < 2.0 {
        FecSchedule {
            base_layer_pct: 15,
            enhancement_pct: 0,
            reference_bonus_pct: 20,
        }
    } else if pct < 5.0 {
        FecSchedule {
            base_layer_pct: 30,
            enhancement_pct: 10,
            reference_bonus_pct: 20,
        }
    } else if pct < 10.0 {
        FecSchedule {
            base_layer_pct: 50,
            enhancement_pct: 20,
            reference_bonus_pct: 20,
        }
    } else {
        // Past 10% the ladder cuts resolution and frame rate first; enhancement layers are dropped
        // entirely rather than protected.
        FecSchedule {
            base_layer_pct: 60,
            enhancement_pct: 0,
            reference_bonus_pct: 20,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Policy: degradation ladder
// ---------------------------------------------------------------------------------------------

/// One rung of the quality ladder — `docs/ARCHITECTURE.md` §2.9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LadderRung {
    /// Rung index, 0 being full quality.
    pub rung: u8,
    /// Target frames per second.
    pub fps: u8,
    /// Resolution scale as a percentage of native.
    pub scale_pct: u8,
    /// Number of temporal layers.
    pub temporal_layers: u8,
    /// Whether video has collapsed to periodic stills, keeping only input and control alive.
    pub stills_only: bool,
}

/// The full ladder, rung 0 first.
pub const LADDER: [LadderRung; 8] = [
    LadderRung {
        rung: 0,
        fps: 60,
        scale_pct: 100,
        temporal_layers: 3,
        stills_only: false,
    },
    LadderRung {
        rung: 1,
        fps: 60,
        scale_pct: 100,
        temporal_layers: 3,
        stills_only: false,
    },
    LadderRung {
        rung: 2,
        fps: 30,
        scale_pct: 100,
        temporal_layers: 2,
        stills_only: false,
    },
    LadderRung {
        rung: 3,
        fps: 30,
        scale_pct: 75,
        temporal_layers: 2,
        stills_only: false,
    },
    LadderRung {
        rung: 4,
        fps: 20,
        scale_pct: 60,
        temporal_layers: 2,
        stills_only: false,
    },
    LadderRung {
        rung: 5,
        fps: 12,
        scale_pct: 50,
        temporal_layers: 1,
        stills_only: false,
    },
    LadderRung {
        rung: 6,
        fps: 5,
        scale_pct: 40,
        temporal_layers: 1,
        stills_only: false,
    },
    LadderRung {
        rung: 7,
        fps: 1,
        scale_pct: 40,
        temporal_layers: 1,
        stills_only: true,
    },
];

/// Selects a ladder rung from the bandwidth estimate and loss rate.
#[must_use]
pub fn select_rung(bwe_bps: u32, loss_fraction: f64) -> LadderRung {
    if loss_fraction > 0.25 {
        return LADDER[7];
    }
    if loss_fraction > 0.15 {
        return LADDER[6];
    }
    let mbps = f64::from(bwe_bps) / 1_000_000.0;
    let idx = if mbps >= 8.0 {
        0
    } else if mbps >= 4.0 {
        1
    } else if mbps >= 2.5 {
        2
    } else if mbps >= 1.5 {
        3
    } else if mbps >= 0.8 {
        4
    } else if mbps >= 0.4 {
        5
    } else {
        6
    };
    LADDER[idx]
}

/// Applies hysteresis to ladder transitions.
///
/// Without this the system oscillates: a rate cut reduces quality, which frees bandwidth, which
/// triggers an immediate promotion, which causes another cut. Descend after 2 s of sustained
/// pressure, ascend only after 10 s of sustained headroom — deliberately asymmetric, because
/// degrading late is far more visible to a user than upgrading late.
#[derive(Debug, Clone)]
pub struct LadderController {
    current: u8,
    pending: Option<(u8, u64)>,
    demote_after_ms: u64,
    promote_after_ms: u64,
}

impl Default for LadderController {
    fn default() -> Self {
        Self::new()
    }
}

impl LadderController {
    /// A controller starting at full quality.
    #[must_use]
    pub fn new() -> Self {
        Self {
            current: 0,
            pending: None,
            demote_after_ms: 2_000,
            promote_after_ms: 10_000,
        }
    }

    /// Feeds in the instantaneous recommendation and returns the rung to actually use.
    pub fn update(&mut self, bwe_bps: u32, loss_fraction: f64, now_ms: u64) -> LadderRung {
        let target = select_rung(bwe_bps, loss_fraction).rung;
        if target == self.current {
            self.pending = None;
            return LADDER[self.current as usize];
        }
        let required = if target > self.current {
            self.demote_after_ms
        } else {
            self.promote_after_ms
        };
        match self.pending {
            Some((pending_target, since)) if pending_target == target => {
                if now_ms.saturating_sub(since) >= required {
                    self.current = target;
                    self.pending = None;
                }
            }
            _ => self.pending = Some((target, now_ms)),
        }
        LADDER[self.current as usize]
    }

    /// The rung currently in force.
    #[must_use]
    pub fn current(&self) -> LadderRung {
        LADDER[self.current as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_converges_and_tracks_its_minimum() {
        let mut r = RttEstimator::new();
        for i in 0..50 {
            r.sample(220, i * 100);
        }
        assert_eq!(r.smoothed_ms(), Some(220));
        assert_eq!(r.min_ms(), Some(220));

        // A queue builds: absolute RTT rises but the windowed minimum holds, so the queueing
        // delay becomes visible. This is the signal GCC's delay gradient struggles to see.
        for i in 50..120 {
            r.sample(300, i * 100);
        }
        assert_eq!(r.min_ms(), Some(220));
        assert!(
            r.queueing_delay_ms() > 50,
            "queueing delay must surface, got {}",
            r.queueing_delay_ms()
        );
    }

    #[test]
    fn loss_window_expires_old_samples() {
        let mut l = LossEstimator::new();
        l.sample(0, 100, 0); // 100% loss at t=0
        assert_eq!(l.permille(), 1000);
        l.sample(100, 0, 5_000); // clean, well past the window
        assert_eq!(l.permille(), 0, "stale loss must age out of the window");
        assert_eq!(
            l.totals(),
            (100, 100),
            "lifetime totals must still accumulate"
        );
    }

    #[test]
    fn jitter_percentile_tracks_the_tail_the_mean_hides() {
        // A realistic jitter distribution: mostly tight, with a 10% late tail. The buffer has to be
        // sized for the tail, which is exactly what the smoothed RFC 3550 value fails to express.
        let mut j = JitterEstimator::new();
        for i in 0..100 {
            let deviation = if i % 10 == 0 { 200 } else { 5 };
            j.sample(deviation, i);
        }
        assert!(
            j.smoothed_ms() < 60,
            "smoothed value averages the tail away, got {}",
            j.smoothed_ms()
        );
        assert!(
            j.percentile_ms(0.95) >= 200,
            "p95 must expose the late tail the buffer has to absorb, got {}",
            j.percentile_ms(0.95)
        );
        // And the median must stay near the common case, or the buffer would be sized for nothing.
        assert_eq!(j.percentile_ms(0.5), 5);
    }

    #[test]
    fn nack_is_refused_at_transcontinental_rtt() {
        let mut rtt = RttEstimator::new();
        rtt.sample(220, 0);
        let jitter = JitterEstimator::new();

        // The core claim of ARCHITECTURE.md §2.2: with a 30 ms buffer, an ordinary frame cannot be
        // repaired in time at 220 ms RTT.
        assert_eq!(
            should_nack(&rtt, &jitter, 30, false, false),
            NackDecision::TooLate
        );

        // A deeper buffer during a lossy episode re-enables it, which is the coupling §2.5 calls out.
        assert_eq!(
            should_nack(&rtt, &jitter, 400, false, false),
            NackDecision::Send
        );
    }

    #[test]
    fn reference_frames_get_a_longer_deadline() {
        let mut rtt = RttEstimator::new();
        rtt.sample(220, 0);
        let jitter = JitterEstimator::new();
        // Same deadline that was refused for an ordinary frame is accepted for a reference,
        // because losing a reference corrupts everything downstream of it.
        assert_eq!(
            should_nack(&rtt, &jitter, 200, true, false),
            NackDecision::Send
        );
        assert_eq!(
            should_nack(&rtt, &jitter, 200, false, false),
            NackDecision::TooLate
        );
    }

    #[test]
    fn discardable_frames_are_never_retransmitted() {
        let mut rtt = RttEstimator::new();
        rtt.sample(5, 0); // even on a LAN
        let jitter = JitterEstimator::new();
        assert_eq!(
            should_nack(&rtt, &jitter, 10_000, false, true),
            NackDecision::Discardable
        );
    }

    #[test]
    fn nack_is_viable_on_a_lan() {
        // Sanity check in the other direction: the rule must not be a blanket disable.
        let mut rtt = RttEstimator::new();
        rtt.sample(8, 0);
        let jitter = JitterEstimator::new();
        assert_eq!(
            should_nack(&rtt, &jitter, 30, false, false),
            NackDecision::Send
        );
    }

    #[test]
    fn fec_scales_with_loss() {
        assert_eq!(fec_schedule(0.001).base_layer_pct, 0);
        assert_eq!(fec_schedule(0.01).base_layer_pct, 15);
        assert_eq!(fec_schedule(0.03).base_layer_pct, 30);
        assert_eq!(fec_schedule(0.07).base_layer_pct, 50);
        assert_eq!(fec_schedule(0.20).base_layer_pct, 60);

        // Enhancement layers are abandoned rather than protected once loss is severe.
        assert_eq!(fec_schedule(0.20).enhancement_pct, 0);
        assert!(fec_schedule(0.07).approximate_overhead() > 0.3);
    }

    #[test]
    fn ladder_selects_by_bandwidth_then_loss() {
        assert_eq!(select_rung(10_000_000, 0.0).rung, 0);
        assert_eq!(select_rung(3_000_000, 0.0).rung, 2);
        assert_eq!(select_rung(500_000, 0.0).rung, 5);
        // Severe loss overrides a healthy bandwidth estimate entirely.
        assert_eq!(select_rung(10_000_000, 0.30).rung, 7);
        assert!(select_rung(10_000_000, 0.30).stills_only);
    }

    #[test]
    fn ladder_demotes_faster_than_it_promotes() {
        let mut c = LadderController::new();
        assert_eq!(c.update(10_000_000, 0.0, 0).rung, 0);

        // Pressure appears; nothing happens instantly.
        assert_eq!(c.update(1_000_000, 0.0, 100).rung, 0);
        // ...but after 2 s it demotes.
        assert_eq!(c.update(1_000_000, 0.0, 2_200).rung, 4);

        // Headroom returns; promotion is deliberately slow.
        assert_eq!(c.update(10_000_000, 0.0, 5_000).rung, 4);
        assert_eq!(
            c.update(10_000_000, 0.0, 12_000).rung,
            4,
            "10s not yet elapsed"
        );
        assert_eq!(c.update(10_000_000, 0.0, 15_100).rung, 0);
    }

    #[test]
    fn ladder_does_not_oscillate_on_a_flapping_estimate() {
        let mut c = LadderController::new();
        c.update(10_000_000, 0.0, 0);
        // Alternate every 500 ms; neither target ever holds long enough to take effect.
        for i in 0..20 {
            let t = 500 * i;
            let bwe = if i % 2 == 0 { 500_000 } else { 10_000_000 };
            c.update(bwe, 0.0, t);
        }
        assert_eq!(
            c.current().rung,
            0,
            "flapping input must not move the ladder"
        );
    }

    #[test]
    fn summary_renders_without_samples() {
        // The telemetry line is printed from session start, before any sample exists.
        let t = LinkTelemetry::new();
        assert!(t.summary().contains("P2P"));
    }

    #[test]
    fn qos_report_saturates_instead_of_wrapping() {
        let mut t = LinkTelemetry::new();
        t.frames.decoded = 1_000_000;
        t.rtt.sample(u32::MAX, 0);
        let r = t.to_qos_report();
        assert_eq!(r.frames_decoded, u16::MAX);
        assert_eq!(r.rtt_ms, u16::MAX);
    }

    // --- sequence tracking -------------------------------------------------------------------

    #[test]
    fn a_contiguous_run_reports_no_loss() {
        let mut t = SequenceTracker::new();
        for n in 0..100u16 {
            t.observe(n);
        }
        assert_eq!(t.take(), (100, 0));
    }

    #[test]
    fn a_gap_is_counted_as_loss() {
        let mut t = SequenceTracker::new();
        t.observe(0);
        t.observe(5);
        let (received, lost) = t.take();
        assert_eq!(received, 2);
        assert_eq!(lost, 4, "1..=4 are missing");
    }

    #[test]
    fn a_late_arrival_cancels_the_loss_it_caused() {
        // Reordering is routine on an unordered channel; counting it as permanent loss would make
        // the estimator cut rate on a link that is delivering everything.
        let mut t = SequenceTracker::new();
        t.observe(0);
        t.observe(2); // 1 is presumed lost
        t.observe(1); // and then arrives
        let (received, lost) = t.take();
        assert_eq!(received, 3);
        assert_eq!(lost, 0);
    }

    #[test]
    fn sequence_wraparound_is_not_reported_as_loss() {
        // The bug this exists to prevent reports 100% loss forever after eleven minutes.
        let mut t = SequenceTracker::new();
        t.observe(u16::MAX - 1);
        t.observe(u16::MAX);
        t.observe(0);
        t.observe(1);
        assert_eq!(t.take(), (4, 0));
    }

    #[test]
    fn a_peer_restarting_its_numbering_resynchronises() {
        let mut t = SequenceTracker::new();
        t.observe(40_000);
        t.observe(7); // neither adjacent nor plausibly reordered
        let (_, lost) = t.take();
        assert_eq!(
            lost, 0,
            "a resync must not invent tens of thousands of losses"
        );
    }

    #[test]
    fn duplicates_do_not_advance_or_lose() {
        let mut t = SequenceTracker::new();
        t.observe(10);
        t.observe(10);
        assert_eq!(t.take(), (2, 0));
    }

    #[test]
    fn take_clears_the_counters() {
        let mut t = SequenceTracker::new();
        t.observe(0);
        t.observe(2);
        assert_eq!(t.take(), (2, 1));
        assert_eq!(t.take(), (0, 0));
    }

    // --- bitrate estimation ------------------------------------------------------------------

    #[test]
    fn a_clean_link_ramps_up() {
        let mut e = BitrateEstimator::new(1_000_000);
        let mut now = 0;
        for _ in 0..20 {
            now += BITRATE_UPDATE_INTERVAL_MS;
            e.update(0.0, now);
        }
        assert!(e.estimate_bps() > 1_000_000, "20 increases of 5% must show");
    }

    #[test]
    fn heavy_loss_cuts_the_rate() {
        let mut e = BitrateEstimator::new(4_000_000);
        e.update(0.30, BITRATE_UPDATE_INTERVAL_MS);
        assert!(e.estimate_bps() < 4_000_000);
        assert!(
            e.estimate_bps() >= 2_000_000,
            "a single report must not more than halve the estimate"
        );
    }

    #[test]
    fn the_tolerant_band_holds_the_rate() {
        // 2-10% loss is where a loss-tolerant video stream is supposed to sit. Reacting inside it
        // would oscillate against the ladder's own loss thresholds.
        let mut e = BitrateEstimator::new(3_000_000);
        e.update(0.05, BITRATE_UPDATE_INTERVAL_MS);
        assert_eq!(e.estimate_bps(), 3_000_000);
    }

    #[test]
    fn updates_are_rate_limited() {
        let mut e = BitrateEstimator::new(1_000_000);
        e.update(0.0, 1_000);
        let after_first = e.estimate_bps();
        e.update(0.0, 1_000 + BITRATE_UPDATE_INTERVAL_MS - 1);
        assert_eq!(
            e.estimate_bps(),
            after_first,
            "no second update inside the window"
        );
    }

    #[test]
    fn a_growing_playout_buffer_withholds_the_increase() {
        let mut e = BitrateEstimator::new(2_000_000);
        e.observe_delay(40);
        e.observe_delay(120); // the receiver is absorbing a widening spread
        e.update(0.0, BITRATE_UPDATE_INTERVAL_MS);
        assert_eq!(
            e.estimate_bps(),
            2_000_000,
            "delay pressure must suppress the ramp, but not cut"
        );
    }

    #[test]
    fn a_stable_playout_buffer_permits_the_increase() {
        let mut e = BitrateEstimator::new(2_000_000);
        e.observe_delay(40);
        e.observe_delay(42);
        e.update(0.0, BITRATE_UPDATE_INTERVAL_MS);
        assert!(e.estimate_bps() > 2_000_000);
    }

    #[test]
    fn the_estimate_stays_inside_its_bounds() {
        let mut e = BitrateEstimator::new(MIN_BITRATE_BPS);
        let mut now = 0;
        for _ in 0..50 {
            now += BITRATE_UPDATE_INTERVAL_MS;
            e.update(0.9, now);
        }
        assert_eq!(
            e.estimate_bps(),
            MIN_BITRATE_BPS,
            "a floor the link can climb back from"
        );

        let mut e = BitrateEstimator::new(MAX_BITRATE_BPS);
        for _ in 0..50 {
            now += BITRATE_UPDATE_INTERVAL_MS;
            e.update(0.0, now);
        }
        assert_eq!(e.estimate_bps(), MAX_BITRATE_BPS);
    }

    #[test]
    fn loss_then_recovery_walks_the_rate_back_up() {
        // The shape that matters on a corridor with transient congestion: cut fast, recover slowly.
        let mut e = BitrateEstimator::new(4_000_000);
        let mut now = 0;
        // 25% loss multiplies by 0.875 per update, so halving takes ~6 of them. That gentleness is
        // the design: a single bad report is a spike, a sustained one is congestion.
        for _ in 0..10 {
            now += BITRATE_UPDATE_INTERVAL_MS;
            e.update(0.25, now);
        }
        let bottom = e.estimate_bps();
        assert!(
            bottom < 2_000_000,
            "sustained 25% loss must cut hard, got {bottom}"
        );

        for _ in 0..30 {
            now += BITRATE_UPDATE_INTERVAL_MS;
            e.update(0.0, now);
        }
        assert!(
            e.estimate_bps() > bottom * 2,
            "and a clean link must recover"
        );
    }
}
