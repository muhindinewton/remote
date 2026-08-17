//! The de-jitter buffer — `docs/ARCHITECTURE.md` §2.5.
//!
//! The only component in the system that deliberately *adds* latency, and therefore the first place
//! to look when a session feels laggy. It exists because packets arrive unevenly: displaying each
//! frame the instant it lands turns network jitter directly into visible stutter.
//!
//! Three rules, each with a reason specific to this corridor:
//!
//! **Target a high percentile, not the mean.** The mean tells you nothing about the frame that
//! arrives late enough to be seen. p95 of the windowed jitter distribution is what the buffer has
//! to absorb.
//!
//! **Grow fast, shrink slowly.** An overflow raises the target immediately; recovery decays at a
//! few milliseconds per second. Shrinking quickly re-creates the stutter the buffer exists to
//! remove, and on a 220 ms path a wrong guess is expensive to undo.
//!
//! **Drop discardable frames first.** When the buffer is over target, an upper-temporal-layer frame
//! can be abandoned with no consequence beyond one skipped frame. Dropping a base-layer frame
//! instead would corrupt everything that references it.
//!
//! There is a feedback loop worth understanding: a deeper buffer means more deadline slack, which
//! re-enables retransmission for reference frames (`rda_telemetry::should_nack`). During a lossy
//! episode the buffer grows and NACK quietly becomes viable again. That coupling is intentional.

use rda_encode::EncodedFrame;
use std::collections::VecDeque;

/// Smallest playout delay the buffer will target.
pub const MIN_TARGET_MS: u32 = 15;

/// Largest playout delay the buffer will target.
///
/// Past this the session is better served by the degradation ladder cutting quality than by adding
/// more delay: a user will forgive a soft picture long before they forgive a laggy one.
pub const MAX_TARGET_MS: u32 = 200;

/// How fast the target decays when conditions improve, in milliseconds per second.
pub const DECAY_MS_PER_S: u32 = 5;

/// Maximum frames held before the oldest are dropped, whatever the timing says.
pub const MAX_QUEUED_FRAMES: usize = 120;

/// How far past its deadline a frame must be before the buffer skips forward past it.
///
/// Without this slack, any moment where two frames are due at once would discard the earlier one —
/// and two frames arriving in the same burst is ordinary on a jittery link, not evidence of being
/// behind. Skipping then would drop most of a perfectly healthy stream.
pub const CATCHUP_SLACK_MS: u64 = 100;

/// How far past its deadline a frame must be to be abandoned outright.
///
/// Half a second late is not worth decoding: it shows the user a moment they have already moved
/// past, and costs a decode to do it.
pub const STALE_AFTER_MS: u64 = 500;

/// What the render loop should do right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlayoutDecision {
    /// Display this frame.
    Play(Box<EncodedFrame>),
    /// Nothing is due yet. Keep the previous picture on screen.
    Wait,
    /// The buffer is empty and has been for a while — the stream has stalled.
    ///
    /// Distinct from [`PlayoutDecision::Wait`] so the UI can say so rather than appearing frozen
    /// with no explanation.
    Starved,
}

/// Reorders and paces incoming frames.
#[derive(Debug)]
pub struct JitterBuffer {
    queue: VecDeque<Queued>,
    target_ms: u32,
    /// Jitter samples over the observation window, for the percentile target.
    jitter: rda_telemetry::JitterEstimator,
    last_arrival_ms: Option<u64>,
    last_pts_us: Option<u64>,
    last_played_pts_us: Option<u64>,
    last_decay_ms: u64,
    empty_since_ms: Option<u64>,
    stats: JitterStats,
}

#[derive(Debug, Clone)]
struct Queued {
    frame: EncodedFrame,
    arrived_ms: u64,
    /// When this frame becomes due.
    due_ms: u64,
}

/// Counters for telemetry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JitterStats {
    /// Frames accepted into the buffer.
    pub accepted: u64,
    /// Frames handed to the decoder.
    pub played: u64,
    /// Frames dropped because they arrived after their playout deadline.
    pub dropped_late: u64,
    /// Frames dropped to drain an over-full buffer.
    pub dropped_overflow: u64,
    /// Frames rejected because an older frame had already been played.
    pub dropped_reordered: u64,
    /// Times the buffer ran dry.
    pub starvations: u64,
}

impl JitterStats {
    /// Fraction of accepted frames that reached the screen.
    #[must_use]
    pub fn play_rate(&self) -> f64 {
        if self.accepted == 0 {
            0.0
        } else {
            self.played as f64 / self.accepted as f64
        }
    }
}

impl Default for JitterBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl JitterBuffer {
    /// A buffer at the minimum target delay.
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            target_ms: MIN_TARGET_MS,
            jitter: rda_telemetry::JitterEstimator::new(),
            last_arrival_ms: None,
            last_pts_us: None,
            last_played_pts_us: None,
            last_decay_ms: 0,
            empty_since_ms: None,
            stats: JitterStats::default(),
        }
    }

    /// The current playout delay target, in milliseconds.
    #[must_use]
    pub fn target_ms(&self) -> u32 {
        self.target_ms
    }

    /// Frames currently queued.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.queue.len()
    }

    /// Counters.
    #[must_use]
    pub fn stats(&self) -> JitterStats {
        self.stats
    }

    /// Accepts a frame that just arrived.
    ///
    /// Returns `false` if it was rejected — too late, out of order, or the buffer is full.
    pub fn push(&mut self, frame: EncodedFrame, now_ms: u64) -> bool {
        self.stats.accepted += 1;

        // Measure inter-arrival jitter: how far the gap between arrivals differs from the gap
        // between the frames' own timestamps. That difference *is* the jitter the buffer absorbs.
        if let (Some(prev_arrival), Some(prev_pts)) = (self.last_arrival_ms, self.last_pts_us) {
            let arrival_gap = now_ms.saturating_sub(prev_arrival) as i64;
            let pts_gap = (frame.pts_us.saturating_sub(prev_pts) / 1000) as i64;
            let deviation = (arrival_gap - pts_gap).unsigned_abs() as u32;
            self.jitter.sample(deviation.min(1000), now_ms);
        }
        self.last_arrival_ms = Some(now_ms);
        self.last_pts_us = Some(frame.pts_us);

        // A frame older than one already displayed can never be useful.
        if let Some(played) = self.last_played_pts_us {
            if frame.pts_us <= played {
                self.stats.dropped_reordered += 1;
                return false;
            }
        }

        self.adapt_target(now_ms);

        // Insert in timestamp order. Reordering is rare on a single SCTP stream but real over RTP,
        // and playing frames out of order is worse than a brief wait.
        let position = self
            .queue
            .iter()
            .position(|q| q.frame.pts_us > frame.pts_us)
            .unwrap_or(self.queue.len());

        // Deadlines must be monotonic in playout order as well as in timestamp. A frame that
        // arrived late cannot become due *before* one that precedes it — otherwise catch-up would
        // look at an out-of-order neighbour, decide it is due, and skip the earlier frame.
        let mut due_ms = now_ms + u64::from(self.target_ms);
        if position > 0 {
            due_ms = due_ms.max(self.queue[position - 1].due_ms);
        }
        self.queue.insert(
            position,
            Queued {
                frame,
                arrived_ms: now_ms,
                due_ms,
            },
        );
        for i in position + 1..self.queue.len() {
            self.queue[i].due_ms = self.queue[i].due_ms.max(self.queue[i - 1].due_ms);
        }
        self.empty_since_ms = None;

        self.enforce_capacity();
        true
    }

    /// Raises the target when the observed jitter demands it; lets it decay when it does not.
    fn adapt_target(&mut self, now_ms: u64) {
        let observed = self.jitter.percentile_ms(0.95);
        if observed > self.target_ms {
            // Grow immediately: the evidence that the buffer is too shallow is a visible stutter.
            self.target_ms = observed.min(MAX_TARGET_MS);
            self.last_decay_ms = now_ms;
        } else if now_ms.saturating_sub(self.last_decay_ms) >= 1000 {
            // Shrink slowly. Every millisecond given back is latency the user feels, but giving it
            // back too eagerly re-creates the stutter.
            let seconds = (now_ms - self.last_decay_ms) / 1000;
            let decay = (DECAY_MS_PER_S as u64 * seconds).min(u64::from(u32::MAX)) as u32;
            self.target_ms = self.target_ms.saturating_sub(decay).max(MIN_TARGET_MS);
            self.last_decay_ms = now_ms;
        }
        self.target_ms = self.target_ms.clamp(MIN_TARGET_MS, MAX_TARGET_MS);
    }

    /// Drains an over-full buffer, sacrificing discardable frames first.
    fn enforce_capacity(&mut self) {
        while self.queue.len() > MAX_QUEUED_FRAMES {
            // An upper-layer frame nothing references costs one skipped frame to drop. A
            // base-layer frame would corrupt everything after it.
            let victim = self
                .queue
                .iter()
                .position(|q| q.frame.is_discardable())
                .unwrap_or(0);
            self.queue.remove(victim);
            self.stats.dropped_overflow += 1;
        }
    }

    /// Asks what to display now.
    pub fn poll(&mut self, now_ms: u64) -> PlayoutDecision {
        // Catch up when genuinely behind: skip forward past frames that are well overdue *and*
        // have a newer frame already waiting. The slack is what distinguishes "we fell behind" from
        // "two frames arrived in the same burst", which is ordinary on a jittery link.
        while self.queue.len() > 1 {
            let front_overdue = now_ms > self.queue[0].due_ms + CATCHUP_SLACK_MS;
            let next_ready = self.queue[1].due_ms <= now_ms;
            if front_overdue && next_ready {
                self.queue.pop_front();
                self.stats.dropped_late += 1;
            } else {
                break;
            }
        }

        // Abandon a single frame that is hopelessly stale, even with nothing behind it.
        if let Some(front) = self.queue.front() {
            if now_ms > front.due_ms + STALE_AFTER_MS {
                self.queue.pop_front();
                self.stats.dropped_late += 1;
            }
        }

        let Some(front) = self.queue.front() else {
            match self.empty_since_ms {
                None => {
                    self.empty_since_ms = Some(now_ms);
                    return PlayoutDecision::Wait;
                }
                Some(since) if now_ms.saturating_sub(since) > 500 => {
                    self.stats.starvations += 1;
                    self.empty_since_ms = Some(now_ms);
                    return PlayoutDecision::Starved;
                }
                Some(_) => return PlayoutDecision::Wait,
            }
        };

        if now_ms < front.due_ms {
            return PlayoutDecision::Wait;
        }

        let queued = self.queue.pop_front().expect("front was just observed");
        self.last_played_pts_us = Some(queued.frame.pts_us);
        self.stats.played += 1;
        PlayoutDecision::Play(Box::new(queued.frame))
    }

    /// Empties the buffer, e.g. after an unrecoverable decode failure.
    ///
    /// Also clears the played-timestamp watermark: after a reset the sender starts again from a
    /// keyframe, whose timestamp may predate what we last displayed.
    pub fn reset(&mut self) {
        self.queue.clear();
        self.last_played_pts_us = None;
        self.last_arrival_ms = None;
        self.last_pts_us = None;
        self.empty_since_ms = None;
    }

    /// How long the oldest queued frame has been waiting.
    #[must_use]
    pub fn oldest_age_ms(&self, now_ms: u64) -> u32 {
        self.queue
            .front()
            .map(|q| now_ms.saturating_sub(q.arrived_ms) as u32)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rda_encode::encoder::FrameKind;

    fn frame(pts_us: u64, layer: u8) -> EncodedFrame {
        EncodedFrame {
            data: vec![0xAB; 100],
            kind: if layer == 0 && pts_us == 0 {
                FrameKind::Keyframe
            } else {
                FrameKind::Delta
            },
            pts_us,
            sequence: pts_us / 33_333,
            temporal_layer: layer,
            ltr_index: None,
            qp: None,
        }
    }

    #[test]
    fn a_frame_is_held_for_the_target_delay_then_played() {
        let mut b = JitterBuffer::new();
        assert!(b.push(frame(0, 0), 1_000));

        assert_eq!(
            b.poll(1_000),
            PlayoutDecision::Wait,
            "must not play immediately"
        );
        assert_eq!(b.poll(1_010), PlayoutDecision::Wait);
        assert!(matches!(b.poll(1_020), PlayoutDecision::Play(_)));
        assert_eq!(b.stats().played, 1);
    }

    #[test]
    fn an_empty_buffer_waits_before_declaring_starvation() {
        // Distinguishing the two lets the UI say "the stream stalled" rather than appearing frozen
        // with no explanation.
        let mut b = JitterBuffer::new();
        assert_eq!(b.poll(0), PlayoutDecision::Wait);
        assert_eq!(b.poll(100), PlayoutDecision::Wait);
        assert_eq!(b.poll(600), PlayoutDecision::Starved);
        assert_eq!(b.stats().starvations, 1);
    }

    #[test]
    fn frames_are_reordered_into_timestamp_sequence() {
        // Playing out of order is worse than waiting: the picture visibly jumps backwards.
        let mut b = JitterBuffer::new();
        // Arriving out of order, staggered, as a reordered network would deliver them.
        b.push(frame(66_666, 0), 1_000);
        b.push(frame(0, 0), 1_030);
        b.push(frame(33_333, 0), 1_060);

        // Poll a timeline rather than three chosen instants: the target delay adapts, so the exact
        // millisecond each frame becomes due is not the property under test. The order is.
        let mut played = Vec::new();
        for step in 0..40u64 {
            if let PlayoutDecision::Play(f) = b.poll(1_050 + step * 10) {
                played.push(f.pts_us);
            }
        }
        assert_eq!(played, vec![0, 33_333, 66_666]);
        assert_eq!(
            b.stats().dropped_late,
            0,
            "a modest reorder must not cost any frames"
        );
    }

    #[test]
    fn a_frame_older_than_one_already_played_is_rejected() {
        let mut b = JitterBuffer::new();
        b.push(frame(33_333, 0), 1_000);
        assert!(matches!(b.poll(1_100), PlayoutDecision::Play(_)));

        assert!(
            !b.push(frame(0, 0), 1_100),
            "a superseded frame must not be queued"
        );
        assert_eq!(b.stats().dropped_reordered, 1);
    }

    #[test]
    fn the_target_grows_immediately_when_jitter_appears() {
        // Growing is urgent: the evidence that the buffer is too shallow is a visible stutter.
        let mut b = JitterBuffer::new();
        assert_eq!(b.target_ms(), MIN_TARGET_MS);

        // Frames 33 ms apart in timestamp, arriving at wildly uneven intervals.
        let mut pts = 0u64;
        let mut now = 1_000u64;
        for i in 0..40 {
            pts += 33_333;
            now += if i % 5 == 0 { 150 } else { 20 };
            b.push(frame(pts, 0), now);
        }
        assert!(
            b.target_ms() > MIN_TARGET_MS,
            "target stayed at {}",
            b.target_ms()
        );
    }

    #[test]
    fn the_target_decays_slowly_when_the_link_settles() {
        let mut b = JitterBuffer::new();
        // Force the target up.
        let mut pts = 0u64;
        let mut now = 1_000u64;
        for i in 0..40 {
            pts += 33_333;
            now += if i % 4 == 0 { 200 } else { 10 };
            b.push(frame(pts, 0), now);
        }
        let peak = b.target_ms();
        assert!(peak > MIN_TARGET_MS);

        // The link settles. One second of calm must give back only a few milliseconds.
        let mut b2 = JitterBuffer::new();
        b2.target_ms = 100;
        b2.last_decay_ms = 0;
        b2.adapt_target(1_000);
        assert_eq!(b2.target_ms(), 95, "decay must be gradual, not a cliff");
    }

    #[test]
    fn the_target_is_clamped_at_both_ends() {
        let mut b = JitterBuffer::new();
        b.target_ms = 5;
        b.adapt_target(0);
        assert_eq!(b.target_ms(), MIN_TARGET_MS);

        b.target_ms = 5_000;
        b.adapt_target(0);
        assert_eq!(
            b.target_ms(),
            MAX_TARGET_MS,
            "more delay is worse than less quality"
        );
    }

    #[test]
    fn a_hopelessly_late_frame_is_discarded_rather_than_displayed() {
        // Showing it costs a decode and displays a moment the user has moved past.
        let mut b = JitterBuffer::new();
        b.push(frame(0, 0), 1_000);
        assert_eq!(b.poll(9_000), PlayoutDecision::Wait);
        assert_eq!(b.stats().dropped_late, 1);
    }

    #[test]
    fn overflow_sacrifices_discardable_frames_first() {
        // A base-layer frame would corrupt everything that references it; an upper-layer frame
        // costs one skipped frame.
        let mut b = JitterBuffer::new();
        for i in 0..(MAX_QUEUED_FRAMES as u64 + 20) {
            // Alternate layers, so there is always a discardable candidate.
            b.push(frame((i + 1) * 33_333, (i % 2) as u8), 1_000);
        }
        assert!(b.depth() <= MAX_QUEUED_FRAMES);
        assert!(b.stats().dropped_overflow > 0);

        // The base layer must have survived intact.
        let base_remaining = b
            .queue
            .iter()
            .filter(|q| q.frame.temporal_layer == 0)
            .count();
        assert!(
            base_remaining > 0,
            "the base layer must not be sacrificed while alternatives exist"
        );
    }

    #[test]
    fn reset_clears_the_watermark_so_a_fresh_keyframe_is_accepted() {
        // After a reset the sender restarts from a keyframe whose timestamp may predate what we
        // last displayed. Keeping the watermark would reject it and wedge the session.
        let mut b = JitterBuffer::new();
        b.push(frame(100_000, 0), 1_000);
        assert!(matches!(b.poll(1_100), PlayoutDecision::Play(_)));

        b.reset();
        assert!(
            b.push(frame(0, 0), 1_200),
            "a post-reset keyframe must be accepted"
        );
        assert_eq!(b.depth(), 1);
    }

    #[test]
    fn statistics_account_for_every_accepted_frame() {
        let mut b = JitterBuffer::new();
        for i in 1..=10u64 {
            b.push(frame(i * 33_333, 0), 1_000 + i * 33);
        }
        for t in 0..40u64 {
            b.poll(1_400 + t * 20);
        }
        let s = b.stats();
        assert_eq!(s.accepted, 10);
        assert_eq!(
            s.played + s.dropped_late + s.dropped_overflow + s.dropped_reordered,
            10
        );
        assert!(s.play_rate() > 0.0);
    }

    #[test]
    fn a_steady_stream_plays_almost_everything() {
        // The sanity check in the other direction: a well-behaved link must not be mangled by the
        // buffer's own policies.
        let mut b = JitterBuffer::new();
        let mut played = 0;
        for i in 1..=60u64 {
            let t = 1_000 + i * 16;
            b.push(frame(i * 16_666, 0), t);
            if matches!(b.poll(t + 20), PlayoutDecision::Play(_)) {
                played += 1;
            }
        }
        assert!(
            played > 50,
            "only {played} of 60 frames played on a clean link"
        );
        assert_eq!(b.stats().dropped_reordered, 0);
    }
}
