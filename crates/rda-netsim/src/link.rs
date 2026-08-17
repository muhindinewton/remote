//! The link itself: a queue of packets in flight, released when their delivery time arrives.
//!
//! Modelled as a discrete-event queue driven by a caller-supplied clock rather than real time. That
//! is what makes a test of a five-second session take milliseconds, and what makes it deterministic:
//! there is no scheduler, no sleeping, and no wall clock to be flaky against.

use crate::profile::{LinkProfile, LossModel};
use crate::rng::Rng;
use std::collections::VecDeque;

/// A packet in flight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// The payload, unchanged.
    pub payload: Vec<u8>,
    /// When the sender handed it over.
    pub sent_ms: u64,
    /// When it becomes available at the far end.
    pub deliver_ms: u64,
    /// Monotonic send counter, so reordering is observable.
    pub sequence: u64,
}

impl Packet {
    /// One-way delay this packet experienced.
    #[must_use]
    pub fn latency_ms(&self) -> u64 {
        self.deliver_ms.saturating_sub(self.sent_ms)
    }
}

/// What happened to a packet on send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Accepted; it will emerge from [`LinkSim::poll`] at the given time.
    Queued {
        /// When it will arrive.
        deliver_ms: u64,
    },
    /// Dropped by the loss model.
    Lost,
    /// Dropped because the bottleneck queue was full.
    ///
    /// Distinct from [`Delivery::Lost`]: this is congestion the sender caused, and it is the
    /// signal the bandwidth estimator is supposed to react to.
    QueueOverflow,
}

impl Delivery {
    /// Whether the packet will arrive.
    #[must_use]
    pub fn is_delivered(self) -> bool {
        matches!(self, Delivery::Queued { .. })
    }
}

/// Counters describing what the link did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkStats {
    /// Packets offered.
    pub sent: u64,
    /// Packets that will arrive.
    pub delivered: u64,
    /// Packets dropped by the loss model.
    pub lost: u64,
    /// Packets dropped by a full queue.
    pub overflowed: u64,
    /// Packets delivered out of send order.
    pub reordered: u64,
    /// Bytes offered.
    pub bytes_sent: u64,
    /// Sum of one-way delays, for the mean.
    latency_sum_ms: u64,
    /// Largest one-way delay observed.
    pub max_latency_ms: u64,
}

impl LinkStats {
    /// Fraction of offered packets that did not arrive, counting both causes.
    #[must_use]
    pub fn loss_rate(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            (self.lost + self.overflowed) as f64 / self.sent as f64
        }
    }

    /// Mean one-way delay of delivered packets.
    #[must_use]
    pub fn mean_latency_ms(&self) -> f64 {
        if self.delivered == 0 {
            0.0
        } else {
            self.latency_sum_ms as f64 / self.delivered as f64
        }
    }
}

/// A simulated one-way link.
///
/// Two of these back to back make a bidirectional path; giving each its own seed keeps the
/// directions independent, which real paths generally are.
#[derive(Debug)]
pub struct LinkSim {
    profile: LinkProfile,
    rng: Rng,
    in_flight: VecDeque<Packet>,
    /// Packets whose delivery time has arrived, waiting to be collected.
    ready: VecDeque<Packet>,
    /// Bytes currently occupying the bottleneck queue.
    queue_bytes: usize,
    /// When the bottleneck finishes transmitting what it already holds.
    queue_drains_at_ms: u64,
    /// Gilbert–Elliott state.
    in_bad_state: bool,
    sequence: u64,
    last_delivered_sequence: Option<u64>,
    stats: LinkStats,
}

impl LinkSim {
    /// Creates a link.
    #[must_use]
    pub fn new(profile: LinkProfile, seed: u64) -> Self {
        Self {
            profile,
            rng: Rng::new(seed),
            in_flight: VecDeque::new(),
            ready: VecDeque::new(),
            queue_bytes: 0,
            queue_drains_at_ms: 0,
            in_bad_state: false,
            sequence: 0,
            last_delivered_sequence: None,
            stats: LinkStats::default(),
        }
    }

    /// The profile in force.
    #[must_use]
    pub fn profile(&self) -> &LinkProfile {
        &self.profile
    }

    /// Counters.
    #[must_use]
    pub fn stats(&self) -> LinkStats {
        self.stats
    }

    /// Bytes currently queued at the bottleneck.
    ///
    /// This is the number that turns a bandwidth problem into a latency problem — the effect the
    /// pacer in `docs/ARCHITECTURE.md` §2.7 exists to prevent.
    #[must_use]
    pub fn queue_depth_bytes(&self) -> usize {
        self.queue_bytes
    }

    /// Advances the loss model one packet and reports whether to drop.
    fn roll_loss(&mut self) -> bool {
        match self.profile.loss {
            LossModel::Bernoulli { rate } => self.rng.chance(rate),
            LossModel::GilbertElliott {
                good_to_bad,
                bad_to_good,
                loss_in_good,
                loss_in_bad,
            } => {
                self.in_bad_state = if self.in_bad_state {
                    !self.rng.chance(bad_to_good)
                } else {
                    self.rng.chance(good_to_bad)
                };
                let p = if self.in_bad_state {
                    loss_in_bad
                } else {
                    loss_in_good
                };
                self.rng.chance(p)
            }
        }
    }

    /// Offers a packet to the link.
    pub fn send(&mut self, payload: Vec<u8>, now_ms: u64) -> Delivery {
        self.stats.sent += 1;
        self.stats.bytes_sent += payload.len() as u64;
        let sequence = self.sequence;
        self.sequence += 1;

        // Drain whatever the bottleneck has transmitted since the last send. Without this the
        // queue only ever grows and every link eventually reports overflow.
        self.drain_queue(now_ms);

        if self.queue_bytes + payload.len() > self.profile.queue_bytes {
            self.stats.overflowed += 1;
            return Delivery::QueueOverflow;
        }
        if self.roll_loss() {
            self.stats.lost += 1;
            return Delivery::Lost;
        }

        // Serialisation delay: how long the bottleneck takes to clock these bytes out.
        let bits = (payload.len() * 8) as u64;
        let serialise_ms = (bits * 1000) / u64::from(self.profile.bandwidth_bps.max(1));

        // A packet cannot start transmitting until the queue ahead of it has drained.
        let start_ms = now_ms.max(self.queue_drains_at_ms);
        self.queue_drains_at_ms = start_ms + serialise_ms;
        self.queue_bytes += payload.len();

        // Propagation plus jitter. Jitter is clamped non-negative: a packet cannot arrive before it
        // was sent, and a normal deviate with a wide sigma will otherwise try.
        let jitter = if self.profile.jitter_ms == 0 {
            0.0
        } else {
            self.rng.normal(0.0, f64::from(self.profile.jitter_ms))
        };
        let delay = (f64::from(self.profile.base_delay_ms) + jitter).max(1.0) as u64;
        let mut deliver_ms = self.queue_drains_at_ms + delay;

        // Reordering: pull this packet in front of one already in flight.
        if self.rng.chance(self.profile.reorder_rate) {
            if let Some(earliest) = self.in_flight.iter().map(|p| p.deliver_ms).min() {
                deliver_ms = earliest.saturating_sub(1).max(now_ms + 1);
            }
        }

        self.stats.delivered += 1;
        self.stats.latency_sum_ms += deliver_ms.saturating_sub(now_ms);
        self.stats.max_latency_ms = self
            .stats
            .max_latency_ms
            .max(deliver_ms.saturating_sub(now_ms));

        self.in_flight.push_back(Packet {
            payload,
            sent_ms: now_ms,
            deliver_ms,
            sequence,
        });
        Delivery::Queued { deliver_ms }
    }

    /// Releases queue occupancy for bytes the bottleneck has finished transmitting.
    fn drain_queue(&mut self, now_ms: u64) {
        if now_ms >= self.queue_drains_at_ms {
            self.queue_bytes = 0;
            self.queue_drains_at_ms = now_ms;
        }
    }

    /// Collects every packet whose delivery time has arrived.
    ///
    /// Returned in delivery-time order, which is not necessarily send order — that is the point of
    /// the reorder model.
    pub fn poll(&mut self, now_ms: u64) -> Vec<Packet> {
        let mut due: Vec<Packet> = Vec::new();
        let mut still_flying = VecDeque::with_capacity(self.in_flight.len());

        while let Some(packet) = self.in_flight.pop_front() {
            if packet.deliver_ms <= now_ms {
                due.push(packet);
            } else {
                still_flying.push_back(packet);
            }
        }
        self.in_flight = still_flying;

        due.sort_by_key(|p| (p.deliver_ms, p.sequence));
        for packet in &due {
            if let Some(last) = self.last_delivered_sequence {
                if packet.sequence < last {
                    self.stats.reordered += 1;
                }
            }
            self.last_delivered_sequence = Some(
                self.last_delivered_sequence
                    .map_or(packet.sequence, |l| l.max(packet.sequence)),
            );
        }

        self.ready.extend(due.iter().cloned());
        self.ready.drain(..).collect()
    }

    /// Packets still in flight.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// The earliest time any in-flight packet will be deliverable.
    ///
    /// Lets a test step straight to the next interesting moment rather than polling in a tight loop.
    #[must_use]
    pub fn next_delivery_ms(&self) -> Option<u64> {
        self.in_flight.iter().map(|p| p.deliver_ms).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(size: usize) -> Vec<u8> {
        vec![0xAB; size]
    }

    #[test]
    fn a_packet_arrives_after_the_propagation_delay() {
        let profile = LinkProfile {
            jitter_ms: 0,
            ..LinkProfile::us_kenya_direct()
        };
        let mut link = LinkSim::new(
            LinkProfile {
                loss: LossModel::none(),
                ..profile
            },
            1,
        );

        let Delivery::Queued { deliver_ms } = link.send(packet(1200), 0) else {
            panic!("a clean link must deliver");
        };
        assert!(deliver_ms >= 110, "delivered after only {deliver_ms} ms");

        assert!(link.poll(100).is_empty(), "must not arrive early");
        let arrived = link.poll(deliver_ms);
        assert_eq!(arrived.len(), 1);
        assert_eq!(arrived[0].payload.len(), 1200);
    }

    #[test]
    fn a_packet_is_delivered_exactly_once() {
        let mut link = LinkSim::new(
            LinkProfile {
                loss: LossModel::none(),
                ..LinkProfile::lan()
            },
            2,
        );
        link.send(packet(100), 0);
        assert_eq!(link.poll(1000).len(), 1);
        assert!(
            link.poll(2000).is_empty(),
            "a packet must not be delivered twice"
        );
    }

    #[test]
    fn nothing_arrives_before_it_was_sent() {
        // A normal deviate with a wide sigma will happily produce a large negative jitter; without
        // clamping, packets arrive before they leave and every downstream timing assumption breaks.
        let profile = LinkProfile {
            jitter_ms: 200,
            ..LinkProfile::hostile()
        };
        let mut link = LinkSim::new(profile, 3);
        for t in 0..500u64 {
            if let Delivery::Queued { deliver_ms } = link.send(packet(200), t) {
                assert!(
                    deliver_ms > t,
                    "packet sent at {t} would arrive at {deliver_ms}"
                );
            }
        }
    }

    #[test]
    fn loss_matches_the_profile_when_the_sender_stays_within_capacity() {
        // Paced to ~480 kbps into an 800 kbps link, so what is measured is the *loss model* rather
        // than congestion the sender caused. Conflating the two is exactly the mistake that makes a
        // FEC evaluation meaningless: overflow is the sender's fault and is fixed by sending less,
        // while model loss is the link's and is fixed by redundancy.
        let mut link = LinkSim::new(LinkProfile::us_kenya_congested(), 4);
        for i in 0..20_000u64 {
            link.send(packet(300), i * 5);
        }
        let stats = link.stats();
        assert_eq!(
            stats.overflowed, 0,
            "a paced sender must not overflow the queue"
        );

        let model_loss = stats.lost as f64 / stats.sent as f64;
        assert!(
            (0.05..0.20).contains(&model_loss),
            "a 10% profile produced {model_loss:.3} model loss"
        );
    }

    #[test]
    fn over_sending_shows_up_as_congestion_not_as_link_loss() {
        // The same profile, driven three times over capacity. The extra losses must be attributed
        // to the queue, because that is the signal the bandwidth estimator reacts to.
        let mut link = LinkSim::new(LinkProfile::us_kenya_congested(), 4);
        for t in 0..20_000u64 {
            link.send(packet(300), t);
        }
        let stats = link.stats();
        assert!(
            stats.overflowed > stats.lost,
            "over-sending produced {} overflow against {} model losses",
            stats.overflowed,
            stats.lost
        );
    }

    #[test]
    fn a_clean_profile_loses_nothing() {
        let mut link = LinkSim::new(LinkProfile::lan(), 5);
        for t in 0..5_000u64 {
            link.send(packet(500), t);
        }
        assert_eq!(link.stats().loss_rate(), 0.0);
        assert_eq!(link.stats().delivered, 5_000);
    }

    #[test]
    fn the_bottleneck_queue_overflows_when_oversent() {
        // Sending far above the link rate must eventually drop, and be attributed to congestion
        // rather than to the loss model — that distinction is what the bandwidth estimator reads.
        let profile = LinkProfile {
            loss: LossModel::none(),
            bandwidth_bps: 100_000,
            queue_bytes: 8_000,
            ..LinkProfile::us_kenya_congested()
        };
        let mut link = LinkSim::new(profile, 6);

        // 1200 bytes every millisecond is ~9.6 Mbps into a 100 kbps link.
        for t in 0..500u64 {
            link.send(packet(1200), t);
        }
        let stats = link.stats();
        assert!(stats.overflowed > 0, "over-sending must overflow the queue");
        assert_eq!(
            stats.lost, 0,
            "overflow must not be attributed to the loss model"
        );
    }

    #[test]
    fn the_queue_drains_over_time() {
        // Without draining, the queue only grows and every link eventually reports overflow —
        // which would make the simulator useless for anything but the first second.
        let profile = LinkProfile {
            loss: LossModel::none(),
            bandwidth_bps: 1_000_000,
            queue_bytes: 16_000,
            ..LinkProfile::us_kenya_direct()
        };
        let mut link = LinkSim::new(profile, 7);

        for t in 0..10u64 {
            link.send(packet(1200), t);
        }
        let before = link.queue_depth_bytes();
        assert!(before > 0);

        // A second later the bottleneck has cleared everything.
        link.send(packet(1), 5_000);
        assert!(link.queue_depth_bytes() < before);
    }

    #[test]
    fn a_paced_sender_does_not_overflow_the_same_link() {
        // The counterpart to the over-sending test, and the reason the pacer exists: the same
        // bytes, spread out, arrive intact.
        let profile = LinkProfile {
            loss: LossModel::none(),
            bandwidth_bps: 1_000_000,
            queue_bytes: 16_000,
            ..LinkProfile::us_kenya_direct()
        };
        let mut link = LinkSim::new(profile, 8);

        // 1200 bytes every 10 ms is 960 kbps into a 1 Mbps link.
        for i in 0..200u64 {
            link.send(packet(1200), i * 10);
        }
        assert_eq!(link.stats().overflowed, 0, "a paced sender must fit");
    }

    #[test]
    fn reordering_is_observable_when_the_profile_asks_for_it() {
        let profile = LinkProfile {
            loss: LossModel::none(),
            reorder_rate: 0.3,
            jitter_ms: 30,
            ..LinkProfile::us_kenya_congested()
        };
        let mut link = LinkSim::new(profile, 9);

        for t in 0..2_000u64 {
            link.send(packet(200), t * 5);
            link.poll(t * 5);
        }
        link.poll(1_000_000);
        assert!(
            link.stats().reordered > 0,
            "a 30% reorder profile produced none"
        );
    }

    #[test]
    fn a_clean_link_delivers_in_order() {
        let mut link = LinkSim::new(
            LinkProfile {
                jitter_ms: 0,
                loss: LossModel::none(),
                ..LinkProfile::us_kenya_direct()
            },
            10,
        );
        for t in 0..500u64 {
            link.send(packet(200), t * 10);
        }
        let arrived = link.poll(1_000_000);
        assert_eq!(arrived.len(), 500);
        assert_eq!(link.stats().reordered, 0);

        let sequences: Vec<u64> = arrived.iter().map(|p| p.sequence).collect();
        let mut sorted = sequences.clone();
        sorted.sort_unstable();
        assert_eq!(sequences, sorted, "a jitter-free link must preserve order");
    }

    #[test]
    fn the_same_seed_reproduces_the_same_run() {
        // A flaky network test is worse than none: it trains people to re-run until green.
        let run = |seed: u64| {
            let mut link = LinkSim::new(LinkProfile::us_kenya_congested(), seed);
            for t in 0..3_000u64 {
                link.send(packet(400), t);
            }
            link.stats()
        };
        assert_eq!(run(11), run(11));
        assert_ne!(run(11), run(12));
    }

    #[test]
    fn latency_statistics_are_plausible_for_the_profile() {
        let mut link = LinkSim::new(LinkProfile::us_kenya_direct(), 12);
        for t in 0..5_000u64 {
            link.send(packet(400), t * 10);
        }
        let stats = link.stats();
        assert!(
            (100.0..160.0).contains(&stats.mean_latency_ms()),
            "mean one-way latency was {:.1} ms",
            stats.mean_latency_ms()
        );
        assert!(stats.max_latency_ms >= stats.mean_latency_ms() as u64);
    }

    #[test]
    fn next_delivery_lets_a_test_skip_ahead() {
        let mut link = LinkSim::new(
            LinkProfile {
                loss: LossModel::none(),
                ..LinkProfile::us_kenya_direct()
            },
            13,
        );
        assert_eq!(link.next_delivery_ms(), None);
        link.send(packet(100), 0);
        let next = link
            .next_delivery_ms()
            .expect("a queued packet has a delivery time");
        assert!(link.poll(next - 1).is_empty());
        assert_eq!(link.poll(next).len(), 1);
        assert_eq!(link.next_delivery_ms(), None);
    }
}
