//! Link profiles for the corridor this system targets.
//!
//! The numbers come from `docs/ARCHITECTURE.md` §1.4, where they are labelled as engineering
//! estimates pending measurement from a real Kenyan vantage point. They are good enough to exercise
//! the FEC schedule, the jitter buffer and the degradation ladder against something shaped like the
//! real path — and far better than testing on loopback, where every one of those mechanisms is
//! trivially satisfied and none of them is exercised at all.

/// How packet loss is distributed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LossModel {
    /// Independent per-packet loss.
    ///
    /// Convenient, and wrong for anything that has to survive real networks: it makes FEC look far
    /// better than it is, because a code that recovers one loss per protected set handles scattered
    /// loss trivially. Kept for isolating one variable at a time.
    Bernoulli {
        /// Probability any given packet is lost, `0.0..=1.0`.
        rate: f64,
    },

    /// Two-state Gilbert–Elliott burst loss. **The realistic model, and the default.**
    ///
    /// The link alternates between a good state that rarely drops and a bad state that drops
    /// heavily. A congested queue does not drop one packet in twenty at random; it drops several in
    /// a row. That distinction is what separates a FEC scheme that works from one that only looks
    /// like it does.
    GilbertElliott {
        /// Probability of entering the bad state per packet while in the good state.
        good_to_bad: f64,
        /// Probability of returning to the good state per packet while in the bad state.
        bad_to_good: f64,
        /// Loss probability while in the good state.
        loss_in_good: f64,
        /// Loss probability while in the bad state.
        loss_in_bad: f64,
    },
}

impl LossModel {
    /// A burst model whose long-run average loss is approximately `rate`.
    ///
    /// The transition probabilities are chosen so the bad state persists for roughly ten packets,
    /// which is the order of magnitude a congested queue produces at video packet rates.
    #[must_use]
    pub fn bursty(rate: f64) -> Self {
        let rate = rate.clamp(0.0, 0.95);
        // Mean bad-state run length is 1 / bad_to_good = 10 packets.
        let bad_to_good = 0.1;
        // Solve for the good→bad rate that yields the requested long-run loss, given that the bad
        // state loses 80% of what passes through it.
        let loss_in_bad = 0.8;
        let good_to_bad = if rate <= 0.0 {
            0.0
        } else {
            // Steady-state fraction of time in the bad state is p / (p + bad_to_good); the loss is
            // that fraction times `loss_in_bad`.
            let bad_fraction = (rate / loss_in_bad).min(0.95);
            (bad_fraction * bad_to_good) / (1.0 - bad_fraction)
        };
        LossModel::GilbertElliott {
            good_to_bad,
            bad_to_good,
            loss_in_good: 0.0,
            loss_in_bad,
        }
    }

    /// No loss at all.
    #[must_use]
    pub fn none() -> Self {
        LossModel::Bernoulli { rate: 0.0 }
    }
}

/// One end-to-end link.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LinkProfile {
    /// Human-readable name, for test output.
    pub name: &'static str,
    /// Base one-way delay in milliseconds. Half the round-trip time.
    pub base_delay_ms: u32,
    /// Standard deviation of the per-packet delay, in milliseconds.
    pub jitter_ms: u32,
    /// How loss is distributed.
    pub loss: LossModel,
    /// Probability a packet is delivered out of order relative to its neighbours.
    pub reorder_rate: f64,
    /// Bandwidth ceiling in bits per second. Packets beyond it queue, and a full queue drops.
    pub bandwidth_bps: u32,
    /// Maximum bytes the bottleneck queue holds before dropping.
    ///
    /// Real queue depth is what converts a bandwidth problem into a latency problem, which is the
    /// effect §2.7's pacer exists to avoid.
    pub queue_bytes: usize,
}

impl LinkProfile {
    /// Round-trip time implied by the base delay.
    #[must_use]
    pub fn rtt_ms(&self) -> u32 {
        self.base_delay_ms * 2
    }

    /// A local network. Present so a test can prove a mechanism is *not* firing when it should not.
    #[must_use]
    pub fn lan() -> Self {
        Self {
            name: "lan",
            base_delay_ms: 1,
            jitter_ms: 0,
            loss: LossModel::none(),
            reorder_rate: 0.0,
            bandwidth_bps: 1_000_000_000,
            queue_bytes: 1 << 20,
        }
    }

    /// US-East ↔ Nairobi over a healthy direct path.
    ///
    /// 110 ms each way, which is the middle of the 180–250 ms RTT the project targets.
    #[must_use]
    pub fn us_kenya_direct() -> Self {
        Self {
            name: "us-kenya-direct",
            base_delay_ms: 110,
            jitter_ms: 12,
            loss: LossModel::bursty(0.005),
            reorder_rate: 0.001,
            bandwidth_bps: 8_000_000,
            queue_bytes: 256 * 1024,
        }
    }

    /// US-East ↔ Nairobi relayed through a European TURN PoP.
    ///
    /// A relay adds a hop, so both delay and jitter rise. This is the path a session takes when
    /// hole punching fails, which on mobile-tethered Kenyan connections is not rare.
    #[must_use]
    pub fn us_kenya_relayed() -> Self {
        Self {
            name: "us-kenya-relayed",
            base_delay_ms: 130,
            jitter_ms: 20,
            loss: LossModel::bursty(0.02),
            reorder_rate: 0.002,
            bandwidth_bps: 4_000_000,
            queue_bytes: 192 * 1024,
        }
    }

    /// Evening-peak congestion: the condition the whole design exists for.
    ///
    /// 125 ms each way, 10% bursty loss, and 800 kbps. Every claim about FEC, the jitter buffer and
    /// the degradation ladder is really a claim about this profile.
    #[must_use]
    pub fn us_kenya_congested() -> Self {
        Self {
            name: "us-kenya-congested",
            base_delay_ms: 125,
            jitter_ms: 45,
            loss: LossModel::bursty(0.10),
            reorder_rate: 0.01,
            bandwidth_bps: 800_000,
            queue_bytes: 64 * 1024,
        }
    }

    /// A link on the edge of unusable: 250 ms RTT and 20% loss.
    ///
    /// Rung 7 of the degradation ladder — video collapses to stills and the session survives on
    /// input and control alone.
    #[must_use]
    pub fn hostile() -> Self {
        Self {
            name: "hostile",
            base_delay_ms: 125,
            jitter_ms: 60,
            loss: LossModel::bursty(0.20),
            reorder_rate: 0.02,
            bandwidth_bps: 400_000,
            queue_bytes: 32 * 1024,
        }
    }

    /// Every profile, for tests that sweep the range.
    #[must_use]
    pub fn all() -> [LinkProfile; 5] {
        [
            Self::lan(),
            Self::us_kenya_direct(),
            Self::us_kenya_relayed(),
            Self::us_kenya_congested(),
            Self::hostile(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;

    /// Measures the long-run loss rate a model actually produces.
    fn measure_loss(model: LossModel, packets: usize, seed: u64) -> f64 {
        let mut rng = Rng::new(seed);
        let mut in_bad = false;
        let mut lost = 0usize;

        for _ in 0..packets {
            let drop = match model {
                LossModel::Bernoulli { rate } => rng.chance(rate),
                LossModel::GilbertElliott {
                    good_to_bad,
                    bad_to_good,
                    loss_in_good,
                    loss_in_bad,
                } => {
                    in_bad = if in_bad {
                        !rng.chance(bad_to_good)
                    } else {
                        rng.chance(good_to_bad)
                    };
                    rng.chance(if in_bad { loss_in_bad } else { loss_in_good })
                }
            };
            if drop {
                lost += 1;
            }
        }
        lost as f64 / packets as f64
    }

    #[test]
    fn the_burst_model_hits_its_requested_average() {
        for target in [0.01, 0.05, 0.10, 0.20] {
            let measured = measure_loss(LossModel::bursty(target), 200_000, 42);
            let error = (measured - target).abs();
            assert!(
                error < target * 0.35 + 0.005,
                "requested {target}, measured {measured}"
            );
        }
    }

    #[test]
    fn burst_loss_actually_arrives_in_runs() {
        // The property that separates this from Bernoulli, and the reason FEC has to be evaluated
        // against it. If losses were independent, runs of five would be vanishingly rare at 10%.
        let mut rng = Rng::new(5);
        let model = LossModel::bursty(0.10);
        let LossModel::GilbertElliott {
            good_to_bad,
            bad_to_good,
            loss_in_good,
            loss_in_bad,
        } = model
        else {
            panic!("bursty() must produce a Gilbert-Elliott model");
        };

        let mut in_bad = false;
        let mut run = 0usize;
        let mut longest = 0usize;
        for _ in 0..100_000 {
            in_bad = if in_bad {
                !rng.chance(bad_to_good)
            } else {
                rng.chance(good_to_bad)
            };
            if rng.chance(if in_bad { loss_in_bad } else { loss_in_good }) {
                run += 1;
                longest = longest.max(run);
            } else {
                run = 0;
            }
        }
        assert!(
            longest >= 5,
            "longest loss run was only {longest}; this is not bursty"
        );
    }

    #[test]
    fn zero_loss_is_exactly_zero() {
        assert_eq!(measure_loss(LossModel::none(), 10_000, 1), 0.0);
        assert_eq!(measure_loss(LossModel::bursty(0.0), 10_000, 1), 0.0);
    }

    #[test]
    fn every_corridor_profile_respects_the_speed_of_light() {
        // New York to Nairobi is ~11,840 km; light in fibre covers that in ~59 ms one way. A
        // profile below that floor is not modelling this corridor, it is modelling a wish.
        for profile in LinkProfile::all() {
            if profile.name == "lan" {
                continue;
            }
            assert!(
                profile.base_delay_ms >= 59,
                "{} has a one-way delay of {} ms, below the geodesic floor",
                profile.name,
                profile.base_delay_ms
            );
            assert!(
                (180..=260).contains(&profile.rtt_ms()),
                "{} has an RTT of {} ms, outside the 180-250 ms target",
                profile.name,
                profile.rtt_ms()
            );
        }
    }

    #[test]
    fn profiles_get_worse_in_order() {
        // A sanity check on the ladder of profiles: each step down must actually be worse, or a
        // test sweeping them proves nothing.
        let direct = LinkProfile::us_kenya_direct();
        let congested = LinkProfile::us_kenya_congested();
        let hostile = LinkProfile::hostile();

        assert!(congested.bandwidth_bps < direct.bandwidth_bps);
        assert!(hostile.bandwidth_bps < congested.bandwidth_bps);
        assert!(congested.jitter_ms > direct.jitter_ms);
        assert!(hostile.jitter_ms > congested.jitter_ms);
    }
}
