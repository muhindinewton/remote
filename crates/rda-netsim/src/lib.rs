//! Deterministic network impairment simulation — `docs/ARCHITECTURE.md` §2.
//!
//! Every latency and loss claim in the architecture is an assertion about a link nobody involved in
//! development can actually reach. This crate makes those claims testable: it models the US ↔ Kenya
//! corridor closely enough that the FEC schedule, the jitter buffer and the degradation ladder can
//! be exercised against it in CI, on a laptop, in milliseconds.
//!
//! Three modelling decisions matter more than the rest:
//!
//! **Loss is bursty, not Bernoulli.** Real packet loss arrives in runs — a congested queue drops
//! several consecutive packets, not one in twenty at random. Independent per-packet loss makes FEC
//! look far better than it is, because a code that recovers one loss per protected set handles
//! scattered loss trivially and burst loss not at all. [`LossModel::GilbertElliott`] is the
//! two-state chain that produces realistic runs, and it is the default.
//!
//! **Delay has a floor.** The speed of light in fibre over the New York–Nairobi geodesic is about
//! 59 ms one way, and real routing via Europe adds more. A profile whose base delay is below that
//! floor is not modelling this corridor.
//!
//! **Everything is seeded.** A flaky network test is worse than no network test: it trains people
//! to re-run until green. Given the same seed, this produces byte-identical results on every
//! machine and every run.
//!
//! What it does **not** model: cross traffic reacting to our sending rate, middlebox behaviour, or
//! the TCP-friendliness of competing flows. Those need a real testbed, and
//! [`scripts/impair.sh`](../../../scripts/impair.sh) drives one.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod link;
pub mod profile;
pub mod rng;

pub use link::{Delivery, LinkSim, LinkStats, Packet};
pub use profile::{LinkProfile, LossModel};
pub use rng::Rng;
