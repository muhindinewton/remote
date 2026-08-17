//! Reconnection backoff with jitter.
//!
//! Jitter is not decoration. When a signaling server restarts, every client it was serving
//! reconnects at once; without jitter they retry in lockstep and the thundering herd knocks the
//! server over again, repeatedly. Full jitter — a uniform draw from `[0, delay]` rather than
//! `delay ± small` — is what actually decorrelates them.

use std::time::Duration;

/// Exponential backoff with full jitter.
#[derive(Debug, Clone)]
pub struct Backoff {
    base_ms: u64,
    max_ms: u64,
    factor: u32,
    attempt: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        // 500 ms base is comfortably above a 250 ms RTT, so the first retry does not fire while
        // the previous attempt's response is still in flight across the ocean.
        Self::new(500, 60_000, 2)
    }
}

impl Backoff {
    /// Builds a backoff schedule.
    #[must_use]
    pub fn new(base_ms: u64, max_ms: u64, factor: u32) -> Self {
        Self {
            base_ms,
            max_ms,
            factor: factor.max(2),
            attempt: 0,
        }
    }

    /// Returns the next delay and advances the schedule.
    pub fn next_delay(&mut self) -> Duration {
        let ceiling = self.ceiling();
        self.attempt = self.attempt.saturating_add(1);
        Duration::from_millis(jitter(ceiling))
    }

    /// The current ceiling before jitter is applied.
    #[must_use]
    pub fn ceiling(&self) -> u64 {
        self.base_ms
            .saturating_mul(u64::from(self.factor).saturating_pow(self.attempt.min(32)))
            .min(self.max_ms)
    }

    /// How many attempts have been made.
    #[must_use]
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Resets after a successful connection.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

fn jitter(ceiling: u64) -> u64 {
    use rand::Rng;
    if ceiling == 0 {
        return 0;
    }
    rand::thread_rng().gen_range(0..=ceiling)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceiling_grows_exponentially_then_saturates() {
        let mut b = Backoff::new(100, 1000, 2);
        assert_eq!(b.ceiling(), 100);
        b.next_delay();
        assert_eq!(b.ceiling(), 200);
        b.next_delay();
        assert_eq!(b.ceiling(), 400);
        b.next_delay();
        assert_eq!(b.ceiling(), 800);
        b.next_delay();
        assert_eq!(b.ceiling(), 1000, "must clamp to max");
    }

    #[test]
    fn a_long_outage_does_not_overflow() {
        // An agent left running through a multi-day outage keeps calling this.
        let mut b = Backoff::new(500, 60_000, 2);
        for _ in 0..10_000 {
            b.next_delay();
        }
        assert_eq!(b.ceiling(), 60_000);
    }

    #[test]
    fn delays_stay_within_the_ceiling() {
        let mut b = Backoff::new(1000, 10_000, 2);
        for _ in 0..100 {
            let ceiling = b.ceiling();
            assert!(b.next_delay().as_millis() as u64 <= ceiling);
        }
    }

    #[test]
    fn jitter_actually_decorrelates_clients() {
        // Ten "clients" backing off from the same attempt count must not agree on a delay, or a
        // server restart produces a synchronised retry storm.
        let delays: std::collections::HashSet<u128> = (0..10)
            .map(|_| {
                let mut b = Backoff::new(10_000, 60_000, 2);
                b.next_delay().as_millis()
            })
            .collect();
        assert!(delays.len() > 1, "full jitter must spread retries");
    }

    #[test]
    fn reset_returns_to_the_base_delay() {
        let mut b = Backoff::new(100, 10_000, 2);
        for _ in 0..5 {
            b.next_delay();
        }
        assert!(b.ceiling() > 100);
        b.reset();
        assert_eq!(b.ceiling(), 100);
        assert_eq!(b.attempt(), 0);
    }
}
