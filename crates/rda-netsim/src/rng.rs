//! A small deterministic PRNG.
//!
//! Deliberately not `rand`: the point of this crate is that a given seed produces identical results
//! on every machine and across dependency upgrades. `rand`'s generators are explicitly permitted to
//! change their output between versions, which would silently invalidate every recorded baseline.
//!
//! xoshiro256++ is used because it is tiny, has good statistical properties for this purpose, and
//! can be written out in full so there is nothing to take on faith.

/// A seeded xoshiro256++ generator.
#[derive(Debug, Clone)]
pub struct Rng {
    state: [u64; 4],
}

impl Rng {
    /// Creates a generator from a seed.
    ///
    /// The seed is expanded with SplitMix64 first: xoshiro behaves badly when initialised with a
    /// state that is mostly zeroes, and a caller passing `0` or `1` is entirely likely.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        let mut z = seed;
        let mut next = || {
            z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut x = z;
            x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            x ^ (x >> 31)
        };
        Self {
            state: [next(), next(), next(), next()],
        }
    }

    /// Returns the next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        let result = self.state[0]
            .wrapping_add(self.state[3])
            .rotate_left(23)
            .wrapping_add(self.state[0]);
        let t = self.state[1] << 17;

        self.state[2] ^= self.state[0];
        self.state[3] ^= self.state[1];
        self.state[1] ^= self.state[2];
        self.state[0] ^= self.state[3];
        self.state[2] ^= t;
        self.state[3] = self.state[3].rotate_left(45);

        result
    }

    /// Returns a value uniformly distributed in `0.0..1.0`.
    pub fn next_f64(&mut self) -> f64 {
        // 53 bits is exactly the mantissa width, so every representable value in the range is
        // reachable and none is favoured.
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Returns `true` with probability `p`.
    pub fn chance(&mut self, p: f64) -> bool {
        if p <= 0.0 {
            return false;
        }
        if p >= 1.0 {
            return true;
        }
        self.next_f64() < p
    }

    /// Returns a value uniformly distributed in `low..=high`.
    pub fn range_u32(&mut self, low: u32, high: u32) -> u32 {
        if high <= low {
            return low;
        }
        let span = u64::from(high - low) + 1;
        low + (self.next_u64() % span) as u32
    }

    /// Returns an approximately normal deviate with the given mean and standard deviation.
    ///
    /// Sums twelve uniforms rather than using Box–Muller: the sum of twelve has mean 6 and variance
    /// 1 exactly, so subtracting 6 gives a unit normal with no transcendental functions and no
    /// chance of the `ln(0)` that trips naive Box–Muller implementations.
    pub fn normal(&mut self, mean: f64, std_dev: f64) -> f64 {
        let sum: f64 = (0..12).map(|_| self.next_f64()).sum();
        mean + (sum - 6.0) * std_dev
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_produces_the_same_sequence() {
        // The whole reason this crate does not use `rand`. Without it, a recorded baseline silently
        // stops meaning anything after a dependency bump.
        let a: Vec<u64> = (0..16)
            .scan(Rng::new(42), |r, _| Some(r.next_u64()))
            .collect();
        let b: Vec<u64> = (0..16)
            .scan(Rng::new(42), |r, _| Some(r.next_u64()))
            .collect();
        assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_diverge() {
        let a: Vec<u64> = (0..8)
            .scan(Rng::new(1), |r, _| Some(r.next_u64()))
            .collect();
        let b: Vec<u64> = (0..8)
            .scan(Rng::new(2), |r, _| Some(r.next_u64()))
            .collect();
        assert_ne!(a, b);
    }

    #[test]
    fn a_degenerate_seed_still_produces_varied_output() {
        // xoshiro behaves badly from a mostly-zero state, and a caller passing 0 is entirely
        // likely. SplitMix64 expansion is what prevents it.
        for seed in [0u64, 1, u64::MAX] {
            let mut rng = Rng::new(seed);
            let values: std::collections::HashSet<u64> = (0..64).map(|_| rng.next_u64()).collect();
            assert!(
                values.len() > 60,
                "seed {seed} produced only {} distinct values",
                values.len()
            );
        }
    }

    #[test]
    fn floats_stay_in_the_unit_interval() {
        let mut rng = Rng::new(7);
        for _ in 0..10_000 {
            let v = rng.next_f64();
            assert!((0.0..1.0).contains(&v), "produced {v}");
        }
    }

    #[test]
    fn chance_matches_its_probability() {
        let mut rng = Rng::new(3);
        let hits = (0..100_000).filter(|_| rng.chance(0.25)).count();
        // 25% of 100k, well inside sampling noise.
        assert!((24_000..26_000).contains(&hits), "got {hits} hits");
    }

    #[test]
    fn chance_handles_the_certain_and_impossible_cases() {
        let mut rng = Rng::new(9);
        assert!(!rng.chance(0.0));
        assert!(!rng.chance(-1.0));
        assert!(rng.chance(1.0));
        assert!(rng.chance(2.0));
    }

    #[test]
    fn ranges_are_inclusive_and_cover_their_span() {
        let mut rng = Rng::new(11);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2_000 {
            let v = rng.range_u32(10, 14);
            assert!((10..=14).contains(&v), "produced {v}");
            seen.insert(v);
        }
        assert_eq!(seen.len(), 5, "every value in the range must be reachable");
    }

    #[test]
    fn a_degenerate_range_returns_its_bound() {
        let mut rng = Rng::new(13);
        assert_eq!(rng.range_u32(5, 5), 5);
        assert_eq!(rng.range_u32(9, 3), 9);
    }

    #[test]
    fn the_normal_deviate_has_the_requested_moments() {
        let mut rng = Rng::new(17);
        let samples: Vec<f64> = (0..20_000).map(|_| rng.normal(100.0, 15.0)).collect();
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        let variance =
            samples.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / samples.len() as f64;

        assert!((mean - 100.0).abs() < 1.0, "mean was {mean}");
        assert!(
            (variance.sqrt() - 15.0).abs() < 1.0,
            "std dev was {}",
            variance.sqrt()
        );
    }
}
