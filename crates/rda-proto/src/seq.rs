//! RFC 1982 serial number arithmetic for the 16-bit control frame sequence space.
//!
//! Naive `<` comparison on a wrapping counter is non-conforming and produces a very specific,
//! very confusing bug: after ~65 536 events the receiver decides every new frame is stale and the
//! cursor freezes permanently. `docs/PROTOCOL.md` §6.4 requires serial arithmetic.

/// A 16-bit sequence number compared under RFC 1982 serial arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Serial(pub u16);

impl Serial {
    /// Half the sequence space. Differences at or beyond this are undefined by RFC 1982; we treat
    /// them as "not newer" so a wildly out-of-range value cannot be used to force stale-acceptance.
    const HALF: u16 = 1 << 15;

    /// Returns the next sequence number, wrapping.
    #[must_use]
    pub fn next(self) -> Self {
        Serial(self.0.wrapping_add(1))
    }

    /// Returns `true` if `self` is strictly newer than `other` in the circular sequence space.
    ///
    /// Returns `false` for the exactly-opposite point on the circle, where ordering is undefined.
    #[must_use]
    pub fn is_newer_than(self, other: Serial) -> bool {
        let diff = self.0.wrapping_sub(other.0);
        diff != 0 && diff < Self::HALF
    }

    /// Returns `true` if `self` should be discarded as stale relative to the last applied value.
    ///
    /// Used for the unreliable pointer channel, where a late-arriving old position has negative
    /// value: applying it teleports the cursor backwards.
    #[must_use]
    pub fn is_stale_against(self, last_applied: Serial) -> bool {
        !self.is_newer_than(last_applied)
    }
}

impl From<u16> for Serial {
    fn from(v: u16) -> Self {
        Serial(v)
    }
}

/// Tracks the highest sequence number applied on one channel in one direction.
#[derive(Debug, Clone, Copy, Default)]
pub struct SerialTracker {
    last: Option<Serial>,
}

impl SerialTracker {
    /// Creates a tracker that has not yet seen any frame.
    #[must_use]
    pub fn new() -> Self {
        Self { last: None }
    }

    /// Records `seq` if it is newer than everything seen so far.
    ///
    /// Returns `true` if the caller should apply the frame, `false` if it is stale and must be
    /// discarded. The first frame of a session is always accepted.
    pub fn accept(&mut self, seq: Serial) -> bool {
        match self.last {
            None => {
                self.last = Some(seq);
                true
            }
            Some(last) if seq.is_newer_than(last) => {
                self.last = Some(seq);
                true
            }
            Some(_) => false,
        }
    }

    /// The most recently accepted sequence number, if any.
    #[must_use]
    pub fn last(&self) -> Option<Serial> {
        self.last
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_ordering() {
        assert!(Serial(5).is_newer_than(Serial(4)));
        assert!(!Serial(4).is_newer_than(Serial(5)));
        assert!(!Serial(4).is_newer_than(Serial(4)));
    }

    #[test]
    fn wraps_correctly() {
        // This is the case a naive `<` comparison gets wrong.
        assert!(Serial(0).is_newer_than(Serial(65535)));
        assert!(Serial(5).is_newer_than(Serial(65530)));
        assert!(!Serial(65535).is_newer_than(Serial(0)));
    }

    #[test]
    fn opposite_point_is_not_newer() {
        // Exactly half the space away: RFC 1982 leaves this undefined. We must not treat it as
        // newer, or an attacker could inject a value that resets our notion of "current".
        assert!(!Serial(0).is_newer_than(Serial(32768)));
        assert!(!Serial(32768).is_newer_than(Serial(0)));
    }

    #[test]
    fn tracker_rejects_replays_and_reorders() {
        let mut t = SerialTracker::new();
        assert!(t.accept(Serial(100)));
        assert!(t.accept(Serial(101)));
        assert!(!t.accept(Serial(101)), "duplicate must be rejected");
        assert!(
            !t.accept(Serial(99)),
            "reordered older frame must be rejected"
        );
        assert!(t.accept(Serial(102)));
    }

    #[test]
    fn tracker_survives_a_full_wrap() {
        let mut t = SerialTracker::new();
        let mut s = Serial(65530);
        assert!(t.accept(s));
        for _ in 0..100 {
            s = s.next();
            assert!(t.accept(s), "sequence {} rejected across wrap", s.0);
        }
    }
}
