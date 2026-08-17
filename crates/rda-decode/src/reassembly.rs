//! Putting fragmented video frames back together.
//!
//! SCTP will not carry a message larger than the negotiated ceiling and a keyframe is always
//! larger, so the sender splits frames into [`rda_proto::control::MAX_VIDEO_FRAGMENT`] pieces
//! ([`Payload::fragment_video`]). This is the other half.
//!
//! It sits before the jitter buffer rather than after: a partial frame is not a frame, and letting
//! one into the buffer would give the playout scheduler a deadline for something that can never be
//! decoded.
//!
//! The hard part is not assembly, it is knowing when to stop waiting. The video channel is
//! unreliable and unordered, so a missing fragment may be late or may be gone, and the difference
//! is only ever established by giving up. Three rules decide it:
//!
//! **Fragments arrive out of order, so a frame is not abandoned merely because a newer one
//! started.** On an unordered channel the last fragment of frame N routinely lands after the first
//! of frame N+1, and treating that as loss would discard perfectly good frames under normal
//! operation.
//!
//! **A frame is abandoned once it is older than the playout horizon.** Past that point it could
//! not be shown even if it completed, so holding its fragments only costs memory.
//!
//! **The number of frames in flight is capped.** Without a cap, a sender that never completes a
//! frame — buggy, or hostile — grows this map without limit.

use rda_encode::encoder::FrameKind;
use rda_encode::EncodedFrame;
use rda_proto::control::Payload;
use std::collections::BTreeMap;

/// How long an incomplete frame is held before it is written off.
///
/// Deliberately longer than the jitter buffer's target: the buffer is what absorbs late arrivals,
/// and abandoning a frame the buffer would still have accepted converts recoverable jitter into a
/// visible artefact. Deliberately shorter than a second, because a frame that late is worthless
/// whatever its fragments do.
pub const FRAGMENT_TIMEOUT_MS: u64 = 400;

/// How many partially-received frames may be in flight at once.
///
/// At 30 fps and a 400 ms timeout, honest traffic holds at most a dozen. Sixteen leaves headroom
/// without letting a peer that never completes a frame consume memory without bound.
pub const MAX_PARTIAL_FRAMES: usize = 16;

/// What happened to a fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReassemblyStats {
    /// Fragments accepted.
    pub fragments: u64,
    /// Frames fully reassembled.
    pub completed: u64,
    /// Frames abandoned with fragments missing.
    pub incomplete: u64,
    /// Fragments discarded because their frame had already been completed or abandoned.
    pub stale: u64,
    /// Fragments that contradicted an earlier fragment of the same frame.
    pub inconsistent: u64,
}

/// One frame under construction.
struct Partial {
    kind: u8,
    temporal_layer: u8,
    pts_us: u64,
    /// Fragment slots, `None` until filled. Sized from the count in the first fragment seen.
    slots: Vec<Option<Vec<u8>>>,
    filled: usize,
    first_seen_ms: u64,
}

impl Partial {
    fn is_complete(&self) -> bool {
        self.filled == self.slots.len()
    }

    /// Concatenates the fragments in index order.
    fn assemble(self) -> EncodedFrame {
        let total: usize = self.slots.iter().flatten().map(Vec::len).sum();
        let mut data = Vec::with_capacity(total);
        for slot in self.slots.into_iter().flatten() {
            data.extend_from_slice(&slot);
        }
        EncodedFrame {
            data,
            kind: match self.kind {
                1 => FrameKind::Keyframe,
                2 => FrameKind::LtrRecovery,
                _ => FrameKind::Delta,
            },
            pts_us: self.pts_us,
            sequence: 0,
            temporal_layer: self.temporal_layer,
            ltr_index: None,
            qp: None,
        }
    }
}

/// Reassembles fragmented video frames.
#[derive(Default)]
pub struct Reassembler {
    /// Keyed by frame id, ordered so the oldest is always at the front.
    partials: BTreeMap<u32, Partial>,
    stats: ReassemblyStats,
}

impl Reassembler {
    /// Builds an empty reassembler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current counters.
    #[must_use]
    pub fn stats(&self) -> ReassemblyStats {
        self.stats
    }

    /// How many frames are partially received.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.partials.len()
    }

    /// Accepts one fragment, returning the frame if it completed it.
    ///
    /// Payloads other than [`Payload::VideoFrame`] return `None` untouched, so a caller can hand
    /// this whatever arrived on the video channel without pre-filtering.
    pub fn accept(&mut self, payload: Payload, now_ms: u64) -> Option<EncodedFrame> {
        let Payload::VideoFrame {
            frame_id,
            fragment_index,
            fragment_count,
            kind,
            temporal_layer,
            pts_us,
            data,
        } = payload
        else {
            return None;
        };

        self.expire(now_ms);
        self.stats.fragments += 1;

        // The single-fragment case is the common one for delta frames, and skipping the map for it
        // keeps the steady state allocation-free beyond the frame itself.
        if fragment_count == 1 && !self.partials.contains_key(&frame_id) {
            self.stats.completed += 1;
            return Some(
                Partial {
                    kind,
                    temporal_layer,
                    pts_us,
                    slots: vec![Some(data)],
                    filled: 1,
                    first_seen_ms: now_ms,
                }
                .assemble(),
            );
        }

        let entry = self.partials.entry(frame_id).or_insert_with(|| Partial {
            kind,
            temporal_layer,
            pts_us,
            slots: vec![None; fragment_count as usize],
            filled: 0,
            first_seen_ms: now_ms,
        });

        // Fragments of one frame must agree about that frame. Disagreement means either a frame id
        // was reused while fragments were still in flight or the peer is confused; either way the
        // safe move is to drop the fragment rather than splice two frames' bitstreams together.
        if entry.slots.len() != fragment_count as usize || entry.pts_us != pts_us {
            self.stats.inconsistent += 1;
            return None;
        }

        let slot = &mut entry.slots[fragment_index as usize];
        if slot.is_some() {
            // A duplicate. Unreliable channels do retransmit, and the first copy is as good as
            // the second.
            self.stats.stale += 1;
            return None;
        }
        *slot = Some(data);
        entry.filled += 1;

        if entry.is_complete() {
            let partial = self.partials.remove(&frame_id).expect("just looked it up");
            self.stats.completed += 1;
            return Some(partial.assemble());
        }

        // Enforce the cap only after inserting, so the fragment that would have completed an old
        // frame is never the one evicted for arriving.
        while self.partials.len() > MAX_PARTIAL_FRAMES {
            let oldest = self
                .partials
                .iter()
                .min_by_key(|(_, p)| p.first_seen_ms)
                .map(|(id, _)| *id)
                .expect("non-empty above the cap");
            self.partials.remove(&oldest);
            self.stats.incomplete += 1;
        }
        None
    }

    /// Drops frames that can no longer be shown in time.
    fn expire(&mut self, now_ms: u64) {
        let expired: Vec<u32> = self
            .partials
            .iter()
            .filter(|(_, p)| now_ms.saturating_sub(p.first_seen_ms) > FRAGMENT_TIMEOUT_MS)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.partials.remove(&id);
            self.stats.incomplete += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragments(frame_id: u32, kind: u8, pts_us: u64, len: usize) -> Vec<Payload> {
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        Payload::fragment_video(frame_id, kind, 0, pts_us, &data)
    }

    #[test]
    fn a_single_fragment_frame_completes_immediately() {
        let mut r = Reassembler::new();
        let parts = fragments(1, 1, 1000, 100);
        assert_eq!(parts.len(), 1);
        let frame = r.accept(parts[0].clone(), 0).expect("completes");
        assert_eq!(frame.data.len(), 100);
        assert_eq!(frame.kind, FrameKind::Keyframe);
        assert_eq!(r.in_flight(), 0);
    }

    #[test]
    fn fragments_reassemble_to_the_original_bytes() {
        let len = rda_proto::control::MAX_VIDEO_FRAGMENT * 3 + 17;
        let original: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let parts = Payload::fragment_video(7, 1, 0, 5000, &original);
        assert_eq!(parts.len(), 4);

        let mut r = Reassembler::new();
        let mut out = None;
        for (i, part) in parts.into_iter().enumerate() {
            let done = r.accept(part, i as u64);
            if done.is_some() {
                out = done;
            }
        }
        assert_eq!(out.expect("completes").data, original);
    }

    #[test]
    fn out_of_order_fragments_still_reassemble() {
        // The video channel is unordered, so this is the normal case rather than the exception.
        let len = rda_proto::control::MAX_VIDEO_FRAGMENT * 2 + 1;
        let original: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let mut parts = Payload::fragment_video(9, 0, 0, 33_000, &original);
        parts.reverse();

        let mut r = Reassembler::new();
        let mut out = None;
        for part in parts {
            if let Some(frame) = r.accept(part, 0) {
                out = Some(frame);
            }
        }
        assert_eq!(out.expect("completes").data, original);
    }

    #[test]
    fn interleaved_frames_do_not_corrupt_each_other() {
        // Two frames in flight at once, fragments alternating. Nothing about the channel prevents
        // this, and mixing their bitstreams would produce a decode failure with no obvious cause.
        let a: Vec<u8> = vec![0xAA; rda_proto::control::MAX_VIDEO_FRAGMENT + 10];
        let b: Vec<u8> = vec![0xBB; rda_proto::control::MAX_VIDEO_FRAGMENT + 20];
        let pa = Payload::fragment_video(1, 1, 0, 1000, &a);
        let pb = Payload::fragment_video(2, 0, 0, 2000, &b);

        let mut r = Reassembler::new();
        assert!(r.accept(pa[0].clone(), 0).is_none());
        assert!(r.accept(pb[0].clone(), 0).is_none());
        let done_b = r.accept(pb[1].clone(), 0).expect("b completes");
        let done_a = r.accept(pa[1].clone(), 0).expect("a completes");
        assert_eq!(done_a.data, a);
        assert_eq!(done_b.data, b);
    }

    #[test]
    fn a_duplicate_fragment_is_ignored() {
        let parts = fragments(3, 0, 1000, rda_proto::control::MAX_VIDEO_FRAGMENT + 1);
        let mut r = Reassembler::new();
        assert!(r.accept(parts[0].clone(), 0).is_none());
        assert!(r.accept(parts[0].clone(), 0).is_none());
        assert_eq!(r.stats().stale, 1);
        assert!(r.accept(parts[1].clone(), 0).is_some());
    }

    #[test]
    fn an_incomplete_frame_is_abandoned_after_the_timeout() {
        let parts = fragments(4, 1, 1000, rda_proto::control::MAX_VIDEO_FRAGMENT * 2);
        let mut r = Reassembler::new();
        assert!(r.accept(parts[0].clone(), 0).is_none());
        assert_eq!(r.in_flight(), 1);

        // A later fragment of a different frame drives the clock forward past the timeout.
        let later = fragments(5, 0, 100_000, 10);
        assert!(r
            .accept(later[0].clone(), FRAGMENT_TIMEOUT_MS + 1)
            .is_some());
        assert_eq!(r.in_flight(), 0);
        assert_eq!(r.stats().incomplete, 1);

        // The missing fragment arriving now must not resurrect it.
        assert!(r
            .accept(parts[1].clone(), FRAGMENT_TIMEOUT_MS + 2)
            .is_none());
    }

    #[test]
    fn frames_in_flight_are_capped() {
        let mut r = Reassembler::new();
        // Every one of these is missing its second fragment, so none can ever complete.
        for id in 0..(MAX_PARTIAL_FRAMES as u32 * 3) {
            let parts = fragments(
                id,
                0,
                u64::from(id) * 1000,
                rda_proto::control::MAX_VIDEO_FRAGMENT + 1,
            );
            assert!(r.accept(parts[0].clone(), 0).is_none());
        }
        assert!(r.in_flight() <= MAX_PARTIAL_FRAMES);
        assert!(r.stats().incomplete > 0);
    }

    #[test]
    fn fragments_that_disagree_about_their_frame_are_refused() {
        let mut r = Reassembler::new();
        let parts = fragments(6, 1, 1000, rda_proto::control::MAX_VIDEO_FRAGMENT + 1);
        assert!(r.accept(parts[0].clone(), 0).is_none());

        // Same frame id, different timestamp: a reused id, or a peer splicing frames together.
        let Payload::VideoFrame { fragment_count, .. } = parts[1].clone() else {
            unreachable!()
        };
        let impostor = Payload::VideoFrame {
            frame_id: 6,
            fragment_index: 1,
            fragment_count,
            kind: 1,
            temporal_layer: 0,
            pts_us: 999_999,
            data: vec![0xFF; 8],
        };
        assert!(r.accept(impostor, 0).is_none());
        assert_eq!(r.stats().inconsistent, 1);
        assert_eq!(r.in_flight(), 1, "the honest partial frame survives");
    }

    #[test]
    fn a_non_video_payload_is_passed_over() {
        let mut r = Reassembler::new();
        assert!(r
            .accept(
                Payload::Unknown {
                    msg_type: 0x99,
                    body: vec![1, 2, 3]
                },
                0
            )
            .is_none());
        assert_eq!(r.stats().fragments, 0);
    }
}
