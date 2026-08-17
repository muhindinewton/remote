//! The bridge from the blocking capture thread to the async world.
//!
//! Latest-frame-wins is the only correct backpressure policy for live screen content. A queued
//! stale frame has *negative* value: delivering it late spends bandwidth on a picture the user has
//! already moved past, and delays the frame they actually want. So the sink holds exactly one
//! frame, and a new capture overwrites an unconsumed one.
//!
//! Dropped frames are counted rather than silently discarded — an encoder that cannot keep up is a
//! real condition the degradation ladder needs to see.

use crate::Frame;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

#[derive(Debug, Default)]
struct Shared {
    dropped: AtomicU64,
    produced: AtomicU64,
    consumed: AtomicU64,
}

/// The capture thread's end: writes frames.
pub struct FrameSink {
    slot: Arc<std::sync::Mutex<Option<Frame>>>,
    notify: Arc<Notify>,
    shared: Arc<Shared>,
}

/// The async end: reads frames.
pub struct FrameSource {
    slot: Arc<std::sync::Mutex<Option<Frame>>>,
    notify: Arc<Notify>,
    shared: Arc<Shared>,
}

/// Creates a linked sink and source.
#[must_use]
pub fn channel() -> (FrameSink, FrameSource) {
    let slot = Arc::new(std::sync::Mutex::new(None));
    let notify = Arc::new(Notify::new());
    let shared = Arc::new(Shared::default());
    (
        FrameSink {
            slot: slot.clone(),
            notify: notify.clone(),
            shared: shared.clone(),
        },
        FrameSource {
            slot,
            notify,
            shared,
        },
    )
}

/// Statistics from the frame pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkStats {
    /// Frames captured.
    pub produced: u64,
    /// Frames handed to the encoder.
    pub consumed: u64,
    /// Frames overwritten before anyone read them.
    ///
    /// A nonzero value means the encoder is behind the capture rate. That is not necessarily a
    /// fault — it is exactly what should happen when the ladder has cut the frame rate — but a
    /// persistently high value means the target fps is set above what the machine can encode.
    pub dropped: u64,
}

impl FrameSink {
    /// Publishes a frame, replacing any unconsumed one.
    ///
    /// Never blocks and never fails. The capture thread must not be able to stall on a slow
    /// consumer, because a stalled capture thread means a frozen screen rather than a late one.
    pub fn publish(&self, frame: Frame) {
        self.shared.produced.fetch_add(1, Ordering::Relaxed);
        // A poisoned lock means a consumer panicked mid-read. Recovering the guard is correct here:
        // the protected value is a single frame with no invariant to violate, and refusing to
        // capture because a previous reader panicked would turn a recoverable fault into a dead
        // session.
        let mut slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        if slot.replace(frame).is_some() {
            self.shared.dropped.fetch_add(1, Ordering::Relaxed);
        }
        drop(slot);
        self.notify.notify_one();
    }

    /// Current statistics.
    #[must_use]
    pub fn stats(&self) -> SinkStats {
        stats_of(&self.shared)
    }
}

impl FrameSource {
    /// Takes the pending frame, if any, without waiting.
    pub fn try_recv(&self) -> Option<Frame> {
        let mut slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        let frame = slot.take();
        drop(slot);
        if frame.is_some() {
            self.shared.consumed.fetch_add(1, Ordering::Relaxed);
        }
        frame
    }

    /// Waits for the next frame.
    ///
    /// Re-checks the slot after being notified rather than trusting the notification, because a
    /// second `publish` can land between the notify and the wake.
    pub async fn recv(&self) -> Frame {
        loop {
            if let Some(frame) = self.try_recv() {
                return frame;
            }
            self.notify.notified().await;
        }
    }

    /// Waits for the next frame, giving up after `timeout`.
    pub async fn recv_timeout(&self, timeout: std::time::Duration) -> Option<Frame> {
        tokio::time::timeout(timeout, self.recv()).await.ok()
    }

    /// Current statistics.
    #[must_use]
    pub fn stats(&self) -> SinkStats {
        stats_of(&self.shared)
    }
}

fn stats_of(shared: &Shared) -> SinkStats {
    SinkStats {
        produced: shared.produced.load(Ordering::Relaxed),
        consumed: shared.consumed.load(Ordering::Relaxed),
        dropped: shared.dropped.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DirtyRegion, PixelFormat, Surface};
    use std::time::{Duration, Instant};

    fn frame(sequence: u64) -> Frame {
        Frame {
            surface: Surface::Cpu {
                data: Arc::from(vec![0u8; 4].into_boxed_slice()),
                stride: 4,
                format: PixelFormat::Bgra8,
            },
            display_id: 0,
            width: 1,
            height: 1,
            captured_at: Instant::now(),
            dirty: DirtyRegion::Full,
            sequence,
        }
    }

    #[tokio::test]
    async fn a_published_frame_is_received() {
        let (sink, source) = channel();
        sink.publish(frame(1));
        assert_eq!(source.recv().await.sequence, 1);
    }

    #[tokio::test]
    async fn the_latest_frame_wins() {
        // The core policy: a slow consumer must get the *newest* frame, not the oldest queued one.
        let (sink, source) = channel();
        for i in 1..=5 {
            sink.publish(frame(i));
        }
        assert_eq!(source.recv().await.sequence, 5);
        assert_eq!(sink.stats().dropped, 4);
    }

    #[tokio::test]
    async fn publishing_never_blocks_on_a_stalled_consumer() {
        // A capture thread that can block is a frozen screen, not a late one.
        let (sink, _source) = channel();
        let start = Instant::now();
        for i in 0..10_000 {
            sink.publish(frame(i));
        }
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(sink.stats().produced, 10_000);
        assert_eq!(sink.stats().dropped, 9_999);
    }

    #[tokio::test]
    async fn try_recv_returns_none_when_empty() {
        let (sink, source) = channel();
        assert!(source.try_recv().is_none());
        sink.publish(frame(1));
        assert!(source.try_recv().is_some());
        assert!(
            source.try_recv().is_none(),
            "a frame must only be delivered once"
        );
    }

    #[tokio::test]
    async fn recv_waits_for_a_later_publish() {
        let (sink, source) = channel();
        let handle = tokio::spawn(async move { source.recv().await.sequence });
        tokio::time::sleep(Duration::from_millis(20)).await;
        sink.publish(frame(42));
        assert_eq!(handle.await.unwrap(), 42);
    }

    #[tokio::test]
    async fn recv_timeout_gives_up_on_an_idle_desktop() {
        let (_sink, source) = channel();
        assert!(source
            .recv_timeout(Duration::from_millis(30))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn statistics_account_for_every_frame() {
        let (sink, source) = channel();
        sink.publish(frame(1));
        sink.publish(frame(2));
        source.recv().await;
        sink.publish(frame(3));
        source.recv().await;

        let s = sink.stats();
        assert_eq!(s.produced, 3);
        assert_eq!(s.consumed, 2);
        assert_eq!(s.dropped, 1);
        assert_eq!(s.consumed + s.dropped, s.produced);
    }

    #[tokio::test]
    async fn a_panicking_consumer_does_not_wedge_the_capture_thread() {
        // Lock poisoning must not turn a recoverable fault into a dead session.
        let (sink, source) = channel();
        let slot = source.slot.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = slot.lock().unwrap();
            panic!("consumer died holding the lock");
        }));
        sink.publish(frame(7));
        assert_eq!(source.try_recv().map(|f| f.sequence), Some(7));
    }
}
