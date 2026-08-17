//! The dedicated capture thread — `docs/ARCHITECTURE.md` §3.2.
//!
//! Capture runs on its own OS thread, never a tokio worker. The platform APIs block, some require
//! thread affinity or a specific desktop, and blocking a runtime worker starves every unrelated
//! task on it. Frames reach the async world through [`rda_capture::FrameSink`], which drops stale
//! frames rather than queueing them.
//!
//! The thread also owns recovery: `SessionLost` is a routine event — a monitor being plugged in, a
//! resolution change, a GPU switch — and must restart the capture session rather than end the
//! remote session.

use rda_capture::{
    CaptureConfig, CaptureError, DisplayInfo, FrameSink, FrameSource, ScreenCapturer,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// How long to wait for a frame before looping. Bounded so the stop flag is checked promptly.
const FRAME_TIMEOUT: Duration = Duration::from_millis(250);

/// Consecutive unrecoverable errors tolerated before the thread gives up.
const MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// Handle to a running capture thread.
pub struct CaptureThread {
    stop: Arc<AtomicBool>,
    restarts: Arc<AtomicU64>,
    handle: Option<std::thread::JoinHandle<()>>,
    displays: Vec<DisplayInfo>,
}

impl CaptureThread {
    /// Starts capturing a display on a dedicated thread.
    ///
    /// Returns the frame source and the display topology, which the host needs to tell the peer
    /// what geometry to expect and to denormalise incoming coordinates.
    pub fn spawn(
        mut capturer: Box<dyn ScreenCapturer>,
        display_id: u8,
        config: CaptureConfig,
    ) -> Result<(Self, FrameSource), CaptureError> {
        let displays = capturer.displays()?;
        capturer.start(display_id, config)?;

        let (sink, source) = rda_capture::sink::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let restarts = Arc::new(AtomicU64::new(0));

        let thread_stop = stop.clone();
        let thread_restarts = restarts.clone();
        let handle = std::thread::Builder::new()
            .name("rda-capture".to_string())
            .spawn(move || {
                run(
                    capturer,
                    display_id,
                    config,
                    sink,
                    thread_stop,
                    thread_restarts,
                );
            })
            .map_err(|e| {
                CaptureError::Unavailable(format!("could not spawn capture thread: {e}"))
            })?;

        Ok((
            Self {
                stop,
                restarts,
                handle: Some(handle),
                displays,
            },
            source,
        ))
    }

    /// The display topology observed at start.
    #[must_use]
    pub fn displays(&self) -> &[DisplayInfo] {
        &self.displays
    }

    /// How many times the capture session had to be rebuilt.
    ///
    /// A steadily climbing count means something is repeatedly invalidating the session — a
    /// flapping display or a GPU switching back and forth — which is worth surfacing rather than
    /// absorbing silently.
    #[must_use]
    pub fn restart_count(&self) -> u64 {
        self.restarts.load(Ordering::Relaxed)
    }

    /// Signals the thread to stop and waits for it.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for CaptureThread {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run(
    mut capturer: Box<dyn ScreenCapturer>,
    display_id: u8,
    config: CaptureConfig,
    sink: FrameSink,
    stop: Arc<AtomicBool>,
    restarts: Arc<AtomicU64>,
) {
    info!(
        backend = capturer.name(),
        display_id, "capture thread started"
    );
    let mut consecutive_failures = 0u32;

    while !stop.load(Ordering::Relaxed) {
        match capturer.next_frame(FRAME_TIMEOUT) {
            Ok(Some(frame)) => {
                consecutive_failures = 0;
                // An unchanged frame costs nothing to skip here and would cost an encode and a
                // transmission to publish. On an idle desktop this is the whole saving.
                if frame.is_worth_encoding() {
                    sink.publish(frame);
                }
            }
            Ok(None) => {
                consecutive_failures = 0;
            }
            Err(e) if e.is_recoverable() => {
                if matches!(e, CaptureError::Timeout) {
                    debug!("capture timed out; screen is idle");
                    continue;
                }
                // SessionLost: rebuild rather than end the remote session. Users consider plugging
                // in a monitor routine, and it should not disconnect them.
                warn!(error = %e, "capture session lost; restarting");
                restarts.fetch_add(1, Ordering::Relaxed);
                let _ = capturer.stop();
                match capturer.start(display_id, config) {
                    Ok(()) => info!("capture session restarted"),
                    Err(e) => {
                        consecutive_failures += 1;
                        warn!(error = %e, consecutive_failures, "capture restart failed");
                        if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                            warn!("giving up after repeated capture failures");
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(200));
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "unrecoverable capture error; capture thread stopping");
                break;
            }
        }
    }

    let _ = capturer.stop();
    info!("capture thread stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use rda_capture::backend::test_pattern::TestPatternCapturer;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn frames_reach_the_async_side() {
        let capturer = Box::new(TestPatternCapturer::small());
        let (mut thread, source) =
            CaptureThread::spawn(capturer, 0, CaptureConfig::default()).unwrap();

        let frame = source
            .recv_timeout(Duration::from_secs(2))
            .await
            .expect("a frame must cross the thread boundary");
        assert_eq!(frame.width, 640);
        assert_eq!(thread.displays().len(), 1);
        thread.stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_idle_screen_publishes_nothing() {
        // The saving that makes an idle session free. If this regresses, idle bandwidth silently
        // goes to full frame rate.
        let mut capturer = TestPatternCapturer::small();
        capturer.always_static = true;
        let (mut thread, source) =
            CaptureThread::spawn(Box::new(capturer), 0, CaptureConfig::default()).unwrap();

        assert!(
            source
                .recv_timeout(Duration::from_millis(300))
                .await
                .is_none(),
            "unchanged frames must not be published"
        );
        thread.stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lost_session_is_rebuilt_rather_than_fatal() {
        let mut capturer = TestPatternCapturer::small();
        capturer.inject_error = Some(CaptureError::SessionLost("simulated".into()));
        let (mut thread, source) =
            CaptureThread::spawn(Box::new(capturer), 0, CaptureConfig::default()).unwrap();

        // Capture must recover and keep producing: a resolution change should not end the session.
        let frame = source.recv_timeout(Duration::from_secs(2)).await;
        assert!(frame.is_some(), "capture must survive a recoverable error");
        assert_eq!(thread.restart_count(), 1);
        thread.stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stopping_is_idempotent_and_joins_the_thread() {
        let (mut thread, _source) = CaptureThread::spawn(
            Box::new(TestPatternCapturer::small()),
            0,
            CaptureConfig::default(),
        )
        .unwrap();
        thread.stop();
        thread.stop();
    }

    #[test]
    fn starting_on_an_unknown_display_fails_before_spawning() {
        let result = CaptureThread::spawn(
            Box::new(TestPatternCapturer::small()),
            7,
            CaptureConfig::default(),
        );
        assert!(matches!(result, Err(CaptureError::UnknownDisplay(7))));
    }
}
