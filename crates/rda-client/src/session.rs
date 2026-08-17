//! The network half of the viewer: connect, authenticate, decode, forward input.
//!
//! Separated from `main` because it is driven by two different front ends — a window and a headless
//! PNG writer — and duplicating a session loop is how two front ends come to disagree about what a
//! session is.

use anyhow::{Context, Result};
use rda_crypto::identity::Identity;
use rda_decode::jitter::{JitterBuffer, PlayoutDecision};
use rda_proto::control::{Channel, ControlFrame, Payload};
use rda_proto::ids::DeviceId;
use rda_signal_client::ClientConfig;
use rda_telemetry::{LinkTelemetry, SequenceTracker};
use rda_transport::TransportEvent;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::viewer::{Framebuffer, InputEvent, LatestFrame};

/// How often the viewer reports what it is seeing back to the host.
///
/// One second matches `docs/PROTOCOL.md` §7.11 and RTCP receiver-report convention. Faster would
/// not help: the host's estimator is rate-limited to one change per RTT, and on this corridor an
/// RTT is a quarter of a second.
const QOS_INTERVAL: Duration = Duration::from_secs(1);

/// What the session does with each decoded frame.
pub enum FrameSink {
    /// Hand it to a window.
    Window(std::sync::Arc<LatestFrame>),
    /// Write the first `max` frames to disk as PNGs.
    Png {
        dir: std::path::PathBuf,
        max: usize,
        written: usize,
    },
}

/// Everything the session needs that is not a connection.
pub struct SessionConfig {
    pub server: String,
    pub peer: DeviceId,
    pub pin: String,
    pub identity: Identity,
    /// Stop after this long, or run until the peer or the user ends it when `None`.
    pub duration: Option<Duration>,
}

/// Counters worth printing when a session ends.
#[derive(Debug, Default, Clone, Copy)]
pub struct SessionReport {
    pub received: u64,
    pub decoded: u64,
    pub bytes: u64,
    pub written: usize,
    pub loss_fraction: f64,
    pub playout_target_ms: u32,
}

/// How many times a transient setup failure is retried before giving up.
///
/// Two failure modes here are timing accidents rather than misconfiguration: the pre-negotiated
/// channel-open race ([`rda_transport::Session::unopened_channels`]), and macOS gating inbound UDP
/// the first time a freshly built binary runs. Both clear on a retry, and a user who has to notice
/// the difference and rerun the command by hand is a user who concludes the product is broken.
const SETUP_ATTEMPTS: u32 = 3;

/// Connects and authenticates, retrying transient setup failures, then runs the session.
pub async fn run_with_retry(
    config: SessionConfig,
    sink: FrameSink,
    input: Option<mpsc::Receiver<InputEvent>>,
    ready: Option<mpsc::Sender<()>>,
) -> Result<SessionReport> {
    let mut sink = sink;
    for attempt in 1..=SETUP_ATTEMPTS {
        match run(&config, &mut sink, input.as_ref(), ready.as_ref()).await {
            Ok(report) => return Ok(report),
            Err(e) => {
                let transient = e
                    .downcast_ref::<rda_session::NegotiateError>()
                    .is_some_and(rda_session::NegotiateError::is_transient);
                if !transient || attempt == SETUP_ATTEMPTS {
                    return Err(e);
                }
                warn!(attempt, error = %e, "setup failed; retrying");
                println!("  attempt {attempt} failed ({e}); retrying…");
                tokio::time::sleep(Duration::from_millis(750)).await;
            }
        }
    }
    unreachable!("the loop returns on the final attempt")
}

/// Connects, authenticates, and runs until the session ends.
///
/// `ready` is signalled once the session is authenticated and frames can start arriving. The window
/// waits for it rather than opening immediately, because a window that opens before the connection
/// succeeds shows a black rectangle for thirty seconds and then an error in a terminal the user is
/// no longer looking at.
pub async fn run(
    config: &SessionConfig,
    sink: &mut FrameSink,
    input: Option<&mpsc::Receiver<InputEvent>>,
    ready: Option<&mpsc::Sender<()>>,
) -> Result<SessionReport> {
    let mut signal = rda_signal_client::connect(
        &config.server,
        &rda_signal_client::Identity::new(rda_signal_client::SigningKey::from_bytes(
            &config.identity.secret_bytes_for_keystore(),
        )),
        &ClientConfig {
            role: rda_proto::signaling::Role::Controller,
            agent: Some("rda-client/0.1.0".into()),
            ..Default::default()
        },
    )
    .await
    .with_context(|| format!("could not reach the signaling server at {}", config.server))?;

    info!(peer = %config.peer, "dialling");
    let negotiated = rda_session::connect_to_host(
        &mut signal,
        &config.peer,
        config.identity.public().to_b64(),
        Some("rda-client".into()),
    )
    .await
    .context("negotiation failed")?;

    let mut session = negotiated.session;
    info!("peer connection established; authenticating");

    let authenticated = rda_session::auth::authenticate_as_controller(
        &mut session,
        &negotiated.session_id,
        &config.identity,
        &config.pin,
    )
    .await
    .context("authentication failed")?;

    println!();
    println!("  connected to {}", authenticated.peer.device_id());
    println!("  granted: {:?}", authenticated.caps.to_names());
    println!("  compare with the host: {}", authenticated.sas.join(" · "));
    println!();

    if let Some(ready) = ready {
        let _ = ready.send(());
    }

    // Closed explicitly on every path. Dropping an `RTCPeerConnection` leaves its ICE agent alive
    // with sockets bound, which on the host — the side that serves session after session — degrades
    // negotiation until it times out entirely.
    let outcome = stream(&mut session, config, sink, input).await;
    if let Err(e) = session.close().await {
        warn!(error = %e, "the peer connection did not close cleanly");
    }
    outcome
}

async fn stream(
    session: &mut rda_transport::Session,
    config: &SessionConfig,
    sink: &mut FrameSink,
    input: Option<&mpsc::Receiver<InputEvent>>,
) -> Result<SessionReport> {
    // Hardware where it exists, software everywhere else. Demanding hardware here is what made the
    // viewer connect, authenticate and then die on its first frame on Windows and Linux.
    // `RDA_FORCE_SOFTWARE_DECODE=1` exercises the non-macOS path on a Mac. Without a way to do
    // that, the software decoder is only ever run by the platforms that cannot run the tests.
    let mut decoder = if std::env::var_os("RDA_FORCE_SOFTWARE_DECODE").is_some() {
        rda_decode::backend::software_decoder()
    } else {
        rda_decode::backend::best_decoder()
    }
    .map_err(|e| anyhow::anyhow!("no video decoder available: {e}"))?;
    info!(
        backend = decoder.name(),
        hardware = decoder.is_hardware(),
        "decoding"
    );
    if !decoder.is_hardware() {
        println!(
            "  decoder: {} (software — expect higher CPU use)",
            decoder.name()
        );
    }
    let mut jitter = JitterBuffer::new();
    let mut reassembler = rda_decode::Reassembler::new();
    let clock = Instant::now();

    // What the host cannot see for itself. SCTP abandons a fragment under `max_packet_life_time`
    // and tells the sender nothing, so loss is only observable here, from gaps in the wire
    // sequence. Reporting it back is what closes the rate-control loop.
    let mut telemetry = LinkTelemetry::new();
    let mut sequences = SequenceTracker::new();
    let mut last_report = Instant::now();

    // Per channel and per direction, as `docs/PROTOCOL.md` §6.4 requires. One shared counter would
    // put gaps in the pointer channel's sequence, which is the sequence the host uses to throw away
    // stale positions.
    let mut pointer_seq = 0u16;
    let mut keys_seq = 0u16;
    let mut control_seq = 0u16;

    let mut report = SessionReport::default();
    let deadline = config.duration.map(|d| tokio::time::Instant::now() + d);
    let mut quit = false;

    while !quit && deadline.is_none_or(|d| tokio::time::Instant::now() < d) {
        let now_ms = clock.elapsed().as_millis() as u64;

        // Forward whatever the user did. Drained without blocking so a quiet user costs nothing and
        // a busy one cannot stall the video path.
        if let Some(rx) = input {
            while let Ok(event) = rx.try_recv() {
                if matches!(event, InputEvent::Quit) {
                    quit = true;
                    break;
                }
                let (payload, seq) = match to_payload(event) {
                    Some((p, Channel::InputPointer)) => {
                        pointer_seq = pointer_seq.wrapping_add(1);
                        (p, pointer_seq)
                    }
                    Some((p, _)) => {
                        keys_seq = keys_seq.wrapping_add(1);
                        (p, keys_seq)
                    }
                    None => continue,
                };
                let frame = ControlFrame::new(payload, seq, now_ms as u32);
                if session.send(&frame).await.is_err() {
                    warn!("the session closed while sending input");
                    quit = true;
                    break;
                }
            }
        }

        // Report what this end sees, once a second, on `stats`.
        if last_report.elapsed() >= QOS_INTERVAL {
            last_report = Instant::now();
            let (delivered, lost) = sequences.take();
            telemetry.loss.sample(delivered, lost, now_ms);
            telemetry.playout_delay_ms = jitter.target_ms();
            let js = jitter.stats();
            telemetry.frames.dropped = js.dropped_late + js.dropped_overflow + js.dropped_reordered;

            control_seq = control_seq.wrapping_add(1);
            let qos = ControlFrame::new(
                Payload::QosReport(telemetry.to_qos_report()),
                control_seq,
                now_ms as u32,
            );
            let _ = session.send(&qos).await;
        }

        // A short timeout rather than a blocking wait: the input queue above has to be serviced at
        // interactive rates even when no video is arriving.
        match tokio::time::timeout(Duration::from_millis(5), session.events.recv()).await {
            Ok(Some(TransportEvent::Frame {
                channel: Channel::Video,
                frame,
            })) => {
                if let Payload::VideoFrame { ref data, .. } = frame.payload {
                    report.bytes += data.len() as u64;
                    sequences.observe(frame.header.sequence);
                }
                // Fragments become a frame here, before the jitter buffer: a partial frame is not a
                // frame, and giving the playout scheduler a deadline for something undecodable only
                // guarantees a miss.
                if let Some(mut assembled) = reassembler.accept(frame.payload, now_ms) {
                    report.received += 1;
                    assembled.sequence = report.received;
                    jitter.push(assembled, now_ms);
                }
            }
            // Answer the host's RTT probe immediately. `host_delay_us` reports how long the reply
            // sat here, so the host can subtract our scheduling latency and be left with the path.
            Ok(Some(TransportEvent::Frame {
                channel: Channel::Control,
                frame,
            })) => {
                if let Payload::Ping { token } = frame.payload {
                    let received = Instant::now();
                    control_seq = control_seq.wrapping_add(1);
                    let pong = ControlFrame::new(
                        Payload::Pong {
                            token,
                            host_delay_us: received.elapsed().as_micros().min(u128::from(u16::MAX))
                                as u16,
                        },
                        control_seq,
                        now_ms as u32,
                    );
                    let _ = session.send(&pong).await;
                }
            }
            Ok(Some(TransportEvent::Closed)) => {
                warn!("the host ended the session");
                break;
            }
            Ok(Some(_)) | Err(_) => {}
            Ok(None) => break,
        }

        if let PlayoutDecision::Play(frame) = jitter.poll(now_ms) {
            let is_key = frame.kind.is_random_access_point();
            match decoder.decode(&frame.data, frame.pts_us, is_key) {
                Ok(pictures) => {
                    for picture in pictures {
                        report.decoded += 1;
                        telemetry.frames.decoded += 1;
                        present(sink, &picture, &mut report)?;
                    }
                }
                // Normal while waiting for the first keyframe.
                Err(e) if e.is_recoverable() => {
                    tracing::debug!(error = %e, "waiting for a decodable frame");
                }
                Err(e) => warn!(error = %e, "decode failed"),
            }
        }
    }

    report.loss_fraction = telemetry.loss.fraction();
    report.playout_target_ms = jitter.target_ms();
    Ok(report)
}

fn present(
    sink: &mut FrameSink,
    picture: &rda_decode::decoder::DecodedFrame,
    report: &mut SessionReport,
) -> Result<()> {
    match sink {
        FrameSink::Window(slot) => slot.put(Framebuffer::from_decoded(picture)),
        FrameSink::Png { dir, max, written } => {
            if *written < *max {
                crate::write_png(&dir.join(format!("frame-{written:04}.png")), picture)?;
                *written += 1;
                report.written = *written;
            }
        }
    }
    Ok(())
}

/// Translates a viewer event into its wire payload and the channel it belongs on.
fn to_payload(event: InputEvent) -> Option<(Payload, Channel)> {
    Some(match event {
        InputEvent::Move {
            x_norm,
            y_norm,
            modifiers,
        } => (
            Payload::MouseMove {
                display_id: 0,
                flags: 0,
                x_norm,
                y_norm,
                modifiers,
            },
            Channel::InputPointer,
        ),
        InputEvent::Button {
            button,
            down,
            x_norm,
            y_norm,
            modifiers,
        } => (
            Payload::MouseButton {
                button,
                action: if down {
                    rda_proto::control::KeyAction::Down
                } else {
                    rda_proto::control::KeyAction::Up
                },
                // The position rides on the click itself: motion travels on an unreliable channel,
                // so a dropped move would otherwise land the click somewhere the user never aimed.
                x_norm,
                y_norm,
                modifiers,
                display_id: 0,
                click_count: 1,
            },
            Channel::InputKeys,
        ),
        InputEvent::Scroll {
            vertical,
            horizontal,
            modifiers,
        } => (
            Payload::MouseWheel {
                delta_v: vertical,
                delta_h: horizontal,
                modifiers,
                display_id: 0,
                flags: 0,
            },
            Channel::InputKeys,
        ),
        InputEvent::Key {
            usage,
            down,
            modifiers,
        } => (
            Payload::KeyEvent {
                usage_page: rda_proto::control::USAGE_PAGE_KEYBOARD,
                usage_id: usage,
                action: if down {
                    rda_proto::control::KeyAction::Down
                } else {
                    rda_proto::control::KeyAction::Up
                },
                flags: 0,
                modifiers,
            },
            Channel::InputKeys,
        ),
        InputEvent::Quit => return None,
    })
}
