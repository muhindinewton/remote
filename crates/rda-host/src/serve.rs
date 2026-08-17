//! The host agent's serve loop: register, accept, authenticate, then stream and inject.
//!
//! This is where every earlier phase meets. Capture and encode from Phase 4 feed the video channel;
//! the authorization gate from Phase 3 decides whether input reaches the OS at all; the transport
//! and signaling from Phase 2 carry it.
//!
//! Two structural points:
//!
//! **The capture thread stays a thread.** It is spawned exactly as `rda-host capture` spawns it:
//! blocking OS APIs on a dedicated OS thread, handing frames across through a latest-frame-wins
//! slot. Moving it onto the async runtime to simplify this file would stall unrelated tasks every
//! time a capture call blocked.
//!
//! **Input cannot reach the OS without a grant.** [`Injector::apply`] takes a [`SessionGrant`], and
//! the only thing that produces one is a completed handshake. There is no path through this file
//! that injects anything before that, and it is the type system rather than review that says so.

use anyhow::{Context, Result};
use rda_capture::CaptureConfig;
use rda_crypto::keystore::{EphemeralKeystore, FileKeystore, Keystore};
use rda_encode::encoder::{Codec, EncoderConfig, FrameKind};
use rda_encode::pipeline::{EncoderFactory, Pipeline};
use rda_input::backend::{Backend, RecordingBackend};
use rda_input::{AuthMethod, DisplayGeometry, Injector, SessionGrant};
use rda_proto::caps::SessionCaps;
use rda_proto::control::{Channel, ControlFrame, Payload};
use rda_proto::signaling::{Message, RelayCredentials};
use rda_signal_client::ClientConfig;
use rda_telemetry::{BitrateEstimator, LinkTelemetry};
use rda_transport::TransportEvent;
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::capture_thread::CaptureThread;

/// How long a single fragment send may block before the session is written off.
const SEND_TIMEOUT: Duration = Duration::from_secs(2);

/// How often to ask the transport for its own measurements.
///
/// Only the relayed/direct classification comes back. webrtc-ice 0.12 reports both
/// `current_round_trip_time` and `available_outgoing_bitrate` as hardcoded zeroes, so RTT is
/// measured with `Ping`/`Pong` (`docs/PROTOCOL.md` §7.11) and bandwidth is estimated from the
/// viewer's loss reports. Neither number exists below this layer.
const STATS_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// How the host was told to run.
pub struct ServeOptions {
    /// Signaling server URL.
    pub server: String,
    /// Whether to actually inject received input, or only account for it.
    ///
    /// Defaults to off. Injection is total control of this machine, and a demo binary should not
    /// take it because a flag was left out.
    pub allow_input: bool,
    /// A fixed PIN, instead of a fresh random one.
    ///
    /// For scripted testing only. A random PIN is unguessable and single-use; a fixed one printed
    /// in a shell history is neither, which is why using this logs a warning every time.
    pub fixed_pin: Option<String>,
    /// Target frame rate.
    pub fps: u8,
    /// Target bitrate in bits per second.
    pub bitrate_bps: u32,
    /// Stop streaming after this many seconds, or run until the peer leaves when zero.
    pub seconds: u64,
    /// Serve a single session and exit, rather than looping.
    pub once: bool,
    /// Where to keep the device identity, or `None` for the platform default.
    pub identity_path: Option<std::path::PathBuf>,
    /// Generate a throwaway identity instead of persisting one.
    pub ephemeral: bool,
}

/// Registers with the signaling server and serves sessions until stopped.
///
/// The registration and the identity outlive individual sessions; everything else — the PIN, the
/// peer connection, the capability grant — is per session and is rebuilt each time. That boundary is
/// the security-relevant one: a PIN that survived a disconnect would be a standing password, and a
/// grant that survived one would let a peer that had merely reconnected keep privileges the operator
/// approved for someone else.
pub async fn serve(options: ServeOptions) -> Result<()> {
    // Loaded from disk, so this machine keeps the same address across restarts. A device id that
    // changed every launch would make every other feature that names a machine — a saved host list,
    // an unattended grant, a reconnect — meaningless.
    let identity = load_identity(&options)?;
    let signal_identity = rda_signal_client::Identity::new(
        rda_signal_client::SigningKey::from_bytes(&identity.secret_bytes_for_keystore()),
    );

    let mut signal = rda_signal_client::connect(
        &options.server,
        &signal_identity,
        &ClientConfig {
            role: rda_proto::signaling::Role::Host,
            agent: Some("rda-host/0.1.0".into()),
            ..Default::default()
        },
    )
    .await
    .with_context(|| format!("could not reach the signaling server at {}", options.server))?;

    println!();
    println!("  host ready — device id: {}", identity.device_id());
    println!("  signaling: {}", options.server);

    let mut sessions = 0u32;
    loop {
        match one_session(&mut signal, &identity, &options).await {
            Ok(()) => sessions += 1,
            // A failed session is not a failed host. A wrong PIN, a peer that gave up mid-ICE, a
            // network blip — every one of these ends this session and none of them should take the
            // machine offline, because the operator is not there to restart it.
            Err(e) => {
                sessions += 1;
                warn!(error = %e, "session ended early");
                println!("\n  session ended: {e}");
            }
        }
        if options.once {
            return Ok(());
        }
        println!("\n  ── session {sessions} over ──");
    }
}

/// Shows a PIN, waits for one peer, and serves it until it leaves.
async fn one_session(
    signal: &mut rda_signal_client::SignalConnection,
    identity: &rda_crypto::identity::Identity,
    options: &ServeOptions,
) -> Result<()> {
    // A fresh PIN per session, shown *before* waiting for anyone. That ordering is the whole user
    // story: the person at this machine reads the PIN aloud to whoever is about to connect, which
    // they cannot do if it only appears once that person has already connected. In a shipped host
    // this is the tray window, and the consent dialog that follows names what the remote party will
    // be able to do (`docs/ARCHITECTURE.md` §5.2).
    let clock = Instant::now();
    let pin = match &options.fixed_pin {
        Some(digits) => {
            warn!("serving with a fixed PIN; this is for testing and is not private");
            rda_crypto::pake::SessionPin::from_digits(digits, 0)
                .map_err(|e| anyhow::anyhow!("invalid --pin: {e}"))?
        }
        None => rda_crypto::pake::SessionPin::generate(0),
    };

    println!();
    println!("  ┌────────────────────┐");
    println!("  │   PIN:  {}     │", pin.display());
    println!("  └────────────────────┘");
    println!("  read this to whoever is connecting");
    println!();
    println!("  they run:");
    println!(
        "      rda-client --server {} --peer {} --pin {}",
        options.server,
        identity.device_id(),
        pin.display()
    );
    println!();
    println!("  waiting for a connection…");

    // Wait to be dialled.
    //
    // **A session begins at a `connect_request`, not at any envelope carrying a session id.** The
    // previous session's teardown leaves messages in this inbox — trailing ICE candidates, a
    // `peer_gone` — and every one of them is stamped with the *old* session id. Taking the id from
    // whatever arrived first therefore made every second session answer on a dead session id, so
    // the offer went nowhere and the viewer timed out after thirty seconds. Sessions alternated
    // between working and failing, which is exactly as confusing as it sounds.
    //
    // Credentials are matched to that id for the same reason, and may legitimately arrive first.
    let mut session_id: Option<String> = None;
    let mut credentials: Option<(Option<String>, RelayCredentials)> = None;

    let (session_id, credentials) = loop {
        let Some(envelope) = signal.inbox.recv().await else {
            anyhow::bail!("the signaling connection closed while waiting for a peer");
        };
        match envelope.msg {
            Message::RelayCredentials(c) => credentials = Some((envelope.sid.clone(), c)),
            Message::ConnectRequest(request) => {
                println!(
                    "  connection request from {}",
                    request.from_label.as_deref().unwrap_or("an unnamed device")
                );
                session_id = envelope.sid.clone();
            }
            other => {
                tracing::debug!(?other, sid = ?envelope.sid, "ignoring a message while waiting")
            }
        }

        // Credentials with no session id are server-wide and belong to whatever session is current.
        if let (Some(sid), Some((cred_sid, cred))) = (&session_id, &credentials) {
            if cred_sid.is_none() || cred_sid.as_ref() == Some(sid) {
                break (sid.clone(), cred.clone());
            }
        }
    };

    // What this host is willing to grant. `input` is offered only when it was explicitly enabled,
    // so a controller cannot be granted something the operator never agreed to.
    let granted = SessionCaps {
        view: true,
        input: options.allow_input,
        ..SessionCaps::default()
    };

    let negotiated =
        rda_session::accept_connection(signal, session_id.clone(), credentials, granted)
            .await
            .context("negotiation failed")?;
    let mut session = negotiated.session;
    info!("peer connection established");

    // From here the session must be closed on *every* exit, so the body is run and its result held
    // rather than propagated with `?`. Dropping an `RTCPeerConnection` does not close it: the ICE
    // agent keeps running, keeps its UDP sockets bound and keeps sending consent checks. A host
    // that serves session after session therefore accumulates live agents competing for the same
    // ports, and negotiation degrades from milliseconds to a thirty-second timeout after a handful
    // of connections.
    let outcome = authenticated_session(
        &mut session,
        &session_id,
        identity,
        &pin,
        granted,
        options,
        clock,
    )
    .await;
    if let Err(e) = session.close().await {
        warn!(error = %e, "the peer connection did not close cleanly");
    }
    outcome
}

/// Authenticates the connected peer and serves it. Split out so the caller can always close.
#[allow(clippy::too_many_arguments)]
async fn authenticated_session(
    session: &mut rda_transport::Session,
    session_id: &str,
    identity: &rda_crypto::identity::Identity,
    pin: &rda_crypto::pake::SessionPin,
    granted: SessionCaps,
    options: &ServeOptions,
    clock: Instant,
) -> Result<()> {
    let authenticated = rda_session::auth::authenticate_as_host(
        session,
        session_id,
        identity,
        pin,
        granted,
        clock.elapsed().as_millis() as u64,
    )
    .await
    .context("authentication failed")?;

    println!("  authenticated {}", authenticated.peer.device_id());
    println!(
        "  compare with the controller: {}",
        authenticated.sas.join(" · ")
    );
    println!("  granted: {:?}", authenticated.caps.to_names());

    // The grant exists only from here. Nothing above this line could have injected anything, and it
    // is dropped when this function returns, so it cannot outlive the session that earned it.
    let grant = SessionGrant::issue(
        session_id.to_string(),
        authenticated.peer.device_id().clone(),
        authenticated.caps,
        AuthMethod::SessionPin,
        clock.elapsed().as_millis() as u64,
    );

    stream(session, options, &grant, clock).await
}

/// Captures, encodes and sends until the deadline, injecting whatever input arrives.
async fn stream(
    session: &mut rda_transport::Session,
    options: &ServeOptions,
    grant: &SessionGrant,
    clock: Instant,
) -> Result<()> {
    let capturer = rda_capture::backend::platform_capturer().context("no capture backend")?;
    let display = capturer
        .displays()
        .context("could not enumerate displays")?
        .first()
        .context("no displays available")?
        .clone();

    // Encode at capture resolution, as `rda-host encode` does. Downscaling belongs on the GPU
    // beside the colour conversion; doing it on the CPU here would measure the resampler.
    let (enc_w, enc_h) = (display.width & !1, display.height & !1);

    // The pipeline, not the bare encoder: it owns the rate controller and the degradation ladder,
    // so what goes on the wire follows the link instead of a number chosen at startup. `--bitrate`
    // is the starting estimate now, not a fixed target.
    let factory: EncoderFactory = Box::new(rda_encode::backend::hardware_encoder);
    let mut pipeline = Pipeline::new(
        factory,
        enc_w,
        enc_h,
        EncoderConfig {
            codec: Codec::H264,
            width: enc_w,
            height: enc_h,
            fps: options.fps,
            bitrate_bps: options.bitrate_bps,
            ..Default::default()
        },
    )
    .context("could not create a hardware encoder")?;

    // The estimator exists because nothing below it supplies one: webrtc-rs reports
    // `available_outgoing_bitrate` as a hardcoded zero, and ships TWCC transport with no controller
    // on top. See `rda_telemetry::BitrateEstimator` for what that costs us.
    let mut telemetry = LinkTelemetry::new();
    let mut estimator = BitrateEstimator::new(options.bitrate_bps);
    telemetry.bwe_bps = estimator.estimate_bps();
    let mut last_stats_poll = Instant::now();

    // The backend is chosen here and only here. Without `--allow-input` every guard, validation and
    // reconciliation path still runs — the events simply land in a recorder instead of the OS,
    // which proves the path without handing over the machine.
    let backend: Box<dyn Backend> = if options.allow_input {
        rda_input::backend::platform_backend().context("no input backend")?
    } else {
        Box::new(RecordingBackend::default())
    };
    let mut injector = Injector::new(
        backend,
        vec![DisplayGeometry {
            id: display.id,
            x: display.x,
            y: display.y,
            width: display.width,
            height: display.height,
        }],
    );

    let (mut thread, source) = CaptureThread::spawn(
        rda_capture::backend::platform_capturer().context("no capture backend")?,
        display.id,
        CaptureConfig {
            target_fps: u32::from(options.fps),
            ..Default::default()
        },
    )
    .context("could not start the capture thread")?;

    println!();
    println!("  streaming {enc_w}x{enc_h} at {} fps", options.fps);
    println!(
        "  input: {}",
        if options.allow_input {
            "INJECTED into this machine"
        } else {
            "counted only — pass --allow-input to actually inject"
        }
    );
    if options.seconds == 0 {
        println!("  streaming until the viewer disconnects\n");
    } else {
        println!("  streaming for {}s\n", options.seconds);
    }

    // Zero means "as long as the peer wants it", which is what an actual session is. A fixed
    // deadline is a demo affordance, and making it the default meant a real user's screen went
    // dark mid-task for no reason they could see.
    let deadline = if options.seconds == 0 {
        None
    } else {
        Some(tokio::time::Instant::now() + Duration::from_secs(options.seconds))
    };
    let mut sent = 0u64;
    let mut bytes = 0u64;
    let mut received_input = 0u64;
    let mut reports_in = 0u64;
    let mut ping_token = 0u32;
    let mut ping_sent: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
    let mut seq = 0u16;
    let mut frame_id = 0u32;
    let mut closed = false;

    while !closed && deadline.is_none_or(|d| tokio::time::Instant::now() < d) {
        let now_ms = clock.elapsed().as_millis() as u64;

        // Drain inbound input first. Nothing here blocks: a controller sending nothing must not
        // hold up the video path, and a controller flooding must not starve it either.
        while let Ok(event) =
            tokio::time::timeout(Duration::from_millis(1), session.events.recv()).await
        {
            match event {
                Some(TransportEvent::Frame {
                    channel: Channel::InputKeys | Channel::InputPointer,
                    frame,
                }) => {
                    received_input += 1;
                    if let Err(e) = injector.apply(grant, &frame, now_ms) {
                        tracing::debug!(error = %e, "input refused");
                    }
                }
                // The viewer telling us what it actually received. This is the only loss signal
                // that exists: SCTP abandons fragments under `max_packet_life_time` and reports
                // nothing upward, so without this the sender is blind.
                Some(TransportEvent::Frame {
                    channel: Channel::Stats,
                    frame,
                }) => {
                    if let Payload::QosReport(report) = frame.payload {
                        reports_in += 1;
                        apply_qos(&mut telemetry, &mut estimator, &report, now_ms);
                    }
                }
                // The other half of the RTT measurement.
                Some(TransportEvent::Frame {
                    channel: Channel::Control,
                    frame,
                }) => {
                    if let Payload::Pong {
                        token,
                        host_delay_us,
                    } = frame.payload
                    {
                        if let Some(sent) = ping_sent.remove(&token) {
                            // The viewer's own processing time is subtracted, so what is left is
                            // the path rather than the peer's scheduling latency.
                            let elapsed = now_ms.saturating_sub(sent);
                            let peer_delay_ms = u64::from(host_delay_us) / 1000;
                            telemetry
                                .rtt
                                .sample(elapsed.saturating_sub(peer_delay_ms) as u32, now_ms);
                        }
                    }
                }
                Some(TransportEvent::Closed) | None => {
                    warn!("the peer disconnected");
                    closed = true;
                    break;
                }
                Some(_) => {}
            }
        }

        // Real RTT, from the STUN connectivity checks. Unlike the bandwidth estimate this one the
        // transport genuinely measures, so it is worth asking for.
        if last_stats_poll.elapsed() >= STATS_POLL_INTERVAL {
            last_stats_poll = Instant::now();
            session.poll_stats(now_ms).await;
            telemetry.relayed = session.telemetry().await.relayed;

            // Measure RTT ourselves. The transport will not: webrtc-ice reports
            // `current_round_trip_time` as a hardcoded zero, so a session that trusted it would
            // believe every link on earth is instantaneous — including a 220 ms one, where that
            // belief drives the NACK deadline and the jitter buffer straight into the wrong answer.
            ping_token = ping_token.wrapping_add(1);
            ping_sent.insert(ping_token, now_ms);
            // Only the newest few are worth an answer; anything older has been superseded.
            ping_sent.retain(|_, sent| now_ms.saturating_sub(*sent) < 10_000);
            let ping = ControlFrame::new(Payload::Ping { token: ping_token }, seq, now_ms as u32);
            seq = seq.wrapping_add(1);
            let _ = session.send(&ping).await;
        }

        // Fold the current view of the link into the encoder settings.
        if let Err(e) = pipeline.apply_telemetry(&telemetry, now_ms) {
            warn!(error = %e, "could not apply telemetry to the encoder");
        }

        // One captured frame, converted, encoded and sent.
        let Some(frame) = source.recv_timeout(Duration::from_millis(100)).await else {
            // Not an error: an unchanged screen produces no frames, which is damage detection
            // working rather than failing.
            continue;
        };
        // The pipeline decides whether this frame is worth encoding at all — an unchanged screen
        // and a frame arriving above the target rate both stop here, before any CPU is spent.
        let outcome = match pipeline.step(&frame, now_ms) {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::debug!(error = %e, "skipping a frame the pipeline refused");
                continue;
            }
        };

        for encoded in outcome.frames() {
            // Over the reassembly cap means the encoder is misconfigured rather than the picture
            // being complex. Dropping the frame beats sending something the peer will refuse.
            if encoded.data.len() > rda_proto::control::MAX_VIDEO_FRAME {
                warn!(bytes = encoded.data.len(), "dropping an oversized frame");
                continue;
            }
            let kind = match encoded.kind {
                FrameKind::Delta => 0,
                FrameKind::Keyframe => 1,
                FrameKind::LtrRecovery => 2,
            };
            // SCTP will not carry a message larger than the negotiated ceiling and a keyframe is
            // always larger, so every frame goes out as fragments.
            let fragments = Payload::fragment_video(
                frame_id,
                kind,
                encoded.temporal_layer,
                encoded.pts_us,
                &encoded.data,
            );
            frame_id = frame_id.wrapping_add(1);

            let mut whole_frame_sent = true;
            for fragment in fragments {
                let wire = ControlFrame::new(fragment, seq, now_ms as u32);
                seq = seq.wrapping_add(1);
                bytes += wire.encode().len() as u64;
                // Bounded, because an unbounded send is not merely slow but permanent: once the
                // peer stops reading, SCTP's send buffer fills and `send` waits for a window
                // update that a departed peer will never send. Two seconds is far longer than any
                // real path needs — eight round trips at 250 ms — and short enough that a dead
                // session is noticed rather than becoming a stuck process.
                match tokio::time::timeout(SEND_TIMEOUT, session.send(&wire)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        warn!(error = %e, "send failed; ending the session");
                        whole_frame_sent = false;
                        closed = true;
                        break;
                    }
                    Err(_) => {
                        warn!("send blocked for {SEND_TIMEOUT:?}; the peer has stopped reading");
                        whole_frame_sent = false;
                        closed = true;
                        break;
                    }
                }
            }
            if whole_frame_sent {
                sent += 1;
            }
        }
    }

    let capture_stats = source.stats();
    thread.stop();

    let stats = injector.stats();
    println!();
    println!(
        "video out     {sent} frames, {:.1} KiB",
        bytes as f64 / 1024.0
    );
    let pipeline_stats = pipeline.stats();
    println!(
        "capture       {} produced, {} dropped (encoder behind)",
        capture_stats.produced, capture_stats.dropped
    );
    println!(
        "encoder       {} encoded, {} skipped (screen static), {} paced, {} rebuilds",
        pipeline_stats.encoded,
        pipeline_stats.skipped_static,
        pipeline_stats.paced_out,
        pipeline_stats.rebuilds
    );
    let directive = pipeline.directive();
    // `unwrap_or(0)` would make "never measured" and "sub-millisecond" print identically, which is
    // the difference between a broken stats path and a loopback link.
    let rtt = match telemetry.rtt.smoothed_ms() {
        Some(ms) => format!("{ms} ms rtt"),
        None => "rtt unmeasured".to_string(),
    };
    println!(
        "link          {} reports in, {:.1}% loss, {}, bwe {:.2} Mbps",
        reports_in,
        telemetry.loss.fraction() * 100.0,
        rtt,
        f64::from(telemetry.bwe_bps) / 1e6
    );
    println!(
        "  settled on  rung {}: {} kbps, {} fps, {}% scale",
        directive.rung,
        directive.bitrate_bps / 1000,
        directive.fps,
        directive.scale_pct
    );
    println!("input in      {received_input} events");
    println!("  injected    {}", stats.injected);
    println!("  refused     {}", stats.refused);
    println!("  reconciled  {} synthetic releases", stats.reconciled);
    if sent == 0 {
        println!(
            "\nNothing was sent. If this screen never changed, that is damage detection working —\n\
             move a window and try again."
        );
    }
    Ok(())
}

/// Folds one viewer report into the sender's view of the link.
///
/// The report is the receiver's word about a path the sender cannot observe, so it is treated as
/// evidence rather than instruction: it feeds the estimators, and the estimators — with their own
/// windows and hysteresis — decide what the encoder does. A peer that reports nonsense moves the
/// rate within the bounds the ladder already permits, and no further.
fn apply_qos(
    telemetry: &mut LinkTelemetry,
    estimator: &mut BitrateEstimator,
    report: &rda_proto::control::QosReport,
    now_ms: u64,
) {
    // The wire carries a ratio, not counts. Reconstituting it against a fixed denominator preserves
    // the ratio the window needs, which is all `LossEstimator` uses it for.
    let lost = u32::from(report.loss_permille.min(1000));
    telemetry.loss.sample(1000 - lost, lost, now_ms);
    telemetry.jitter.sample(u32::from(report.jitter_ms), now_ms);
    telemetry.frames.decoded = u64::from(report.frames_decoded);
    telemetry.frames.dropped = u64::from(report.frames_dropped);
    telemetry.playout_delay_ms = u32::from(report.playout_delay_ms);

    estimator.observe_delay(u32::from(report.playout_delay_ms));
    telemetry.bwe_bps = estimator.update(telemetry.loss.fraction(), now_ms);
}

/// Loads or creates this device's identity according to the options.
fn load_identity(options: &ServeOptions) -> Result<rda_crypto::identity::Identity> {
    if options.ephemeral {
        warn!("running with a throwaway identity; this device id will not be recognised again");
        return Ok(EphemeralKeystore.load_or_create()?);
    }
    let keystore = match &options.identity_path {
        Some(path) => FileKeystore::at(path),
        None => FileKeystore::default_location("host")?,
    };
    let identity = keystore.load_or_create().with_context(|| {
        format!(
            "could not use the identity at {}",
            keystore.path().display()
        )
    })?;
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rda_proto::control::QosReport;

    fn report(loss_permille: u16, playout_ms: u16) -> QosReport {
        QosReport {
            loss_permille,
            playout_delay_ms: playout_ms,
            jitter_ms: 5,
            ..QosReport::default()
        }
    }

    /// Feeds `count` reports a second apart and returns the resulting estimate.
    fn run(loss_permille: u16, playout_ms: u16, count: u32, start_bps: u32) -> u32 {
        let mut telemetry = LinkTelemetry::new();
        let mut estimator = BitrateEstimator::new(start_bps);
        for i in 0..count {
            apply_qos(
                &mut telemetry,
                &mut estimator,
                &report(loss_permille, playout_ms),
                u64::from(i) * 1000,
            );
        }
        telemetry.bwe_bps
    }

    #[test]
    fn a_clean_link_raises_the_estimate() {
        assert!(run(0, 40, 10, 2_000_000) > 2_000_000);
    }

    #[test]
    fn a_lossy_link_lowers_the_estimate() {
        // The whole point of the loop: the viewer is the only party that can see loss, and saying
        // so has to move the encoder. Before this was wired, the host encoded at its startup
        // bitrate forever no matter what the link did.
        assert!(run(300, 40, 10, 4_000_000) < 4_000_000);
    }

    #[test]
    fn sustained_loss_walks_the_ladder_down() {
        let mut telemetry = LinkTelemetry::new();
        let mut estimator = BitrateEstimator::new(8_000_000);
        let mut ladder = rda_telemetry::LadderController::new();

        let clean = ladder.update(8_000_000, 0.0, 0).rung;
        assert_eq!(clean, 0, "a clean 8 Mbps link sits at the top rung");

        // The ladder is fed every iteration, as the serve loop feeds it: one call arms a
        // transition and a later one commits it, which is the hysteresis doing its job. A test
        // that called it twice would conclude, wrongly, that the ladder never moves.
        let mut degraded = clean;
        for i in 0..40u32 {
            let now = u64::from(i) * 1000;
            apply_qos(&mut telemetry, &mut estimator, &report(400, 40), now);
            degraded = ladder
                .update(telemetry.bwe_bps, telemetry.loss.fraction(), now)
                .rung;
        }

        assert!(
            degraded > clean,
            "sustained 40% loss must demote: {clean} -> {degraded}"
        );
    }

    #[test]
    fn a_growing_playout_buffer_holds_the_estimate_down() {
        // A deepening receive buffer means a queue is filling somewhere. It must not be read as
        // headroom, which is what an estimator watching only loss would conclude — and loss is
        // zero here, so loss alone would ramp at full speed.
        let mut growing = LinkTelemetry::new();
        let mut growing_est = BitrateEstimator::new(2_000_000);
        let mut playout = 30u16;
        for i in 0..8u32 {
            playout = playout.saturating_add(playout / 2 + 25);
            apply_qos(
                &mut growing,
                &mut growing_est,
                &report(0, playout),
                u64::from(i) * 1000,
            );
        }

        let mut stable = LinkTelemetry::new();
        let mut stable_est = BitrateEstimator::new(2_000_000);
        for i in 0..8u32 {
            apply_qos(
                &mut stable,
                &mut stable_est,
                &report(0, 30),
                u64::from(i) * 1000,
            );
        }

        assert!(
            growing.bwe_bps < stable.bwe_bps,
            "a filling buffer must ramp slower than a stable one: {} vs {}",
            growing.bwe_bps,
            stable.bwe_bps
        );
    }

    #[test]
    fn a_report_claiming_impossible_loss_cannot_break_the_estimator() {
        // The report is a peer's word about a path we cannot see. It moves the rate only within
        // the bounds the estimator already enforces.
        let settled = run(60_000, 40, 20, 4_000_000);
        assert!(settled >= rda_telemetry::MIN_BITRATE_BPS);
        assert!(settled <= 4_000_000);
    }
}
