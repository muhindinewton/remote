//! Host agent binary.
//!
//! Phase 3 scope: enumerate displays, verify permissions, start capture, and prove the input path
//! end to end under a real authorization gate. The signaling and WebRTC wiring from Phase 2 is
//! joined to this in Phase 4, once there is an encoded stream to carry.
//!
//! Run `rda-host doctor` first on any new machine — the permission failures on macOS and Linux are
//! silent by design, and a one-shot diagnostic is the difference between "it does not work" and a
//! specific instruction.

use anyhow::Context;
use rda_capture::{backend, CaptureConfig};
use rda_crypto::keystore::Keystore;
use rda_host::capture_thread::CaptureThread;
use rda_input::backend::platform_backend;
use std::time::Duration;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("RDA_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    match std::env::args().nth(1).as_deref() {
        Some("doctor") => doctor(),
        Some("capture") => capture_demo().await,
        Some("encode") => encode_demo().await,
        Some("serve") => rda_host::serve(parse_serve_options()?).await,
        Some("id") => print_identity(),
        Some(other) => {
            eprintln!("unknown command: {other}");
            usage();
            std::process::exit(2);
        }
        None => {
            usage();
            Ok(())
        }
    }
}

fn usage() {
    eprintln!(
        "rda-host — remote desktop host agent\n\
         \n\
         USAGE:\n    rda-host <COMMAND> [OPTIONS]\n\
         \n\
         COMMANDS:\n\
             doctor     Check capture and input permissions and report what is missing\n\
             capture    Capture this display for a few seconds and report frame statistics\n\
             encode     Capture and hardware-encode for a few seconds, reporting real bitrate\n\
             serve      Serve this screen to one controller over WebRTC\n\
             id         Print this device's identity\n\
         \n\
         SERVE OPTIONS:\n\
             --server <URL>     signaling server (default ws://127.0.0.1:8080/ws)\n\
             --fps <N>          target frame rate (default 30)\n\
             --bitrate <BPS>    target bitrate (default 3000000)\n\
             --seconds <N>      stop streaming after N seconds (default 0 = until disconnect)\n\
             --once             serve one session and exit, instead of looping\n\
             --allow-input      actually inject the controller's input into this machine\n\
             --pin <DIGITS>     use a fixed PIN instead of a random one (testing only)\n\
             --identity <PATH>  device key file (default: the platform config directory)\n\
             --ephemeral        use a throwaway identity, leaving nothing on disk\n"
    );
}

/// Parses the `serve` arguments.
///
/// Hand-rolled to keep the host binary free of a CLI dependency; there are five flags and a parser
/// crate would be more code than this.
fn parse_serve_options() -> anyhow::Result<rda_host::ServeOptions> {
    let mut options = rda_host::ServeOptions {
        server: "ws://127.0.0.1:8080/ws".to_string(),
        allow_input: false,
        fixed_pin: None,
        fps: 30,
        bitrate_bps: 3_000_000,
        seconds: 0,
        once: false,
        identity_path: None,
        ephemeral: false,
    };

    let argv: Vec<String> = std::env::args().skip(2).collect();
    let mut i = 0;
    while i < argv.len() {
        let take = |i: &mut usize| -> anyhow::Result<String> {
            *i += 1;
            argv.get(*i)
                .cloned()
                .with_context(|| format!("missing value for {}", argv[*i - 1]))
        };
        match argv[i].as_str() {
            "--server" => options.server = take(&mut i)?,
            "--fps" => options.fps = take(&mut i)?.parse()?,
            "--bitrate" => options.bitrate_bps = take(&mut i)?.parse()?,
            "--seconds" => options.seconds = take(&mut i)?.parse()?,
            "--allow-input" => options.allow_input = true,
            "--pin" => options.fixed_pin = Some(take(&mut i)?),
            "--identity" => options.identity_path = Some(take(&mut i)?.into()),
            "--ephemeral" => options.ephemeral = true,
            "--once" => options.once = true,
            other => anyhow::bail!("unknown option for serve: {other}"),
        }
        i += 1;
    }
    Ok(options)
}

fn print_identity() -> anyhow::Result<()> {
    let keystore = rda_crypto::keystore::FileKeystore::default_location("host")?;
    let identity = keystore.load_or_create()?;
    println!("device id:  {}", identity.device_id());
    println!("public key: {}", identity.public().to_b64());
    println!("stored at:  {}", keystore.path().display());
    Ok(())
}

/// Reports what works and what does not, with the specific remedy for each.
///
/// Both platforms fail silently by default — macOS returns black frames or ignores injected events
/// with no error at all — so guessing is not a viable diagnostic strategy for a user.
fn doctor() -> anyhow::Result<()> {
    println!("rda-host doctor\n");

    let mut problems = 0;

    print!("screen capture ......... ");
    match backend::platform_capturer() {
        Ok(capturer) => match capturer.displays() {
            Ok(displays) => {
                println!(
                    "ok ({} display(s), backend: {})",
                    displays.len(),
                    capturer.name()
                );
                for d in &displays {
                    println!(
                        "    [{}] {:<16} {}x{} @ {:.1}x{}",
                        d.id,
                        d.name,
                        d.width,
                        d.height,
                        d.scale(),
                        if d.primary { " (primary)" } else { "" }
                    );
                }
            }
            Err(e) => {
                println!("FAILED\n    {e}");
                problems += 1;
            }
        },
        Err(e) => {
            println!("FAILED\n    {e}");
            problems += 1;
        }
    }

    print!("hardware encoder ....... ");
    match rda_encode::backend::hardware_encoder(rda_encode::EncoderConfig {
        width: 640,
        height: 360,
        ..Default::default()
    }) {
        Ok(e) => println!("ok (backend: {}, hardware: {})", e.name(), e.is_hardware()),
        Err(e) => {
            println!("FAILED\n    {e}");
            problems += 1;
        }
    }

    print!("input injection ........ ");
    match platform_backend() {
        Ok(b) => println!("ok (backend: {})", b.name()),
        Err(e) => {
            println!("FAILED\n    {e}");
            problems += 1;
        }
    }

    println!();
    if problems == 0 {
        println!("All checks passed.");
    } else {
        println!("{problems} check(s) failed. The host cannot serve a session until they pass.");
        std::process::exit(1);
    }
    Ok(())
}

/// Captures for a few seconds and reports what the frame pipeline actually did.
async fn capture_demo() -> anyhow::Result<()> {
    let capturer = backend::platform_capturer().context("no capture backend available")?;
    let displays = capturer
        .displays()
        .context("could not enumerate displays")?;
    let target = displays.first().context("no displays available")?.clone();

    info!(
        name = %target.name,
        width = target.width,
        height = target.height,
        scale = target.scale(),
        "starting capture"
    );

    let (mut thread, source) = CaptureThread::spawn(
        capturer,
        target.id,
        CaptureConfig {
            target_fps: 30,
            ..Default::default()
        },
    )
    .context("could not start the capture thread")?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut frames = 0u64;
    let mut total_bytes = 0u64;

    while tokio::time::Instant::now() < deadline {
        match source.recv_timeout(Duration::from_millis(500)).await {
            Some(frame) => {
                frames += 1;
                if let rda_capture::Surface::Cpu { data, .. } = &frame.surface {
                    total_bytes += data.len() as u64;
                }
            }
            // Not an error: an idle screen produces no frames, which is the design working.
            None => info!("no frame in 500 ms (screen is idle)"),
        }
    }

    let stats = source.stats();
    thread.stop();

    println!("\ncaptured {frames} frame(s) in 5s");
    println!("  produced: {}", stats.produced);
    println!("  consumed: {}", stats.consumed);
    println!(
        "  dropped:  {} (encoder behind capture rate)",
        stats.dropped
    );
    println!(
        "  raw data: {:.1} MiB",
        total_bytes as f64 / (1024.0 * 1024.0)
    );
    if frames > 0 {
        println!(
            "\nUncompressed, that is {:.0} Mbps — which is why Phase 4 exists.",
            (total_bytes as f64 * 8.0 / 5.0) / 1_000_000.0
        );
    }

    if stats.dropped > stats.consumed && stats.produced > 10 {
        error!("more frames dropped than delivered; the target frame rate is above what this machine sustains");
    }
    Ok(())
}

/// Captures and hardware-encodes for a few seconds, reporting the bitrate actually achieved.
///
/// The point of the exercise: `capture` reports the raw rate, which is absurd; this reports what
/// goes on the wire, which is what has to fit through a Nairobi link.
async fn encode_demo() -> anyhow::Result<()> {
    use rda_encode::pipeline::{EncoderFactory, Pipeline};
    use rda_encode::{Codec, EncoderConfig};
    use rda_telemetry::LinkTelemetry;

    let capturer = backend::platform_capturer().context("no capture backend available")?;
    let displays = capturer
        .displays()
        .context("could not enumerate displays")?;
    let target = displays.first().context("no displays available")?.clone();

    // Encode at capture resolution. Downscaling belongs on the GPU alongside the colour
    // conversion, which is a Phase 5 item; doing it on the CPU here would measure the resampler
    // rather than the encoder.
    let (enc_w, enc_h) = (target.width & !1, target.height & !1);
    let config = EncoderConfig {
        codec: Codec::H264,
        width: enc_w,
        height: enc_h,
        fps: 30,
        bitrate_bps: 4_000_000,
        ..Default::default()
    };

    let factory: EncoderFactory = Box::new(rda_encode::backend::hardware_encoder);
    let mut pipeline = Pipeline::new(factory, enc_w, enc_h, config)
        .context("could not create a hardware encoder")?;

    info!(
        encoder = pipeline.encoder_name(),
        hardware = pipeline.is_hardware(),
        width = enc_w,
        height = enc_h,
        "starting encode"
    );

    let (mut thread, source) = CaptureThread::spawn(
        backend::platform_capturer()?,
        target.id,
        rda_capture::CaptureConfig {
            target_fps: 30,
            ..Default::default()
        },
    )
    .context("could not start the capture thread")?;

    // A representative cross-continent link: 4 Mbps, 220 ms RTT, 1% loss.
    let mut telemetry = LinkTelemetry::new();
    telemetry.bwe_bps = 4_000_000;

    let start = tokio::time::Instant::now();
    let deadline = start + Duration::from_secs(5);
    let mut raw_bytes = 0u64;

    while tokio::time::Instant::now() < deadline {
        let Some(frame) = source.recv_timeout(Duration::from_millis(500)).await else {
            continue;
        };
        if let rda_capture::Surface::Cpu { data, .. } = &frame.surface {
            raw_bytes += data.len() as u64;
        }
        let now_ms = start.elapsed().as_millis() as u64;
        telemetry.rtt.sample(220, now_ms);
        telemetry.loss.sample(99, 1, now_ms);
        pipeline.apply_telemetry(&telemetry, now_ms)?;

        // The ladder may have rebuilt the encoder at a smaller size; skip frames whose geometry
        // no longer matches rather than feeding the encoder something it will reject.
        if frame.width == pipeline.directive().scaled_dimensions(enc_w, enc_h).0
            || (frame.width == enc_w && frame.height == enc_h)
        {
            if let Err(e) = pipeline.step(&frame, now_ms) {
                warn!(error = %e, "encode step failed");
            }
        }
    }

    let stats = pipeline.stats();
    thread.stop();

    println!(
        "\nencoder: {} (hardware: {})",
        pipeline.encoder_name(),
        pipeline.is_hardware()
    );
    println!("  offered:  {}", stats.offered);
    println!("  encoded:  {}", stats.encoded);
    println!("  skipped:  {} (screen unchanged)", stats.skipped_static);
    println!("  paced:    {} (above target frame rate)", stats.paced_out);
    println!("  keyframes: {}", stats.keyframes);
    println!("  rebuilds: {}", stats.rebuilds);

    if stats.encoded > 0 {
        let mbps = (stats.bytes_out as f64 * 8.0 / 5.0) / 1e6;
        let raw_mbps = (raw_bytes as f64 * 8.0 / 5.0) / 1e6;
        println!("\n  raw:        {raw_mbps:>8.1} Mbps");
        println!("  compressed: {mbps:>8.1} Mbps");
        if raw_mbps > 0.0 {
            println!("  ratio:      {:>8.0}x", raw_mbps / mbps.max(0.001));
        }
        println!("  mean frame: {} bytes", stats.mean_frame_bytes());
    } else {
        println!("\nNo frames encoded. If the screen was static, that is the design working.");
    }
    Ok(())
}
