//! Remote desktop viewer.
//!
//! Opens a window showing the host's screen and forwards keyboard and pointer input to it. With
//! `--headless` it instead writes decoded frames to disk as PNGs, which is how the pipeline is
//! checked in CI and on a machine with no display.
//!
//! ```sh
//! rda-client --peer K7M2-9QXR-4TVB --pin 314159
//! ```

mod session;
mod viewer;

use anyhow::{Context, Result};
use rda_crypto::identity::Identity;
use rda_crypto::keystore::{EphemeralKeystore, FileKeystore, Keystore};
use rda_proto::ids::DeviceId;
use std::path::PathBuf;
use std::time::Duration;
use tracing::info;
use tracing_subscriber::EnvFilter;

struct Args {
    server: String,
    peer: String,
    pin: String,
    seconds: u64,
    headless: bool,
    out: PathBuf,
    max_frames: usize,
    identity_path: Option<PathBuf>,
    ephemeral: bool,
}

fn parse_args() -> Result<Args> {
    let mut args = Args {
        server: "ws://127.0.0.1:8080/ws".to_string(),
        peer: String::new(),
        pin: String::new(),
        seconds: 0,
        headless: false,
        out: PathBuf::from("./frames"),
        max_frames: 30,
        identity_path: None,
        ephemeral: false,
    };

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let take = |i: &mut usize| -> Result<String> {
            *i += 1;
            argv.get(*i)
                .cloned()
                .with_context(|| format!("missing value for {}", argv[*i - 1]))
        };
        match argv[i].as_str() {
            "--server" => args.server = take(&mut i)?,
            "--peer" => args.peer = take(&mut i)?,
            "--pin" => args.pin = take(&mut i)?,
            "--seconds" => args.seconds = take(&mut i)?.parse()?,
            "--headless" => args.headless = true,
            "--out" => args.out = PathBuf::from(take(&mut i)?),
            "--max-frames" => args.max_frames = take(&mut i)?.parse()?,
            "--identity" => args.identity_path = Some(PathBuf::from(take(&mut i)?)),
            "--ephemeral" => args.ephemeral = true,
            "-h" | "--help" => {
                usage();
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown argument: {other}"),
        }
        i += 1;
    }
    anyhow::ensure!(
        !args.peer.is_empty(),
        "--peer is required (the host's device id)"
    );
    anyhow::ensure!(
        !args.pin.is_empty(),
        "--pin is required (shown on the host)"
    );
    Ok(args)
}

fn usage() {
    eprintln!(
        "rda-client — remote desktop viewer\n\
         \n\
         USAGE:\n    rda-client --peer <DEVICE-ID> --pin <PIN> [options]\n\
         \n\
         OPTIONS:\n\
             --server <URL>      signaling server (default ws://127.0.0.1:8080/ws)\n\
             --peer <ID>         host device id, as printed by `rda-host serve`\n\
             --pin <DIGITS>      six-digit PIN, as printed by `rda-host serve`\n\
             --seconds <N>       disconnect after N seconds (default 0 = until the window closes)\n\
             --identity <PATH>   device key file (default: the platform config directory)\n\
             --ephemeral         use a throwaway identity, leaving nothing on disk\n\
         \n\
         HEADLESS OPTIONS (no window; for CI and machines with no display):\n\
             --headless          write PNG frames instead of opening a window\n\
             --out <DIR>         where to write them (default ./frames)\n\
             --max-frames <N>    stop after this many (default 30)\n\
         \n\
         In the window, input is forwarded to the host. Press Escape or close the window to end\n\
         the session.\n"
    );
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("RDA_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = parse_args()?;
    let peer = DeviceId::parse(&args.peer).context("invalid --peer device id")?;

    // Persisted, so a host can recognise this viewer on a later connection rather than treating it
    // as a stranger every time — which is what an unattended grant or a trusted-device list needs.
    let identity = load_identity(&args)?;
    info!(device_id = %identity.device_id(), "client identity");

    let config = session::SessionConfig {
        server: args.server.clone(),
        peer,
        pin: args.pin.clone(),
        identity,
        duration: (args.seconds > 0).then(|| Duration::from_secs(args.seconds)),
    };

    if args.headless {
        run_headless(config, &args)
    } else {
        run_windowed(config)
    }
}

/// Runs with a window on this thread and the network on another.
///
/// The split is forced by the platforms: macOS requires the event loop on the process's first
/// thread and Windows requires messages pumped on the thread that created the window. It is also
/// simply correct — a decode that takes 12 ms must not be why a keystroke waits.
fn run_windowed(config: session::SessionConfig) -> Result<()> {
    let frames = std::sync::Arc::new(viewer::LatestFrame::default());
    let (input_tx, input_rx) = std::sync::mpsc::channel();
    let title = format!("rda — {}", config.peer);

    // Set by the network thread when the session ends, so the window does not outlive it.
    let session_over = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let network_over = session_over.clone();
    let network_frames = frames.clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("could not start the async runtime")?;

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let network = std::thread::Builder::new()
        .name("rda-session".into())
        .spawn(move || {
            let outcome = runtime.block_on(session::run_with_retry(
                config,
                session::FrameSink::Window(network_frames),
                Some(input_rx),
                Some(ready_tx),
            ));
            network_over.store(true, std::sync::atomic::Ordering::Relaxed);
            outcome
        })
        .context("could not start the session thread")?;

    // Nothing is drawn until there is a session to draw. A `RecvError` means the sender was
    // dropped, which means the thread returned — so the real error is on the thread, not here.
    if ready_rx.recv().is_err() {
        return match network.join() {
            Ok(Ok(_)) => anyhow::bail!("the session ended before it was established"),
            Ok(Err(e)) => Err(e),
            Err(_) => anyhow::bail!("the session thread panicked"),
        };
    }

    // 1280x720 until the first frame says otherwise; the window scales to whatever arrives.
    viewer::run(&title, 1280, 720, frames, input_tx, session_over)
        .context("the viewer window failed")?;

    match network.join() {
        Ok(Ok(report)) => {
            print_report(&report);
            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(_) => anyhow::bail!("the session thread panicked"),
    }
}

/// Runs with no window, writing PNGs.
fn run_headless(config: session::SessionConfig, args: &Args) -> Result<()> {
    std::fs::create_dir_all(&args.out)
        .with_context(|| format!("could not create {}", args.out.display()))?;
    let sink = session::FrameSink::Png {
        dir: args.out.clone(),
        max: args.max_frames,
        written: 0,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("could not start the async runtime")?;
    let report = runtime.block_on(session::run_with_retry(config, sink, None, None))?;
    print_report(&report);
    if report.written > 0 {
        println!(
            "\nopen {}/frame-0000.png to see the remote screen.",
            args.out.display()
        );
    } else {
        println!("\nNo frames decoded. If the host's screen never changed, that is the damage");
        println!("detection working as designed — move a window on the host and try again.");
    }
    Ok(())
}

fn print_report(report: &session::SessionReport) {
    println!();
    println!(
        "received  {} frames ({:.1} KiB)",
        report.received,
        report.bytes as f64 / 1024.0
    );
    println!("decoded   {}", report.decoded);
    if report.written > 0 {
        println!("written   {} PNGs", report.written);
    }
    // Only loss is measured here. RTT is the host's measurement — it sends the `Ping` and times the
    // `Pong` — so printing a number for it on this side would be inventing one.
    println!(
        "link      {:.1}% loss reported to the host",
        report.loss_fraction * 100.0
    );
    println!("playout   {} ms target", report.playout_target_ms);
}

/// Writes a decoded BGRA frame as a PNG.
///
/// The decoder hands back BGRA with a padded stride; PNG wants tightly packed RGB. Both conversions
/// happen here, and getting either wrong produces a picture that is obviously wrong rather than
/// subtly so — which is the point of writing an image at all.
pub fn write_png(path: &std::path::Path, frame: &rda_decode::decoder::DecodedFrame) -> Result<()> {
    let (w, h) = (frame.width as usize, frame.height as usize);
    let mut rgb = Vec::with_capacity(w * h * 3);
    for y in 0..h {
        let row = &frame.data[y * frame.stride..y * frame.stride + w * 4];
        for px in row.chunks_exact(4) {
            rgb.push(px[2]); // R
            rgb.push(px[1]); // G
            rgb.push(px[0]); // B
        }
    }

    let file = std::fs::File::create(path)?;
    let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), frame.width, frame.height);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    encoder.write_header()?.write_image_data(&rgb)?;
    Ok(())
}

/// Loads or creates this viewer's identity according to the arguments.
fn load_identity(args: &Args) -> Result<Identity> {
    if args.ephemeral {
        return Ok(EphemeralKeystore.load_or_create()?);
    }
    let keystore = match &args.identity_path {
        Some(path) => FileKeystore::at(path),
        None => FileKeystore::default_location("controller")?,
    };
    keystore.load_or_create().with_context(|| {
        format!(
            "could not use the identity at {}",
            keystore.path().display()
        )
    })
}
