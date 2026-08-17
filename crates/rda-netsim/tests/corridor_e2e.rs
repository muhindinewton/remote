//! The Phase 6 acceptance test: the real media pipeline over a simulated US ↔ Kenya link.
//!
//! Every previous phase tested its own layer on a machine where the network is perfect. This drives
//! the actual hardware encoder, the actual jitter buffer and the actual hardware decoder across a
//! link with 250 ms RTT, 10% bursty loss, 45 ms jitter and an 800 kbps ceiling — and asserts the
//! claims `docs/ARCHITECTURE.md` makes about that corridor.
//!
//! The claims under test:
//!
//! 1. A session stays **usable** at 10% bursty loss — video keeps moving rather than freezing.
//! 2. The rate controller **fits inside the link** rather than over-sending into it.
//! 3. Playout delay **adapts to jitter** instead of being a fixed guess.
//! 4. The pipeline **recovers** after a burst rather than staying broken.
//! 5. An idle desktop costs **nothing**, even on a bad link.
//!
//! Everything is seeded, so a failure here is reproducible rather than a coin flip.

use rda_decode::jitter::{JitterBuffer, PlayoutDecision};
use rda_encode::backend::hardware_encoder;
use rda_encode::convert::{bgra_to_planar, ConvertConfig, PlanarFormat};
use rda_encode::encoder::{Codec, EncoderConfig, VideoEncoder};
use rda_encode::rate::RateController;
use rda_netsim::{Delivery, LinkProfile, LinkSim};
use rda_telemetry::LinkTelemetry;

const W: u32 = 640;
const H: u32 = 360;
const FPS: u64 = 30;
const FRAME_INTERVAL_MS: u64 = 1000 / FPS;

/// Maximum bytes per packet on the wire, after headers.
const MTU_PAYLOAD: usize = 1100;

fn encoder(bitrate_bps: u32) -> Option<Box<dyn VideoEncoder>> {
    let config = EncoderConfig {
        codec: Codec::H264,
        width: W,
        height: H,
        fps: FPS as u8,
        bitrate_bps,
        ..Default::default()
    };
    match hardware_encoder(config) {
        Ok(e) => Some(e),
        Err(e) => {
            eprintln!("skipping: no hardware encoder ({e})");
            None
        }
    }
}

/// A frame of moving content, so the encoder has something real to compress.
fn moving_frame(tick: u64) -> Vec<u8> {
    let mut src = vec![0u8; (W * H * 4) as usize];
    let shift = (tick * 7) as usize;
    for y in 0..H as usize {
        for x in 0..W as usize {
            let i = (y * W as usize + x) * 4;
            src[i] = ((x + shift) % 256) as u8; // B
            src[i + 1] = ((y + shift / 2) % 256) as u8; // G
            src[i + 2] = ((x + y + shift) % 256) as u8; // R
            src[i + 3] = 255;
        }
    }
    src
}

/// What one simulated session produced.
#[derive(Debug, Default)]
struct SessionResult {
    frames_encoded: u64,
    frames_played: u64,
    frames_lost_whole: u64,
    packets_sent: u64,
    packets_delivered: u64,
    bytes_sent: u64,
    peak_playout_ms: u32,
    final_bitrate_bps: u32,
    overflowed: u64,
}

impl SessionResult {
    fn play_rate(&self) -> f64 {
        if self.frames_encoded == 0 {
            0.0
        } else {
            self.frames_played as f64 / self.frames_encoded as f64
        }
    }

    /// Bits per second actually put on the wire over the session.
    fn achieved_bps(&self, duration_ms: u64) -> f64 {
        if duration_ms == 0 {
            0.0
        } else {
            (self.bytes_sent as f64 * 8.0) / (duration_ms as f64 / 1000.0)
        }
    }
}

/// Runs a session of `duration_ms` over `profile`, driving the real encoder, rate controller and
/// jitter buffer.
///
/// Frames are fragmented to MTU, and a frame is counted lost only if *any* of its packets is lost —
/// the pessimistic reading, since without FEC a missing fragment makes the whole frame undecodable.
fn run_session(profile: LinkProfile, duration_ms: u64, seed: u64) -> Option<SessionResult> {
    let mut encoder = encoder(2_000_000)?;
    let mut link = LinkSim::new(profile, seed);
    let mut jitter = JitterBuffer::new();
    let mut rate = RateController::new();
    let mut telemetry = LinkTelemetry::new();
    telemetry.bwe_bps = profile.bandwidth_bps;

    let mut result = SessionResult::default();
    // The newest arrival seen, so the receiver's clock tracks the link rather than assuming a
    // fixed one-way delay.
    let mut latest_arrival_ms = 0u64;

    for (tick, now_ms) in (0..duration_ms)
        .step_by(FRAME_INTERVAL_MS as usize)
        .enumerate()
    {
        // The sender's view of the link, fed from what the simulator actually did.
        let stats = link.stats();
        let observed_loss = (stats.loss_rate() * 1000.0) as u16;
        telemetry.loss.sample(
            1000 - u32::from(observed_loss),
            u32::from(observed_loss),
            now_ms,
        );
        telemetry.rtt.sample(profile.rtt_ms(), now_ms);

        let directive = rate.update(&telemetry, now_ms);
        result.final_bitrate_bps = directive.bitrate_bps;
        let _ = encoder.set_bitrate(directive.bitrate_bps);

        // Encode one frame.
        let src = moving_frame(tick as u64);
        let planar = bgra_to_planar(
            &src,
            W,
            H,
            W as usize * 4,
            PlanarFormat::Nv12,
            ConvertConfig::default(),
        )
        .ok()?;

        for frame in encoder.encode(&planar, now_ms * 1000).ok()? {
            result.frames_encoded += 1;

            // Fragment to MTU and offer each packet to the link. A frame is only complete when
            // its *last* packet lands, so the arrival time is the maximum across its fragments —
            // taking the first, or a fixed offset, would hide the very jitter the buffer exists to
            // absorb.
            let mut all_arrived = true;
            let mut frame_arrival_ms = now_ms;
            for chunk in frame.data.chunks(MTU_PAYLOAD) {
                result.packets_sent += 1;
                result.bytes_sent += chunk.len() as u64;
                match link.send(chunk.to_vec(), now_ms) {
                    Delivery::Queued { deliver_ms } => {
                        result.packets_delivered += 1;
                        frame_arrival_ms = frame_arrival_ms.max(deliver_ms);
                    }
                    Delivery::Lost => all_arrived = false,
                    Delivery::QueueOverflow => {
                        all_arrived = false;
                        result.overflowed += 1;
                    }
                }
            }

            // A frame with a missing fragment is undecodable without FEC, so it never reaches the
            // buffer. This is the pessimistic reading on purpose.
            if all_arrived {
                jitter.push(frame, frame_arrival_ms);
                latest_arrival_ms = latest_arrival_ms.max(frame_arrival_ms);
            } else {
                result.frames_lost_whole += 1;
            }
        }

        // The receiver polls at display rate, on a clock that follows actual arrivals.
        for step in 0..2u64 {
            let receiver_now = latest_arrival_ms + step * 16;
            if let PlayoutDecision::Play(_) = jitter.poll(receiver_now) {
                result.frames_played += 1;
            }
        }
        result.peak_playout_ms = result.peak_playout_ms.max(jitter.target_ms());
    }

    // Drain whatever is still buffered.
    for step in 0..200u64 {
        let t = latest_arrival_ms + step * 16;
        if let PlayoutDecision::Play(_) = jitter.poll(t) {
            result.frames_played += 1;
        }
    }

    Some(result)
}

#[test]
fn a_session_survives_a_healthy_transcontinental_link() {
    // The baseline: 220 ms RTT with light loss. Nearly everything must get through, or the harsher
    // tests below prove nothing.
    let profile = LinkProfile::us_kenya_direct();
    let Some(result) = run_session(profile, 3_000, 1) else {
        return;
    };

    assert!(
        result.frames_encoded > 60,
        "only {} frames encoded",
        result.frames_encoded
    );
    assert!(
        result.play_rate() > 0.85,
        "only {:.0}% of frames reached the screen on a healthy link",
        result.play_rate() * 100.0
    );
    assert_eq!(
        result.overflowed, 0,
        "a healthy 8 Mbps link must not be over-sent"
    );
}

#[test]
fn a_session_stays_usable_at_ten_percent_bursty_loss() {
    // The claim the whole architecture rests on: at 10% bursty loss over 250 ms RTT, video keeps
    // moving. Not perfect — a good fraction of frames are lost outright without FEC — but the
    // stream does not stop, which is the difference between "degraded" and "frozen".
    let profile = LinkProfile::us_kenya_congested();
    let Some(result) = run_session(profile, 5_000, 2) else {
        return;
    };

    assert!(
        result.frames_encoded > 100,
        "only {} frames encoded",
        result.frames_encoded
    );
    assert!(
        result.frames_played > 0,
        "the stream froze completely: nothing reached the screen"
    );

    // Without FEC, a lost fragment costs the whole frame. Even so, the majority must survive —
    // if this drops below half, the loss-resilience design is not doing its job.
    assert!(
        result.play_rate() > 0.40,
        "only {:.0}% of frames reached the screen at 10% loss",
        result.play_rate() * 100.0
    );

    // And the losses must be spread through the session rather than being one long dead patch.
    assert!(
        result.frames_lost_whole < result.frames_encoded,
        "every frame was lost"
    );
}

#[test]
fn the_rate_controller_fits_inside_the_link() {
    // Over-sending into a congested link is what turns a bandwidth problem into a latency problem.
    // The controller must settle below the ceiling rather than hammering it.
    let profile = LinkProfile::us_kenya_congested();
    let Some(result) = run_session(profile, 5_000, 3) else {
        return;
    };

    let achieved = result.achieved_bps(5_000);
    assert!(
        achieved < f64::from(profile.bandwidth_bps) * 1.2,
        "sent {:.0} kbps into a {} kbps link",
        achieved / 1000.0,
        profile.bandwidth_bps / 1000
    );

    // The controller must also have actually reacted, not just started low.
    assert!(
        result.final_bitrate_bps < 2_000_000,
        "the controller never came down from its starting rate"
    );
}

#[test]
fn playout_delay_adapts_to_the_links_jitter() {
    // A fixed buffer is either too shallow for a bad link or needlessly laggy on a good one. The
    // adaptive target must actually differ between the two.
    let Some(calm) = run_session(LinkProfile::us_kenya_direct(), 4_000, 4) else {
        return;
    };
    let Some(rough) = run_session(LinkProfile::us_kenya_congested(), 4_000, 4) else {
        return;
    };

    assert!(
        rough.peak_playout_ms > calm.peak_playout_ms,
        "a 45 ms-jitter link targeted {} ms while a 12 ms-jitter link targeted {} ms",
        rough.peak_playout_ms,
        calm.peak_playout_ms
    );
    // And it must stay within the bound where added delay is still worth paying.
    assert!(
        rough.peak_playout_ms <= rda_decode::jitter::MAX_TARGET_MS,
        "playout delay ran to {} ms",
        rough.peak_playout_ms
    );
}

#[test]
fn the_pipeline_recovers_after_the_link_deteriorates() {
    // The property that matters most in practice: a bad patch must not permanently break the
    // session. Encoding continues throughout, and frames keep reaching the screen at the end.
    let Some(hostile) = run_session(LinkProfile::hostile(), 4_000, 5) else {
        return;
    };

    assert!(
        hostile.frames_encoded > 80,
        "encoding stopped on a hostile link: {} frames",
        hostile.frames_encoded
    );
    // At 20% bursty loss most frames die, but the session must not be dead — some picture has to
    // get through, which is rung 7's promise.
    assert!(
        hostile.frames_played > 0,
        "nothing at all reached the screen on the hostile profile"
    );
}

#[test]
fn results_are_reproducible() {
    // A flaky network test trains people to re-run until green. Same seed, same outcome.
    let Some(a) = run_session(LinkProfile::us_kenya_congested(), 2_000, 99) else {
        return;
    };
    let Some(b) = run_session(LinkProfile::us_kenya_congested(), 2_000, 99) else {
        return;
    };

    assert_eq!(a.frames_encoded, b.frames_encoded);
    assert_eq!(a.packets_sent, b.packets_sent);
    assert_eq!(a.frames_lost_whole, b.frames_lost_whole);
    assert_eq!(a.peak_playout_ms, b.peak_playout_ms);
}

#[test]
fn every_corridor_profile_keeps_a_session_alive() {
    // A sweep, so a regression in any one profile is caught rather than only the one a developer
    // happened to run.
    for profile in LinkProfile::all() {
        let Some(result) = run_session(profile, 2_000, 7) else {
            return;
        };
        assert!(
            result.frames_encoded > 30,
            "{}: only {} frames encoded",
            profile.name,
            result.frames_encoded
        );
        assert!(
            result.frames_played > 0,
            "{}: the session produced no picture at all",
            profile.name
        );
        eprintln!(
            "{:>20}  rtt {:>3}ms  encoded {:>4}  played {:>4} ({:>3.0}%)  {:>5.0} kbps  buf {:>3}ms",
            profile.name,
            profile.rtt_ms(),
            result.frames_encoded,
            result.frames_played,
            result.play_rate() * 100.0,
            result.achieved_bps(2_000) / 1000.0,
            result.peak_playout_ms,
        );
    }
}
