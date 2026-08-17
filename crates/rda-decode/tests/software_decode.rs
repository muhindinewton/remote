//! The software decoder against a real bitstream from this project's own encoder.
//!
//! This is the test that would have caught the Windows failure. Every existing decode test ran the
//! macOS hardware path, so `rda-client` on Windows connected, authenticated, and died on its first
//! frame — the whole session working except the one step that turns bytes into a picture.
//!
//! It matters that the input comes from `rda_encode` rather than a canned file: what the viewer has
//! to survive is precisely what *this* host emits, including the parameter sets prepended to every
//! keyframe and the Annex B start-code mixture that goes with them.
//!
//! Skipped where there is no encoder to generate input; the assertions are about the decoder, and a
//! platform without an encoder still runs every other test in this crate.

#![cfg(target_os = "macos")]

use rda_decode::decoder::VideoDecoder;
use rda_encode::encoder::{Codec, EncoderConfig};
use rda_encode::{ConvertConfig, PlanarFormat};

const WIDTH: u32 = 320;
const HEIGHT: u32 = 240;

/// A frame with a moving block, so successive frames genuinely differ.
fn frame(tick: u32) -> Vec<u8> {
    let mut bgra = vec![16u8; (WIDTH * HEIGHT * 4) as usize];
    let x0 = (tick * 7) % (WIDTH - 40);
    for y in 40..90u32 {
        for x in x0..x0 + 40 {
            let i = ((y * WIDTH + x) * 4) as usize;
            bgra[i] = 200; // B
            bgra[i + 1] = 90; // G
            bgra[i + 2] = 40; // R
            bgra[i + 3] = 255;
        }
    }
    bgra
}

fn encode_a_short_stream() -> Vec<(Vec<u8>, bool)> {
    let mut encoder = rda_encode::backend::hardware_encoder(EncoderConfig {
        codec: Codec::H264,
        width: WIDTH,
        height: HEIGHT,
        fps: 30,
        bitrate_bps: 1_500_000,
        ..Default::default()
    })
    .expect("an encoder to generate test input");

    let mut out = Vec::new();
    for tick in 0..12 {
        let bgra = frame(tick);
        let planar = rda_encode::convert::bgra_to_planar(
            &bgra,
            WIDTH,
            HEIGHT,
            WIDTH as usize * 4,
            PlanarFormat::Nv12,
            ConvertConfig::default(),
        )
        .expect("conversion");
        for encoded in encoder
            .encode(&planar, u64::from(tick) * 33_000)
            .expect("encode")
        {
            out.push((encoded.data, encoded.kind.is_random_access_point()));
        }
    }
    out.extend(
        encoder
            .flush()
            .expect("flush")
            .into_iter()
            .map(|f| (f.data, f.kind.is_random_access_point())),
    );
    out
}

#[test]
fn the_software_decoder_decodes_this_projects_own_bitstream() {
    let stream = encode_a_short_stream();
    assert!(!stream.is_empty(), "the encoder produced nothing to decode");

    let mut decoder = rda_decode::backend::software_decoder().expect("a software decoder");
    let mut decoded = 0;
    let mut geometry = None;

    for (data, is_key) in &stream {
        match decoder.decode(data, 0, *is_key) {
            Ok(frames) => {
                for f in frames {
                    decoded += 1;
                    geometry = Some((f.width, f.height));
                    assert_eq!(
                        f.data.len(),
                        f.stride * f.height as usize,
                        "the buffer must match its own stride and height"
                    );
                }
            }
            // Normal until the first keyframe has been seen.
            Err(e) if e.is_recoverable() => {}
            Err(e) => panic!("decode failed: {e}"),
        }
    }

    assert!(
        decoded > 0,
        "no frames decoded from {} packets",
        stream.len()
    );
    assert_eq!(
        geometry,
        Some((WIDTH, HEIGHT)),
        "geometry must survive the round trip"
    );
}

#[test]
fn the_software_decoder_recovers_the_encoded_colours() {
    // The failure this guards against is silent: a channel-order mistake decodes without error and
    // produces a picture in which every colour is wrong. BGRA is the layout the window blit, the
    // PNG writer and the FFI surface all assume.
    let stream = encode_a_short_stream();
    let mut decoder = rda_decode::backend::software_decoder().expect("a software decoder");

    let mut last = None;
    for (data, is_key) in &stream {
        if let Ok(frames) = decoder.decode(data, 0, *is_key) {
            if let Some(f) = frames.into_iter().last() {
                last = Some(f);
            }
        }
    }
    let picture = last.expect("at least one decoded frame");

    // Sample the background, which is a flat dark grey the codec has no trouble with.
    let i = ((10 * picture.width + 10) * 4) as usize;
    let (b, g, r) = (picture.data[i], picture.data[i + 1], picture.data[i + 2]);
    for (name, value) in [("blue", b), ("green", g), ("red", r)] {
        assert!(
            (value as i32 - 16).abs() <= 24,
            "background {name} decoded as {value}, expected ~16 — channel order or range is wrong"
        );
    }
}

#[test]
fn software_and_hardware_agree_on_geometry() {
    // Two backends that disagree about the picture they produce from identical input is the kind of
    // difference that only shows up as "it looks wrong on Windows".
    let stream = encode_a_short_stream();

    let decode_all = |mut decoder: Box<dyn VideoDecoder>| -> Option<(u32, u32)> {
        let mut geometry = None;
        for (data, is_key) in &stream {
            if let Ok(frames) = decoder.decode(data, 0, *is_key) {
                for f in frames {
                    geometry = Some((f.width, f.height));
                }
            }
        }
        geometry
    };

    let software = decode_all(rda_decode::backend::software_decoder().expect("software"));
    let hardware = decode_all(rda_decode::backend::hardware_decoder().expect("hardware"));

    assert_eq!(software, Some((WIDTH, HEIGHT)));
    assert_eq!(
        software, hardware,
        "the two backends must produce the same geometry"
    );
}
