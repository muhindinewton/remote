//! The decoder acceptance test: pixels in, pixels out, through real hardware both ways.
//!
//! An encoder that produces a bitstream nothing can decode is indistinguishable from one that
//! works, right up until a user connects. This closes the loop: encode a known frame on the
//! hardware encoder, decode it on the hardware decoder, and check the picture survived.

use rda_decode::backend::hardware_decoder;
use rda_decode::decoder::{has_parameter_sets, DecodeError};
use rda_encode::backend::hardware_encoder;
use rda_encode::convert::{bgra_to_planar, ConvertConfig, PlanarFormat};
use rda_encode::encoder::{Codec, EncoderConfig, VideoEncoder};

const W: u32 = 320;
const H: u32 = 240;

/// A solid-colour BGRA source frame.
fn solid(r: u8, g: u8, b: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity((W * H * 4) as usize);
    for _ in 0..W * H {
        v.extend_from_slice(&[b, g, r, 255]);
    }
    v
}

fn encoder() -> Option<Box<dyn VideoEncoder>> {
    let config = EncoderConfig {
        codec: Codec::H264,
        width: W,
        height: H,
        fps: 30,
        bitrate_bps: 2_000_000,
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

#[test]
fn an_encoded_frame_decodes_back_to_a_picture() {
    let Some(mut enc) = encoder() else { return };
    let Ok(mut dec) = hardware_decoder() else {
        eprintln!("skipping: no hardware decoder");
        return;
    };

    let src = solid(200, 60, 60);
    let planar = bgra_to_planar(
        &src,
        W,
        H,
        W as usize * 4,
        PlanarFormat::Nv12,
        ConvertConfig::default(),
    )
    .unwrap();

    let encoded = enc.encode(&planar, 0).expect("encode must succeed");
    assert!(!encoded.is_empty(), "the first frame must produce output");

    // The first frame must be self-starting, or a receiver joining a stream never begins.
    assert!(
        has_parameter_sets(&encoded[0].data),
        "an IDR must carry its parameter sets in-band"
    );

    let decoded = dec
        .decode(&encoded[0].data, 0, true)
        .expect("decoding our own bitstream must succeed");
    assert!(!decoded.is_empty(), "a keyframe must decode to a picture");

    let frame = &decoded[0];
    assert_eq!(frame.width, W);
    assert_eq!(frame.height, H);
    assert!(
        frame.is_consistent(),
        "the decoded buffer must match its declared geometry"
    );
    assert!(dec.is_hardware());
}

#[test]
fn the_decoded_picture_resembles_the_source() {
    // Not a bit-exact comparison — H.264 is lossy and 4:2:0 discards chroma detail. But a solid
    // red frame that decodes to green means the colour matrix or plane order is wrong, which is
    // exactly the class of bug a round trip catches and a bitstream check does not.
    let Some(mut enc) = encoder() else { return };
    let Ok(mut dec) = hardware_decoder() else {
        return;
    };

    let (sr, sg, sb) = (200u8, 60u8, 60u8);
    let src = solid(sr, sg, sb);
    let planar = bgra_to_planar(
        &src,
        W,
        H,
        W as usize * 4,
        PlanarFormat::Nv12,
        ConvertConfig::default(),
    )
    .unwrap();

    let encoded = enc.encode(&planar, 0).unwrap();
    let decoded = dec.decode(&encoded[0].data, 0, true).unwrap();
    let frame = &decoded[0];

    // Sample the middle of the picture, away from any edge artefacts.
    let mid_row = (frame.height / 2) as usize;
    let mid_col = (frame.width / 2) as usize;
    let i = mid_row * frame.stride + mid_col * 4;
    let (db, dg, dr) = (frame.data[i], frame.data[i + 1], frame.data[i + 2]);

    let tolerance = 40u8;
    assert!(dr.abs_diff(sr) < tolerance, "red channel {dr} vs {sr}");
    assert!(dg.abs_diff(sg) < tolerance, "green channel {dg} vs {sg}");
    assert!(db.abs_diff(sb) < tolerance, "blue channel {db} vs {sb}");
}

#[test]
fn a_decoder_joining_mid_stream_waits_for_a_keyframe() {
    // The normal state of a receiver that just connected. Treating it as fatal would make every
    // session fail to start.
    let Some(mut enc) = encoder() else { return };
    let Ok(mut dec) = hardware_decoder() else {
        return;
    };

    let src = solid(120, 120, 120);
    let planar = bgra_to_planar(
        &src,
        W,
        H,
        W as usize * 4,
        PlanarFormat::Nv12,
        ConvertConfig::default(),
    )
    .unwrap();

    // Produce a delta frame by encoding twice and taking the second.
    enc.encode(&planar, 0).unwrap();
    let delta = enc.encode(&planar, 33_333).unwrap();
    if delta.is_empty() || has_parameter_sets(&delta[0].data) {
        eprintln!("skipping: this encoder repeats parameter sets on every frame");
        return;
    }

    let err = dec.decode(&delta[0].data, 33_333, false).unwrap_err();
    assert_eq!(err, DecodeError::AwaitingParameterSets);
    assert!(err.is_recoverable(), "a mid-stream join must not be fatal");
    assert!(
        err.wants_keyframe(),
        "the receiver must know to ask for one"
    );
}

#[test]
fn a_sequence_of_frames_decodes_continuously() {
    // One frame proving the plumbing is not the same as a stream staying decodable.
    let Some(mut enc) = encoder() else { return };
    let Ok(mut dec) = hardware_decoder() else {
        return;
    };

    let mut decoded_count = 0;
    for i in 0..20u64 {
        // Vary the picture so successive frames genuinely differ.
        let level = (i * 10) as u8;
        let src = solid(level, 128, 255 - level);
        let planar = bgra_to_planar(
            &src,
            W,
            H,
            W as usize * 4,
            PlanarFormat::Nv12,
            ConvertConfig::default(),
        )
        .unwrap();

        for frame in enc.encode(&planar, i * 33_333).unwrap() {
            match dec.decode(
                &frame.data,
                frame.pts_us,
                frame.kind.is_random_access_point(),
            ) {
                Ok(out) => decoded_count += out.len(),
                Err(e) if e.is_recoverable() => {}
                Err(e) => panic!("unrecoverable decode error on frame {i}: {e}"),
            }
        }
    }
    assert!(
        decoded_count >= 15,
        "only {decoded_count} of 20 frames decoded"
    );
}

#[test]
fn a_reset_decoder_recovers_from_the_next_keyframe() {
    let Some(mut enc) = encoder() else { return };
    let Ok(mut dec) = hardware_decoder() else {
        return;
    };

    let src = solid(50, 150, 200);
    let planar = bgra_to_planar(
        &src,
        W,
        H,
        W as usize * 4,
        PlanarFormat::Nv12,
        ConvertConfig::default(),
    )
    .unwrap();

    let first = enc.encode(&planar, 0).unwrap();
    assert!(!dec.decode(&first[0].data, 0, true).unwrap().is_empty());

    // Simulate an unrecoverable loss.
    dec.reset();

    // A fresh keyframe must bring it back rather than leaving the session wedged.
    let mut enc2 = encoder().unwrap();
    let recovery = enc2.encode(&planar, 100_000).unwrap();
    let out = dec.decode(&recovery[0].data, 100_000, true).unwrap();
    assert!(
        !out.is_empty(),
        "a keyframe after a reset must restart decoding"
    );
}

#[test]
fn garbage_never_panics_the_decoder() {
    // This parses data from the network. It must survive anything.
    let Ok(mut dec) = hardware_decoder() else {
        return;
    };
    for junk in [
        vec![],
        vec![0u8; 8],
        vec![0xFF; 256],
        vec![0, 0, 0, 1, 0x65, 0xFF, 0xFF],
        vec![
            0, 0, 0, 1, 0x67, 0xFF, 0, 0, 0, 1, 0x68, 0xFF, 0, 0, 0, 1, 0x65, 0xAB,
        ],
    ] {
        let _ = dec.decode(&junk, 0, false);
    }
}
