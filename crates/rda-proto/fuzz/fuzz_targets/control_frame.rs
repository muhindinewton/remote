//! Fuzz target for the control frame parser.
//!
//! This parser is reachable by any peer that completes DTLS, and it runs on the host — the machine
//! whose keyboard and screen are at stake. `docs/ARCHITECTURE.md` §5.5 requires this target to
//! exist before the parser has users, not after it has a CVE.
//!
//! Run with: `cargo +nightly fuzz run control_frame`

#![no_main]

use libfuzzer_sys::fuzz_target;
use rda_proto::control::ControlFrame;

fuzz_target!(|data: &[u8]| {
    // Property 1: decoding arbitrary bytes never panics and never hangs.
    let Ok(frame) = ControlFrame::decode(data) else {
        return;
    };

    // Property 2: anything that decodes must re-encode. A payload we accepted but cannot express
    // means the decoder is more permissive than the encoder, which is how peers end up disagreeing
    // about what was sent.
    let encoded = frame.encode();

    // Property 3: the re-encoded form must decode back to an identical value. Without this,
    // a malicious peer could craft two distinct byte strings that decode to the same frame — or
    // worse, one that changes meaning on a round trip through a relay or a log replay.
    match ControlFrame::decode(&encoded) {
        Ok(reparsed) => {
            assert_eq!(
                frame, reparsed,
                "round trip changed the frame:\noriginal bytes: {data:02x?}\nre-encoded: {encoded:02x?}"
            );
        }
        Err(e) => panic!("re-encoding produced bytes we cannot parse: {e}\nbytes: {encoded:02x?}"),
    }
});
