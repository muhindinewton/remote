//! Fuzz target for the signaling envelope parser.
//!
//! This one is reachable *pre-authentication* by anyone who can open a socket to the signaling
//! server, which makes it the most exposed parser in the system.
//!
//! Run with: `cargo +nightly fuzz run signaling_json`

#![no_main]

use libfuzzer_sys::fuzz_target;
use rda_proto::signaling::Envelope;

fuzz_target!(|data: &[u8]| {
    let Ok(env) = Envelope::from_slice(data) else {
        return;
    };

    // Anything we accepted must serialise, and the result must parse back. A message that survives
    // parsing but cannot be re-emitted would break the server's forwarding path, which re-wraps
    // and re-serialises everything it routes.
    let Ok(encoded) = env.to_vec() else {
        panic!("accepted an envelope we cannot re-serialise");
    };
    assert!(
        Envelope::from_slice(&encoded).is_ok(),
        "re-serialised envelope failed to parse: {}",
        String::from_utf8_lossy(&encoded)
    );
});
