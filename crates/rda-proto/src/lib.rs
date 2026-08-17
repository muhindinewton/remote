//! Wire protocol for the RDA remote desktop engine.
//!
//! This crate is the executable form of `docs/PROTOCOL.md`. Where the two disagree, that is a bug in
//! one of them — they are meant to be read side by side.
//!
//! Two deliberate constraints shape everything here:
//!
//! 1. **No `unsafe`.** Every byte in this crate is reachable by an unauthenticated remote peer
//!    (`docs/ARCHITECTURE.md` §5.5 enumerates that surface). Memory safety is not negotiable, so the
//!    crate is `forbid(unsafe_code)` and the parser is fuzzed.
//! 2. **No I/O and no OS dependency.** This crate is pure types plus validation, so both peers, the
//!    signaling server, the test harness and the fuzzer can all share it.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod caps;
pub mod control;
pub mod ids;
pub mod seq;
pub mod signaling;

pub use control::{ControlFrame, DecodeError, Flags, Header, MessageType, Modifiers, Payload};
pub use ids::{device_id_from_pubkey, DeviceId, IdError};
pub use seq::Serial;

/// Protocol major version carried in every control frame header and signaling envelope.
///
/// Major versions are incompatible; minor evolution happens through capabilities ([`caps`]).
pub const PROTO_VERSION: u8 = 1;

/// Maximum size of a single signaling WebSocket message, in bytes.
///
/// The server closes the connection on violation rather than buffering — an unbounded signaling
/// message is a trivial memory-exhaustion vector.
pub const MAX_SIGNALING_MESSAGE: usize = 64 * 1024;

/// Maximum SCTP message size negotiated in the SDP (`a=max-message-size`).
///
/// Caps the reassembly buffer an attacker can force us to allocate.
pub const MAX_SCTP_MESSAGE: usize = 256 * 1024;

/// Maximum reassembled application message across `MORE`-flagged fragments.
pub const MAX_REASSEMBLY: usize = 4 * 1024 * 1024;
