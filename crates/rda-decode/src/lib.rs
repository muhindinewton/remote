//! Video decoding and the client-side jitter buffer.
//!
//! The receiving half of the media path. Two pieces:
//!
//! - [`decoder`] turns a compressed bitstream back into pixels, on hardware where the platform has
//!   it.
//! - [`jitter`] decides *when* a frame is displayed, which on a 220 ms link is where most of the
//!   remaining latency actually lives (`docs/ARCHITECTURE.md` §2.5).
//!
//! The jitter buffer is the only place in the system that deliberately *adds* latency, so it is
//! also the first place to look when a session feels laggy. It grows fast and shrinks slowly, on
//! purpose: shrinking quickly re-creates the stutter it exists to remove.

// `deny` rather than `forbid`: the VideoToolbox backend needs `unsafe` for FFI and carries the only
// `#[allow(unsafe_code)]` in the crate.
#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod backend;
pub mod decoder;
pub mod jitter;
pub mod reassembly;

pub use decoder::{DecodeError, DecodedFrame, VideoDecoder};
pub use jitter::{JitterBuffer, PlayoutDecision};
pub use reassembly::{Reassembler, ReassemblyStats};
