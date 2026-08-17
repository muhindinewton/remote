//! Colour conversion, hardware video encoding and adaptive rate control.
//!
//! The stage between capture and transport. Four pieces:
//!
//! | Module | Owns |
//! |---|---|
//! | [`convert`] | BGRA to NV12/I420, full-range and box-filtered because the content is text |
//! | [`encoder`] | The encoder interface, with LTR recovery as a first-class operation |
//! | [`rate`] | Turning a bandwidth estimate into bitrate, frame rate, resolution and QP |
//! | [`pipeline`] | Sequencing the above, and deciding when a change is worth an encoder rebuild |
//!
//! The recurring theme is that a 220 ms link changes which operations are cheap. A bitrate change
//! is free and happens every frame; a resolution change costs a keyframe and is rationed; an IDR
//! costs 15-30x a P frame and is the last resort rather than the reflex.

// `deny` rather than `forbid`: the VideoToolbox backend needs `unsafe` for its FFI calls and
// carries the only `#[allow(unsafe_code)]` in the crate. Everything else is checked memory-safe.
#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod backend;
pub mod convert;
pub mod encoder;
pub mod pipeline;
pub mod rate;

pub use convert::{bgra_to_planar, ConvertConfig, PlanarFormat, PlanarFrame};
pub use encoder::{
    Codec, EncodeError, EncodedFrame, EncoderConfig, FrameKind, RecoveryMode, VideoEncoder,
};
pub use pipeline::{Pipeline, PipelineStats, StepOutcome};
pub use rate::{EncoderDirective, KeyframeDecision, RateController};
