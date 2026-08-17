//! The encoder interface — `docs/ARCHITECTURE.md` §2.4, §3.5.
//!
//! Two things in this trait are unusual and both come from the 220 ms constraint:
//!
//! **`request_recovery` takes a mode, not a boolean.** The reflex on a decode failure is to emit a
//! keyframe. An IDR is 15–30× a P frame, and on a congested transcontinental link that burst causes
//! the loss it was sent to repair — the spiral in §2.2. So the receiver asks for recovery *against
//! a known-good long-term reference* where it can, and only falls back to IDR when it holds none.
//!
//! **`set_bitrate` is expected to be called every frame.** Rate control is not a startup parameter
//! here; it is a control loop running against a link whose capacity changes faster than AIMD can
//! track it at this RTT.

use crate::convert::PlanarFrame;

/// Video codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Codec {
    /// H.264. The guaranteed floor — every platform can encode and decode it.
    #[default]
    H264,
    /// HEVC. Better than H.264, and encodable on Apple Silicon where AV1 is not.
    Hevc,
    /// AV1. Best for desktop content thanks to palette mode and intra block copy, but hardware
    /// encode requires NVIDIA Ada, Intel Arc, or AMD RDNA3 — and no Apple Silicon at all.
    Av1,
}

impl Codec {
    /// The RTP payload type from `docs/PROTOCOL.md` §9.1.
    #[must_use]
    pub fn payload_type(self) -> u8 {
        match self {
            Codec::H264 => 96,
            Codec::Av1 => 98,
            Codec::Hevc => 100,
        }
    }
}

/// What kind of frame the encoder produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// An IDR: decodable on its own, and expensive.
    Keyframe,
    /// A predicted frame referencing earlier frames.
    Delta,
    /// A predicted frame deliberately referencing an acknowledged long-term reference, emitted to
    /// repair a decode failure without the cost of an IDR.
    LtrRecovery,
}

impl FrameKind {
    /// Whether a receiver can start decoding from this frame alone.
    #[must_use]
    pub fn is_random_access_point(self) -> bool {
        matches!(self, FrameKind::Keyframe)
    }
}

/// One compressed frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedFrame {
    /// The bitstream. Annex B for H.264/HEVC, OBU sequence for AV1.
    pub data: Vec<u8>,
    /// What kind of frame this is.
    pub kind: FrameKind,
    /// Presentation timestamp in microseconds since the session epoch.
    pub pts_us: u64,
    /// Monotonic frame counter.
    pub sequence: u64,
    /// The temporal layer this frame belongs to.
    ///
    /// Layer 0 is the base: never referenced by higher layers, so a lost layer-1 or layer-2 frame
    /// is skippable and the stream continues (§2.4).
    pub temporal_layer: u8,
    /// The long-term reference slot this frame was marked into, if any.
    pub ltr_index: Option<u8>,
    /// Quantisation parameter actually used, where the encoder reports it.
    pub qp: Option<u8>,
}

impl EncodedFrame {
    /// Whether losing this frame damages anything else.
    ///
    /// A frame in a higher temporal layer that is not a reference can be dropped with no
    /// consequence beyond one skipped frame — which is precisely why NACK must not be spent on it
    /// (`rda_telemetry::should_nack`).
    #[must_use]
    pub fn is_discardable(&self) -> bool {
        self.temporal_layer > 0 && self.ltr_index.is_none() && self.kind == FrameKind::Delta
    }

    /// Size in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the bitstream is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// How the receiver would like a decode failure repaired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryMode {
    /// Encode the next frame against long-term reference `index`. Roughly 2–4× a P frame.
    ///
    /// Always preferred when the receiver holds an acknowledged reference.
    Ltr {
        /// The reference slot the receiver last decoded successfully.
        index: u8,
    },
    /// Emit a full IDR. 15–30× a P frame, and the last resort.
    Idr,
}

/// Encoder configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Codec.
    pub codec: Codec,
    /// Width in pixels. Must be even.
    pub width: u32,
    /// Height in pixels. Must be even.
    pub height: u32,
    /// Initial target bitrate in bits per second.
    pub bitrate_bps: u32,
    /// Target frame rate.
    pub fps: u8,
    /// Number of temporal layers. 3 for 60 fps, 2 for 30 fps.
    pub temporal_layers: u8,
    /// Whether to use long-term references for recovery.
    pub use_ltr: bool,
    /// Maximum interval between keyframes, in seconds. `0` disables periodic keyframes entirely,
    /// which is the intended steady state — a keyframe should be an event, not a heartbeat (§2.4).
    pub keyframe_interval_s: u32,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self {
            codec: Codec::H264,
            width: 1920,
            height: 1080,
            bitrate_bps: 4_000_000,
            fps: 30,
            temporal_layers: 2,
            use_ltr: true,
            // No periodic keyframes. Recovery is driven by the receiver asking for it, and a
            // periodic IDR on a congested link is a self-inflicted bandwidth spike.
            keyframe_interval_s: 0,
        }
    }
}

impl EncoderConfig {
    /// Rounds dimensions down to even values, which every 4:2:0 encoder requires.
    #[must_use]
    pub fn with_even_dimensions(mut self) -> Self {
        self.width &= !1;
        self.height &= !1;
        self
    }

    /// Whether the configuration is usable.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.width >= 16
            && self.height >= 16
            && self.width % 2 == 0
            && self.height % 2 == 0
            && self.fps > 0
            && self.bitrate_bps >= 50_000
            && (1..=3).contains(&self.temporal_layers)
    }
}

/// Why encoding failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    /// The encoder could not be created.
    #[error("encoder unavailable: {0}")]
    Unavailable(String),
    /// The configuration was rejected.
    #[error("invalid encoder configuration: {0}")]
    BadConfig(String),
    /// The frame's geometry did not match the session's.
    #[error("frame is {got_w}x{got_h}, encoder expects {want_w}x{want_h}")]
    GeometryMismatch {
        /// Frame width.
        got_w: u32,
        /// Frame height.
        got_h: u32,
        /// Configured width.
        want_w: u32,
        /// Configured height.
        want_h: u32,
    },
    /// The platform encoder returned an error.
    #[error("encode failed: {0}")]
    Failed(String),
    /// No hardware encoder for this codec on this machine.
    #[error("no hardware encoder available for {0:?}")]
    NoHardware(Codec),
    /// This platform has no implementation.
    #[error("video encoding is not implemented on this platform")]
    Unsupported,
}

/// A video encoder.
///
/// Implementations are **not** `Send`: hardware encoder sessions are thread-affine on every
/// platform, so the encoder lives on the same dedicated thread that owns the pipeline rather than
/// being moved between tokio workers.
pub trait VideoEncoder {
    /// Encodes one frame, returning whatever the encoder emitted.
    ///
    /// May return zero frames — hardware encoders buffer — or more than one when a queue drains.
    fn encode(
        &mut self,
        frame: &PlanarFrame,
        pts_us: u64,
    ) -> Result<Vec<EncodedFrame>, EncodeError>;

    /// Changes the target bitrate. Called every frame by the rate controller.
    fn set_bitrate(&mut self, bitrate_bps: u32) -> Result<(), EncodeError>;

    /// Changes the target frame rate.
    fn set_fps(&mut self, fps: u8) -> Result<(), EncodeError>;

    /// Requests recovery from a decode failure.
    ///
    /// Implementations that cannot honour [`RecoveryMode::Ltr`] must fall back to an IDR and say so
    /// through [`VideoEncoder::supports_ltr`], so the rate controller can account for the cost.
    fn request_recovery(&mut self, mode: RecoveryMode) -> Result<(), EncodeError>;

    /// Flushes buffered frames, e.g. at session end.
    fn flush(&mut self) -> Result<Vec<EncodedFrame>, EncodeError>;

    /// Whether this encoder can encode against long-term references.
    fn supports_ltr(&self) -> bool;

    /// Whether encoding runs on dedicated hardware rather than the CPU.
    fn is_hardware(&self) -> bool;

    /// Backend name, for diagnostics.
    fn name(&self) -> &'static str;

    /// The active configuration.
    fn config(&self) -> EncoderConfig;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_types_match_the_protocol_spec() {
        assert_eq!(Codec::H264.payload_type(), 96);
        assert_eq!(Codec::Av1.payload_type(), 98);
    }

    #[test]
    fn only_keyframes_are_random_access_points() {
        assert!(FrameKind::Keyframe.is_random_access_point());
        // LTR recovery repairs a decoder that already has state; it cannot start one.
        assert!(!FrameKind::LtrRecovery.is_random_access_point());
        assert!(!FrameKind::Delta.is_random_access_point());
    }

    fn frame(kind: FrameKind, layer: u8, ltr: Option<u8>) -> EncodedFrame {
        EncodedFrame {
            data: vec![0; 100],
            kind,
            pts_us: 0,
            sequence: 0,
            temporal_layer: layer,
            ltr_index: ltr,
            qp: None,
        }
    }

    #[test]
    fn discardability_drives_the_nack_decision() {
        // Only an upper-layer delta frame that nothing references may be abandoned.
        assert!(frame(FrameKind::Delta, 1, None).is_discardable());
        assert!(frame(FrameKind::Delta, 2, None).is_discardable());

        assert!(
            !frame(FrameKind::Delta, 0, None).is_discardable(),
            "base layer is referenced"
        );
        assert!(
            !frame(FrameKind::Delta, 1, Some(0)).is_discardable(),
            "an LTR is referenced"
        );
        assert!(!frame(FrameKind::Keyframe, 0, None).is_discardable());
        assert!(!frame(FrameKind::LtrRecovery, 0, None).is_discardable());
    }

    #[test]
    fn the_default_config_has_no_periodic_keyframes() {
        // A periodic IDR on a congested transcontinental link is a self-inflicted bandwidth spike.
        assert_eq!(EncoderConfig::default().keyframe_interval_s, 0);
        assert!(EncoderConfig::default().use_ltr);
    }

    #[test]
    fn odd_dimensions_are_rounded_down_for_chroma_subsampling() {
        let c = EncoderConfig {
            width: 1921,
            height: 1081,
            ..Default::default()
        }
        .with_even_dimensions();
        assert_eq!((c.width, c.height), (1920, 1080));
        assert!(c.is_valid());
    }

    #[test]
    fn implausible_configurations_are_rejected() {
        let base = EncoderConfig::default();
        assert!(base.is_valid());
        assert!(
            !EncoderConfig {
                width: 1921,
                ..base
            }
            .is_valid(),
            "odd width"
        );
        assert!(!EncoderConfig { width: 8, ..base }.is_valid(), "too small");
        assert!(!EncoderConfig { fps: 0, ..base }.is_valid());
        assert!(!EncoderConfig {
            bitrate_bps: 1000,
            ..base
        }
        .is_valid());
        assert!(!EncoderConfig {
            temporal_layers: 0,
            ..base
        }
        .is_valid());
        assert!(!EncoderConfig {
            temporal_layers: 9,
            ..base
        }
        .is_valid());
    }
}
