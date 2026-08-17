//! A synthetic encoder that produces a plausible bitstream without touching hardware.
//!
//! Lets the pipeline above the encoder — rate control, temporal layering, LTR recovery, packetising
//! — be tested on any machine, in CI, with no GPU and no permissions. Without it those paths would
//! only ever run on a developer's laptop, which is precisely where regressions do not get caught.
//!
//! It models the *shape* of a real encoder's output rather than its content: an IDR is far larger
//! than a delta frame, LTR recovery sits in between, and frame size tracks the bitrate it was told
//! to hit. Those are the properties the rest of the system reasons about.

use crate::convert::PlanarFrame;
use crate::encoder::{
    Codec, EncodeError, EncodedFrame, EncoderConfig, FrameKind, RecoveryMode, VideoEncoder,
};

/// Relative cost of an IDR against a delta frame. Real encoders land in the 15–30× range on
/// desktop content; the low end is used here so tests stay fast.
pub const IDR_COST_FACTOR: usize = 15;

/// Relative cost of an LTR recovery frame. The whole argument for preferring it over an IDR.
pub const LTR_COST_FACTOR: usize = 3;

/// Synthetic encoder.
pub struct RecordingEncoder {
    config: EncoderConfig,
    sequence: u64,
    bitrate_bps: u32,
    pending_recovery: Option<RecoveryMode>,
    /// Frames the caller asked for, in order — the assertion surface for tests.
    pub emitted: Vec<EncodedFrame>,
    /// Whether to claim LTR support.
    pub ltr_supported: bool,
    /// When set, the next `encode` fails with this error.
    pub fail_next: Option<EncodeError>,
    next_ltr_slot: u8,
}

impl RecordingEncoder {
    /// Builds an encoder for the given configuration.
    pub fn new(config: EncoderConfig) -> Result<Self, EncodeError> {
        if !config.is_valid() {
            return Err(EncodeError::BadConfig(format!(
                "{}x{} @ {} fps, {} bps",
                config.width, config.height, config.fps, config.bitrate_bps
            )));
        }
        Ok(Self {
            bitrate_bps: config.bitrate_bps,
            config,
            sequence: 0,
            pending_recovery: None,
            emitted: Vec::new(),
            ltr_supported: true,
            fail_next: None,
            next_ltr_slot: 0,
        })
    }

    /// The temporal layer for a frame index, following the standard dyadic pattern.
    ///
    /// L1T2: every other frame is layer 1. L1T3: layers cycle 0,2,1,2. Layer 0 is never referenced
    /// by higher layers, which is what makes an upper-layer loss skippable.
    fn temporal_layer(&self, index: u64) -> u8 {
        match self.config.temporal_layers {
            1 => 0,
            2 => (index % 2) as u8,
            _ => match index % 4 {
                0 => 0,
                2 => 1,
                _ => 2,
            },
        }
    }

    /// Bytes a frame of this kind should occupy at the current bitrate.
    fn frame_size(&self, kind: FrameKind) -> usize {
        let per_frame = (self.bitrate_bps / 8 / u32::from(self.config.fps.max(1))) as usize;
        match kind {
            FrameKind::Keyframe => per_frame * IDR_COST_FACTOR,
            FrameKind::LtrRecovery => per_frame * LTR_COST_FACTOR,
            FrameKind::Delta => per_frame,
        }
        .max(16)
    }
}

impl VideoEncoder for RecordingEncoder {
    fn encode(
        &mut self,
        frame: &PlanarFrame,
        pts_us: u64,
    ) -> Result<Vec<EncodedFrame>, EncodeError> {
        if let Some(e) = self.fail_next.take() {
            return Err(e);
        }
        if frame.width != self.config.width || frame.height != self.config.height {
            return Err(EncodeError::GeometryMismatch {
                got_w: frame.width,
                got_h: frame.height,
                want_w: self.config.width,
                want_h: self.config.height,
            });
        }

        let index = self.sequence;
        let (kind, ltr_index) = match self.pending_recovery.take() {
            Some(RecoveryMode::Ltr { index }) if self.ltr_supported => {
                (FrameKind::LtrRecovery, Some(index))
            }
            // An encoder that cannot honour an LTR request must escalate to an IDR rather than
            // silently emit a delta frame the receiver still cannot decode.
            Some(_) => (FrameKind::Keyframe, None),
            None if index == 0 => (FrameKind::Keyframe, Some(0)),
            None => {
                // Mark periodic base-layer frames as long-term references so there is something
                // for the receiver to acknowledge and for recovery to target.
                let layer = self.temporal_layer(index);
                if layer == 0 && index % 60 == 0 {
                    self.next_ltr_slot = (self.next_ltr_slot + 1) % 4;
                    (FrameKind::Delta, Some(self.next_ltr_slot))
                } else {
                    (FrameKind::Delta, None)
                }
            }
        };

        let encoded = EncodedFrame {
            data: vec![0xAB; self.frame_size(kind)],
            kind,
            pts_us,
            sequence: index,
            temporal_layer: if kind == FrameKind::Keyframe {
                0
            } else {
                self.temporal_layer(index)
            },
            ltr_index,
            qp: Some(30),
        };
        self.sequence += 1;
        self.emitted.push(encoded.clone());
        Ok(vec![encoded])
    }

    fn set_bitrate(&mut self, bitrate_bps: u32) -> Result<(), EncodeError> {
        self.bitrate_bps = bitrate_bps;
        Ok(())
    }

    fn set_fps(&mut self, fps: u8) -> Result<(), EncodeError> {
        self.config.fps = fps.max(1);
        Ok(())
    }

    fn request_recovery(&mut self, mode: RecoveryMode) -> Result<(), EncodeError> {
        self.pending_recovery = Some(mode);
        Ok(())
    }

    fn flush(&mut self) -> Result<Vec<EncodedFrame>, EncodeError> {
        Ok(Vec::new())
    }

    fn supports_ltr(&self) -> bool {
        self.ltr_supported
    }

    fn is_hardware(&self) -> bool {
        false
    }

    fn name(&self) -> &'static str {
        "recording"
    }

    fn config(&self) -> EncoderConfig {
        self.config
    }
}

/// Builds a codec-appropriate synthetic encoder. Used where a test needs a specific codec.
pub fn recording_encoder(codec: Codec, width: u32, height: u32) -> RecordingEncoder {
    RecordingEncoder::new(EncoderConfig {
        codec,
        width,
        height,
        ..Default::default()
    })
    .expect("default configuration is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::{bgra_to_planar, ConvertConfig, PlanarFormat};

    fn planar(w: u32, h: u32) -> PlanarFrame {
        let src = vec![128u8; (w * h * 4) as usize];
        bgra_to_planar(
            &src,
            w,
            h,
            w as usize * 4,
            PlanarFormat::Nv12,
            ConvertConfig::default(),
        )
        .unwrap()
    }

    fn encoder() -> RecordingEncoder {
        RecordingEncoder::new(EncoderConfig {
            width: 64,
            height: 64,
            fps: 30,
            temporal_layers: 3,
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn the_first_frame_is_a_keyframe() {
        // A receiver joining a stream has no state; the first frame must be decodable alone.
        let mut e = encoder();
        let out = e.encode(&planar(64, 64), 0).unwrap();
        assert_eq!(out[0].kind, FrameKind::Keyframe);
        assert!(out[0].kind.is_random_access_point());
        assert_eq!(out[0].temporal_layer, 0);
    }

    #[test]
    fn subsequent_frames_are_deltas() {
        let mut e = encoder();
        e.encode(&planar(64, 64), 0).unwrap();
        for i in 1..10 {
            let out = e.encode(&planar(64, 64), i * 33_333).unwrap();
            assert_eq!(
                out[0].kind,
                FrameKind::Delta,
                "frame {i} should not be a keyframe"
            );
        }
    }

    #[test]
    fn an_idr_costs_far_more_than_a_delta_frame() {
        // The whole basis of the LTR argument. If this ratio were small, IDR-on-loss would be fine.
        let mut e = encoder();
        let key = e.encode(&planar(64, 64), 0).unwrap()[0].len();
        let delta = e.encode(&planar(64, 64), 33_333).unwrap()[0].len();
        assert!(key >= delta * 10, "IDR {key} vs delta {delta}");
    }

    #[test]
    fn ltr_recovery_costs_far_less_than_an_idr() {
        let mut e = encoder();
        let key = e.encode(&planar(64, 64), 0).unwrap()[0].len();

        e.request_recovery(RecoveryMode::Ltr { index: 0 }).unwrap();
        let recovery = e.encode(&planar(64, 64), 33_333).unwrap()[0].clone();

        assert_eq!(recovery.kind, FrameKind::LtrRecovery);
        assert_eq!(recovery.ltr_index, Some(0));
        assert!(
            recovery.len() < key / 4,
            "recovery {} vs IDR {key}",
            recovery.len()
        );
    }

    #[test]
    fn an_encoder_without_ltr_escalates_to_an_idr() {
        // Silently emitting a delta frame would leave the receiver still unable to decode, and it
        // would take another round trip to discover that.
        let mut e = encoder();
        e.ltr_supported = false;
        e.encode(&planar(64, 64), 0).unwrap();
        e.request_recovery(RecoveryMode::Ltr { index: 0 }).unwrap();
        assert_eq!(
            e.encode(&planar(64, 64), 1).unwrap()[0].kind,
            FrameKind::Keyframe
        );
    }

    #[test]
    fn temporal_layers_follow_the_dyadic_pattern() {
        let mut e = encoder();
        let mut layers = Vec::new();
        for i in 0..8 {
            layers.push(e.encode(&planar(64, 64), i).unwrap()[0].temporal_layer);
        }
        // Frame 0 is the keyframe, forced to layer 0. Then 0,2,1,2 repeating.
        assert_eq!(layers, vec![0, 2, 1, 2, 0, 2, 1, 2]);
    }

    #[test]
    fn only_upper_layer_frames_are_discardable() {
        // This is what `should_nack` consults, so an error here wastes retransmissions on frames
        // nothing references, or refuses them for frames everything does.
        let mut e = encoder();
        for i in 0..8 {
            e.encode(&planar(64, 64), i).unwrap();
        }
        for f in &e.emitted {
            match f.temporal_layer {
                0 => assert!(!f.is_discardable(), "base layer must never be discardable"),
                _ => assert_eq!(f.is_discardable(), f.ltr_index.is_none()),
            }
        }
    }

    #[test]
    fn two_layer_mode_alternates() {
        let mut e = RecordingEncoder::new(EncoderConfig {
            width: 64,
            height: 64,
            temporal_layers: 2,
            ..Default::default()
        })
        .unwrap();
        let mut layers = Vec::new();
        for i in 0..6 {
            layers.push(e.encode(&planar(64, 64), i).unwrap()[0].temporal_layer);
        }
        assert_eq!(layers, vec![0, 1, 0, 1, 0, 1]);
    }

    #[test]
    fn frame_size_tracks_the_bitrate_it_was_given() {
        let mut e = encoder();
        e.encode(&planar(64, 64), 0).unwrap();
        let at_default = e.encode(&planar(64, 64), 1).unwrap()[0].len();

        e.set_bitrate(400_000).unwrap();
        let at_low = e.encode(&planar(64, 64), 2).unwrap()[0].len();
        assert!(at_low < at_default / 5, "{at_low} vs {at_default}");
    }

    #[test]
    fn a_geometry_mismatch_is_refused() {
        // Feeding the encoder a differently-sized frame after a resolution change would produce
        // garbage rather than an error on a real encoder.
        let mut e = encoder();
        assert!(matches!(
            e.encode(&planar(32, 32), 0),
            Err(EncodeError::GeometryMismatch { .. })
        ));
    }

    #[test]
    fn an_invalid_configuration_is_rejected_at_construction() {
        assert!(RecordingEncoder::new(EncoderConfig {
            width: 3,
            ..Default::default()
        })
        .is_err());
        assert!(RecordingEncoder::new(EncoderConfig {
            fps: 0,
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn injected_failures_propagate() {
        let mut e = encoder();
        e.fail_next = Some(EncodeError::Failed("simulated".into()));
        assert!(e.encode(&planar(64, 64), 0).is_err());
        assert!(
            e.encode(&planar(64, 64), 0).is_ok(),
            "the failure must be one-shot"
        );
    }

    #[test]
    fn long_term_references_are_marked_periodically() {
        // There has to be something for the receiver to acknowledge, or recovery has no target.
        let mut e = encoder();
        for i in 0..130 {
            e.encode(&planar(64, 64), i).unwrap();
        }
        let marked = e.emitted.iter().filter(|f| f.ltr_index.is_some()).count();
        assert!(marked >= 3, "only {marked} frames marked as references");
    }
}
