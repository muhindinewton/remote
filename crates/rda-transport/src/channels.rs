//! DataChannel topology — `docs/PROTOCOL.md` §5.
//!
//! Every channel is **pre-negotiated**: both peers create it locally with an explicit stream id
//! rather than negotiating in band. DCEP costs one round trip per channel, which is ~220 ms each on
//! this corridor — seven channels negotiated in band would add over a second to session setup for
//! no benefit.
//!
//! The reliability settings here are the mechanical expression of `docs/ARCHITECTURE.md` §4.5, and
//! the reason they matter is SCTP's minimum retransmission timeout: on a reliable stream a single
//! lost packet stalls that stream for a second or more. Pointer motion cannot tolerate that, and
//! key events cannot tolerate loss. Hence the split.

use rda_proto::control::Channel;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;

/// Reliability configuration for one channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelSpec {
    /// Which logical channel this is.
    pub channel: Channel,
    /// Whether SCTP must preserve ordering.
    pub ordered: bool,
    /// Retransmission cap. `None` means fully reliable.
    pub max_retransmits: Option<u16>,
    /// Lifetime cap in milliseconds. Mutually exclusive with `max_retransmits`.
    pub max_packet_life_time: Option<u16>,
}

impl ChannelSpec {
    /// Returns `true` if this channel is fully reliable.
    #[must_use]
    pub fn is_reliable(&self) -> bool {
        self.max_retransmits.is_none() && self.max_packet_life_time.is_none()
    }

    /// Builds the WebRTC init struct for this channel.
    ///
    /// `negotiated: true` with an explicit `id` is what avoids the DCEP round trip.
    #[must_use]
    pub fn to_init(&self) -> RTCDataChannelInit {
        RTCDataChannelInit {
            ordered: Some(self.ordered),
            max_retransmits: self.max_retransmits,
            max_packet_life_time: self.max_packet_life_time,
            protocol: Some(format!("rda/{}/1", self.channel.label())),
            negotiated: Some(self.channel.stream_id()),
        }
    }

    /// The channel label used on the wire.
    #[must_use]
    pub fn label(&self) -> &'static str {
        self.channel.label()
    }
}

/// The complete channel topology.
///
/// SCTP head-of-line blocking is per stream, so this table is the isolation boundary: a stalled
/// reliable channel cannot delay an unreliable one, and a multi-gigabyte file transfer cannot
/// block a keystroke.
pub const CHANNELS: [ChannelSpec; 8] = [
    // Handshake and session control. Correctness beats latency; must never lose a message.
    ChannelSpec {
        channel: Channel::Control,
        ordered: true,
        max_retransmits: None,
        max_packet_life_time: None,
    },
    // Keys, buttons, wheel, text. A lost key-up is a stuck key; reordering inverts a keystroke.
    ChannelSpec {
        channel: Channel::InputKeys,
        ordered: true,
        max_retransmits: None,
        max_packet_life_time: None,
    },
    // Pointer motion. Unreliable *and* unordered: a stale position has negative value, and a
    // reliable stream would freeze the cursor for a second on any loss.
    ChannelSpec {
        channel: Channel::InputPointer,
        ordered: false,
        max_retransmits: Some(0),
        max_packet_life_time: None,
    },
    // Host to controller cursor. Same reasoning as pointer motion, opposite direction; a lifetime
    // cap rather than a retransmit cap because a cursor shape is worth one brief retry.
    ChannelSpec {
        channel: Channel::Cursor,
        ordered: false,
        max_retransmits: None,
        max_packet_life_time: Some(250),
    },
    // Telemetry. Never worth a retransmission — a late measurement describes a moment that has
    // already passed.
    ChannelSpec {
        channel: Channel::Stats,
        ordered: false,
        max_retransmits: Some(0),
        max_packet_life_time: None,
    },
    // Clipboard. Reliable, and isolated so a large paste cannot block control.
    ChannelSpec {
        channel: Channel::Clipboard,
        ordered: true,
        max_retransmits: None,
        max_packet_life_time: None,
    },
    // File transfer. Reliable, and isolated so a multi-gigabyte transfer head-of-line-blocks
    // nothing but itself.
    ChannelSpec {
        channel: Channel::File,
        ordered: true,
        max_retransmits: None,
        max_packet_life_time: None,
    },
    // Compressed video. Unreliable and unordered for the same reason pointer motion is: at 220 ms
    // RTT a retransmitted frame arrives long after its playout deadline, so the bandwidth is spent
    // for nothing. The 500 ms lifetime is generous enough to survive a brief reorder and short
    // enough that nothing hopeless stays queued.
    ChannelSpec {
        channel: Channel::Video,
        ordered: false,
        max_retransmits: None,
        max_packet_life_time: Some(500),
    },
];

/// Looks up the specification for a logical channel.
#[must_use]
pub fn spec_for(channel: Channel) -> &'static ChannelSpec {
    CHANNELS
        .iter()
        .find(|c| c.channel == channel)
        .expect("CHANNELS covers every Channel variant; enforced by a test")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_channel_has_a_spec() {
        for ch in Channel::all() {
            let spec = spec_for(ch);
            assert_eq!(spec.channel, ch);
        }
        assert_eq!(CHANNELS.len(), Channel::all().len());
    }

    #[test]
    fn stream_ids_are_unique() {
        let mut ids: Vec<u16> = CHANNELS.iter().map(|c| c.channel.stream_id()).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(
            ids.len(),
            before,
            "a duplicate stream id would silently merge two channels"
        );
    }

    #[test]
    fn pointer_motion_is_unreliable_and_unordered() {
        // This is the single most consequential setting in the file. If it ever becomes reliable,
        // one lost packet freezes the cursor for a second (SCTP minimum RTO) and the product feels
        // broken on exactly the lossy links it was built for.
        let p = spec_for(Channel::InputPointer);
        assert!(!p.ordered);
        assert_eq!(p.max_retransmits, Some(0));
        assert!(!p.is_reliable());
    }

    #[test]
    fn key_events_are_reliable_and_ordered() {
        let k = spec_for(Channel::InputKeys);
        assert!(k.ordered);
        assert!(k.is_reliable(), "a lost key-up is a stuck modifier");
    }

    #[test]
    fn video_is_unreliable_and_unordered() {
        // Same reasoning as pointer motion: a frame that arrives after its deadline is worse than
        // no frame, because it cost bandwidth and displays a moment already gone.
        let v = spec_for(Channel::Video);
        assert!(!v.ordered);
        assert!(!v.is_reliable());
        assert_eq!(v.max_packet_life_time, Some(500));
    }

    #[test]
    fn control_and_transfer_channels_are_reliable() {
        for ch in [Channel::Control, Channel::Clipboard, Channel::File] {
            assert!(spec_for(ch).is_reliable(), "{ch:?} must be reliable");
        }
    }

    #[test]
    fn telemetry_is_never_retransmitted() {
        assert_eq!(spec_for(Channel::Stats).max_retransmits, Some(0));
    }

    #[test]
    fn retransmit_and_lifetime_caps_are_mutually_exclusive() {
        // SCTP rejects a channel that sets both; a peer that tries fails to open the channel at
        // all, which surfaces as a mysterious session that connects and then does nothing.
        for spec in CHANNELS {
            assert!(
                !(spec.max_retransmits.is_some() && spec.max_packet_life_time.is_some()),
                "{:?} sets both reliability caps",
                spec.channel
            );
        }
    }

    #[test]
    fn all_channels_are_pre_negotiated() {
        // In-band DCEP negotiation costs a round trip per channel — over a second in total on a
        // 220 ms path.
        for spec in CHANNELS {
            let init = spec.to_init();
            assert_eq!(init.negotiated, Some(spec.channel.stream_id()));
        }
    }
}
