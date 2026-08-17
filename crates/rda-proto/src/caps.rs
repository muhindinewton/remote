//! Capability negotiation — `docs/PROTOCOL.md` §2.3.
//!
//! Capabilities, not version numbers, are how this protocol evolves within a major version. A
//! feature may be used only if it appears in *both* peers' lists, which makes the intersection the
//! only correct way to ask "can we do X".

use std::collections::BTreeSet;

/// Maximum number of capability strings a peer may advertise.
pub const MAX_CAPS: usize = 64;
/// Maximum length of one capability string.
pub const MAX_CAP_LEN: usize = 48;

/// H.264 video. Required of all conforming implementations.
pub const VIDEO_H264: &str = "v1.video.h264";
/// AV1 video. Preferred where both peers have hardware support.
pub const VIDEO_AV1: &str = "v1.video.av1";
/// HEVC video.
pub const VIDEO_HEVC: &str = "v1.video.hevc";
/// LTR-based recovery. Both peers must advertise this before `RequestKeyframe` mode `Ltr` is legal.
pub const VIDEO_LTR: &str = "v1.video.ltr";
/// Three temporal layers (L1T3).
pub const VIDEO_SVC_T3: &str = "v1.video.svc.t3";
/// Opus audio.
pub const AUDIO_OPUS: &str = "v1.audio.opus";
/// HID usage-based key injection. Required of all conforming implementations.
pub const INPUT_HID: &str = "v1.input.hid";
/// Unicode text injection for IME and dead keys.
pub const INPUT_TEXT: &str = "v1.input.text";
/// Relative pointer mode for captured/locked pointers.
pub const INPUT_RELATIVE: &str = "v1.input.relative";
/// Plain text clipboard.
pub const CLIP_TEXT: &str = "v1.clip.text";
/// Image clipboard.
pub const CLIP_IMAGE: &str = "v1.clip.image";
/// File clipboard entries.
pub const CLIP_FILES: &str = "v1.clip.files";
/// File transfer.
pub const FILE_TRANSFER: &str = "v1.file.transfer";
/// Multiple display selection.
pub const MULTIMON: &str = "v1.multimon";

/// Capabilities every conforming implementation must advertise.
pub const REQUIRED: &[&str] = &[VIDEO_H264, INPUT_HID];

/// A peer's advertised capability set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capabilities(BTreeSet<String>);

impl Capabilities {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a capability.
    pub fn insert(&mut self, cap: &str) -> &mut Self {
        if !cap.is_empty() && cap.len() <= MAX_CAP_LEN && self.0.len() < MAX_CAPS {
            self.0.insert(cap.to_owned());
        }
        self
    }

    /// Returns `true` if this peer advertises `cap`.
    #[must_use]
    pub fn has(&self, cap: &str) -> bool {
        self.0.contains(cap)
    }

    /// The capabilities both peers support. This is the only set a session may actually use.
    #[must_use]
    pub fn intersect(&self, other: &Capabilities) -> Capabilities {
        Capabilities(self.0.intersection(&other.0).cloned().collect())
    }

    /// Returns `true` if the mandatory capabilities are all present.
    #[must_use]
    pub fn meets_required(&self) -> bool {
        REQUIRED.iter().all(|c| self.has(c))
    }

    /// Iterates the capability strings in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    /// Number of advertised capabilities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if nothing is advertised.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Picks the best mutually supported video codec.
    ///
    /// AV1 first for its screen-content tools — palette mode and intra block copy are built for
    /// desktop imagery and matter more here than raw compression efficiency
    /// (`docs/ARCHITECTURE.md` §3.5). H.264 is the guaranteed floor.
    #[must_use]
    pub fn best_video_codec(&self, peer: &Capabilities) -> &'static str {
        let both = self.intersect(peer);
        if both.has(VIDEO_AV1) {
            VIDEO_AV1
        } else if both.has(VIDEO_HEVC) {
            VIDEO_HEVC
        } else {
            VIDEO_H264
        }
    }
}

/// Builds a set from advertised strings, discarding malformed or excess entries.
///
/// Silently dropping rather than erroring is deliberate: an unknown capability from a newer peer
/// must never be fatal (§2.2), and the caps on count and length are a memory bound, not a protocol
/// rule — rejecting the whole message because one entry was oversized would break interop with a
/// future version for no security gain.
impl<S: AsRef<str>> FromIterator<S> for Capabilities {
    fn from_iter<I: IntoIterator<Item = S>>(iter: I) -> Self {
        let set = iter
            .into_iter()
            .map(|s| s.as_ref().to_owned())
            .filter(|s| !s.is_empty() && s.len() <= MAX_CAP_LEN)
            .take(MAX_CAPS)
            .collect();
        Self(set)
    }
}

impl serde::Serialize for Capabilities {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for Capabilities {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw: Vec<String> = Vec::deserialize(d)?;
        Ok(Capabilities::from_iter(raw))
    }
}

/// Per-session permissions granted by the host — `docs/ARCHITECTURE.md` §4.7.
///
/// Enforced at the injection and capture boundaries, never in the UI, so a modified client gains
/// nothing by lying about what it is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct SessionCaps {
    /// See the host's screen. Implied by every session.
    pub view: bool,
    /// Inject keyboard and pointer events.
    pub input: bool,
    /// Synchronise the clipboard.
    pub clipboard: bool,
    /// Transfer files.
    pub file: bool,
    /// Receive host audio.
    pub audio: bool,
}

impl SessionCaps {
    /// A view-only session: the safe default when a host has not decided otherwise.
    #[must_use]
    pub fn view_only() -> Self {
        Self {
            view: true,
            ..Self::default()
        }
    }

    /// Parses the wire representation, ignoring names it does not recognise.
    #[must_use]
    pub fn from_names<I: IntoIterator<Item = S>, S: AsRef<str>>(names: I) -> Self {
        let mut c = Self::default();
        for n in names {
            match n.as_ref() {
                "view" => c.view = true,
                "input" => c.input = true,
                "clipboard" => c.clipboard = true,
                "file" => c.file = true,
                "audio" => c.audio = true,
                _ => {}
            }
        }
        c
    }

    /// The wire representation.
    #[must_use]
    pub fn to_names(self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.view {
            v.push("view");
        }
        if self.input {
            v.push("input");
        }
        if self.clipboard {
            v.push("clipboard");
        }
        if self.file {
            v.push("file");
        }
        if self.audio {
            v.push("audio");
        }
        v
    }

    /// Restricts `self` to what `granted` allows.
    ///
    /// A grant can only ever narrow a request. This is the operation the host applies to an
    /// incoming `requested_caps`, and the reason a controller cannot escalate by asking twice.
    #[must_use]
    pub fn clamp_to(self, granted: SessionCaps) -> SessionCaps {
        SessionCaps {
            view: self.view && granted.view,
            input: self.input && granted.input,
            clipboard: self.clipboard && granted.clipboard,
            file: self.file && granted.file,
            audio: self.audio && granted.audio,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intersection_is_what_a_session_may_use() {
        let host = Capabilities::from_iter([VIDEO_H264, VIDEO_AV1, INPUT_HID, MULTIMON]);
        let client = Capabilities::from_iter([VIDEO_H264, INPUT_HID, INPUT_TEXT]);
        let both = host.intersect(&client);
        assert!(both.has(VIDEO_H264));
        assert!(
            !both.has(VIDEO_AV1),
            "one-sided AV1 support must not be usable"
        );
        assert!(!both.has(INPUT_TEXT));
    }

    #[test]
    fn codec_selection_prefers_av1_only_when_mutual() {
        let av1 = Capabilities::from_iter([VIDEO_H264, VIDEO_AV1]);
        let h264 = Capabilities::from_iter([VIDEO_H264]);
        assert_eq!(av1.best_video_codec(&av1), VIDEO_AV1);
        // An Apple Silicon host cannot encode AV1, so a one-sided advertisement must fall back.
        assert_eq!(av1.best_video_codec(&h264), VIDEO_H264);
    }

    #[test]
    fn required_capabilities_are_checked() {
        assert!(Capabilities::from_iter([VIDEO_H264, INPUT_HID]).meets_required());
        assert!(!Capabilities::from_iter([VIDEO_AV1]).meets_required());
    }

    #[test]
    fn oversized_advertisements_are_bounded() {
        let many: Vec<String> = (0..500).map(|i| format!("v1.fake.{i}")).collect();
        assert_eq!(Capabilities::from_iter(many).len(), MAX_CAPS);
        let long = "v".repeat(MAX_CAP_LEN + 1);
        assert!(Capabilities::from_iter([long]).is_empty());
    }

    #[test]
    fn a_grant_can_only_narrow_a_request() {
        let requested = SessionCaps {
            view: true,
            input: true,
            clipboard: true,
            file: true,
            audio: true,
        };
        let granted = SessionCaps {
            view: true,
            input: true,
            ..SessionCaps::default()
        };
        let effective = requested.clamp_to(granted);
        assert!(effective.input);
        assert!(!effective.file, "a request must never widen a grant");
        assert!(!effective.clipboard);
    }

    #[test]
    fn caps_names_round_trip() {
        let c = SessionCaps {
            view: true,
            input: true,
            clipboard: false,
            file: false,
            audio: true,
        };
        assert_eq!(SessionCaps::from_names(c.to_names()), c);
        // Unknown names are ignored rather than rejected.
        assert_eq!(
            SessionCaps::from_names(["view", "teleport"]),
            SessionCaps::view_only()
        );
    }
}
