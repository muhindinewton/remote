//! Binary control frame codec — `docs/PROTOCOL.md` §6 and §7.
//!
//! Wire layout of the 8-byte header, big-endian throughout:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Ver  | Flags |     Type      |           Sequence            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          Timestamp                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Payload (Type-specific)                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Every decode path is bounds-checked and allocation-free except where a payload genuinely carries
//! variable-length data, and those lengths are hard-capped before allocation.

use crate::PROTO_VERSION;

/// Length of the fixed control frame header, in bytes.
pub const HEADER_LEN: usize = 8;

/// Maximum number of simultaneously-pressed keys in a [`Payload::KeyStateSync`].
pub const MAX_PRESSED_KEYS: usize = 32;

/// Maximum UTF-8 byte length of a [`Payload::TextInput`].
pub const MAX_TEXT_INPUT: usize = 1024;

/// Maximum pixel data length of a [`Payload::CursorShape`].
pub const MAX_CURSOR_DATA: usize = 256 * 1024;

/// Maximum cursor edge length in pixels.
pub const MAX_CURSOR_DIM: u16 = 256;

/// Maximum reassembled compressed video frame, in bytes.
///
/// A keyframe above this means the encoder is misconfigured rather than the picture being complex,
/// so the receiver is entitled to give up on it rather than buffer without limit.
///
/// Two mebibytes is set from measurement, not taste: an IDR of a busy 5.6-megapixel desktop —
/// a 2940×1912 Retina display, the largest single screen we expect to serve unscaled — measures
/// just over 1 MB, and a cap has to clear the worst real frame rather than the typical one. It also
/// bounds the receiver: [`MAX_VIDEO_FRAGMENTS`] slots per frame, and the reassembler caps frames
/// in flight, so the two together put a hard ceiling on memory a peer can make us hold.
pub const MAX_VIDEO_FRAME: usize = 2 * 1024 * 1024;

/// Maximum bitstream bytes carried in a single [`Payload::VideoFrame`] fragment.
///
/// SCTP enforces a negotiated maximum message size — 64 KiB in every stack we interoperate with —
/// and a keyframe at any real resolution is several times that, so fragmentation is not optional.
///
/// 16 KiB rather than the full ceiling is deliberate. On an unreliable channel a message is
/// delivered whole or not at all, so the message size *is* the loss granularity: at 64 KiB one lost
/// SCTP chunk costs the whole quarter of a frame, while at 16 KiB it costs a sixteenth. It also
/// keeps each message inside a handful of MTU-sized chunks, which is what the retransmit timers on
/// a 220 ms path are tuned for.
pub const MAX_VIDEO_FRAGMENT: usize = 16 * 1024;

/// Maximum fragments one frame may be split into.
///
/// [`MAX_VIDEO_FRAME`] divided by [`MAX_VIDEO_FRAGMENT`], so the two caps cannot disagree.
pub const MAX_VIDEO_FRAGMENTS: u16 = (MAX_VIDEO_FRAME / MAX_VIDEO_FRAGMENT) as u16;

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// A control frame that could not be decoded.
///
/// Per `docs/PROTOCOL.md` §6.5 every one of these means "discard this frame and increment the
/// malformed counter" — never "tear down the session". Only [`MalformedCounter`] decides that.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// Buffer is shorter than the field being read requires.
    #[error("truncated frame: need {need} bytes, have {got}")]
    Truncated {
        /// Bytes required.
        need: usize,
        /// Bytes available.
        got: usize,
    },

    /// Header carried a protocol major version we do not implement.
    #[error("unsupported protocol version {0}, expected {PROTO_VERSION}")]
    BadVersion(u8),

    /// A field held a value outside its valid range.
    #[error("field `{field}` has invalid value {value}")]
    InvalidField {
        /// Field name as written in the specification.
        field: &'static str,
        /// The offending value.
        value: u32,
    },

    /// A length field exceeded its hard cap. Rejected before any allocation.
    #[error("field `{field}` length {len} exceeds maximum {max}")]
    LengthCap {
        /// Field name.
        field: &'static str,
        /// Declared length.
        len: usize,
        /// Permitted maximum.
        max: usize,
    },

    /// Text payload was not valid UTF-8, or contained a forbidden control character.
    #[error("invalid text payload: {0}")]
    InvalidText(&'static str),
}

// ---------------------------------------------------------------------------------------------
// Bounds-checked reader
// ---------------------------------------------------------------------------------------------

/// A cursor over a byte slice where every read is bounds-checked.
///
/// The entire parser is written against this so that "forgot to check the length" is not
/// expressible. It never panics and never allocates.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < n {
            return Err(DecodeError::Truncated {
                need: n,
                got: self.remaining(),
            });
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn i16(&mut self) -> Result<i16, DecodeError> {
        Ok(self.u16()? as i16)
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Skips a reserved byte. Reserved fields are ignored on receipt, never validated —
    /// validating them would break forward compatibility the moment we assign one a meaning.
    fn skip_reserved(&mut self, n: usize) -> Result<(), DecodeError> {
        self.take(n).map(|_| ())
    }
}

// ---------------------------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------------------------

/// Header flags — `docs/PROTOCOL.md` §6.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags(pub u8);

impl Flags {
    /// No flags set.
    pub const NONE: Flags = Flags(0x0);
    /// This frame is a non-final fragment of a larger message.
    pub const MORE: u8 = 0x1;
    /// Generated by state reconciliation, not by a real user action. Audit-log relevant.
    pub const SYNTHETIC: u8 = 0x2;

    /// Returns `true` if this frame is a non-final fragment.
    #[must_use]
    pub fn is_more(self) -> bool {
        self.0 & Self::MORE != 0
    }

    /// Returns `true` if this frame was synthesised by reconciliation.
    #[must_use]
    pub fn is_synthetic(self) -> bool {
        self.0 & Self::SYNTHETIC != 0
    }

    /// Returns a copy with `SYNTHETIC` set.
    #[must_use]
    pub fn with_synthetic(self) -> Self {
        Flags(self.0 | Self::SYNTHETIC)
    }
}

/// The fixed 8-byte control frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Protocol major version. Always [`PROTO_VERSION`] on send.
    pub version: u8,
    /// Frame flags.
    pub flags: Flags,
    /// Numeric message type. Kept as `u8` so unknown types survive decode (§2.2).
    pub msg_type: u8,
    /// Per-channel, per-direction wrapping sequence number.
    pub sequence: u16,
    /// Milliseconds since the session epoch (the moment `SessionReady` was sent).
    ///
    /// Milliseconds rather than microseconds is deliberate: a `u32` of microseconds wraps every
    /// 71.6 minutes, which real sessions exceed. Advisory only — never used for security decisions.
    pub timestamp_ms: u32,
}

impl Header {
    /// Builds a header for an outgoing frame.
    #[must_use]
    pub fn new(msg_type: MessageType, sequence: u16, timestamp_ms: u32) -> Self {
        Self {
            version: PROTO_VERSION,
            flags: Flags::NONE,
            msg_type: msg_type as u8,
            sequence,
            timestamp_ms,
        }
    }

    /// Parses a header from the first [`HEADER_LEN`] bytes of `buf`.
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::Truncated {
                need: HEADER_LEN,
                got: buf.len(),
            });
        }
        let version = buf[0] >> 4;
        if version != PROTO_VERSION {
            return Err(DecodeError::BadVersion(version));
        }
        Ok(Self {
            version,
            flags: Flags(buf[0] & 0x0F),
            msg_type: buf[1],
            sequence: u16::from_be_bytes([buf[2], buf[3]]),
            timestamp_ms: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        })
    }

    fn encode_into(self, out: &mut Vec<u8>) {
        out.push((self.version << 4) | (self.flags.0 & 0x0F));
        out.push(self.msg_type);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.timestamp_ms.to_be_bytes());
    }

    /// The message type, if it is one this build understands.
    #[must_use]
    pub fn typed(self) -> Option<MessageType> {
        MessageType::from_u8(self.msg_type)
    }
}

// ---------------------------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------------------------

/// Control message type codes — `docs/PROTOCOL.md` §6.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[allow(missing_docs)] // Each variant is documented in PROTOCOL.md §6.3; repeating it adds nothing.
pub enum MessageType {
    Hello = 0x01,
    HelloAck = 0x02,
    AuthRequest = 0x03,
    AuthResponse = 0x04,
    SessionReady = 0x05,
    Ping = 0x06,
    Pong = 0x07,
    Pause = 0x08,
    Resume = 0x09,
    EndSession = 0x0A,
    Error = 0x0B,
    /// The controller's key confirmation and DTLS binding signature — `docs/PROTOCOL.md` §4.
    AuthConfirm = 0x0C,

    MouseMove = 0x10,
    MouseMoveRelative = 0x11,
    MouseButton = 0x12,
    MouseWheel = 0x13,
    KeyEvent = 0x14,
    KeyStateSync = 0x15,
    TextInput = 0x16,

    DisplayList = 0x30,
    DisplaySelect = 0x31,
    QualityHint = 0x32,
    RequestKeyframe = 0x33,
    LtrAck = 0x34,
    CursorUpdate = 0x35,
    CursorShape = 0x36,
    VideoFrame = 0x37,

    ClipboardOffer = 0x40,
    ClipboardRequest = 0x41,
    ClipboardData = 0x42,

    QosReport = 0x50,
}

impl MessageType {
    /// Maps a numeric code to a type, or `None` if this build does not know it.
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        use MessageType::*;
        Some(match v {
            0x01 => Hello,
            0x02 => HelloAck,
            0x03 => AuthRequest,
            0x04 => AuthResponse,
            0x05 => SessionReady,
            0x06 => Ping,
            0x07 => Pong,
            0x08 => Pause,
            0x09 => Resume,
            0x0A => EndSession,
            0x0B => Error,
            0x0C => AuthConfirm,
            0x10 => MouseMove,
            0x11 => MouseMoveRelative,
            0x12 => MouseButton,
            0x13 => MouseWheel,
            0x14 => KeyEvent,
            0x15 => KeyStateSync,
            0x16 => TextInput,
            0x30 => DisplayList,
            0x31 => DisplaySelect,
            0x32 => QualityHint,
            0x33 => RequestKeyframe,
            0x34 => LtrAck,
            0x35 => CursorUpdate,
            0x36 => CursorShape,
            0x37 => VideoFrame,
            0x40 => ClipboardOffer,
            0x41 => ClipboardRequest,
            0x42 => ClipboardData,
            0x50 => QosReport,
            _ => return None,
        })
    }

    /// The DataChannel this message type rides on — `docs/PROTOCOL.md` §5.
    ///
    /// Encoding this in the type system rather than at each call site is what stops a future change
    /// from quietly putting pointer motion on a reliable channel, which would stall the cursor for
    /// a second on every loss (SCTP minimum RTO, `docs/ARCHITECTURE.md` §2.8).
    #[must_use]
    pub fn channel(self) -> Channel {
        use MessageType::*;
        match self {
            MouseMove | MouseMoveRelative => Channel::InputPointer,
            MouseButton | MouseWheel | KeyEvent | KeyStateSync | TextInput => Channel::InputKeys,
            CursorUpdate | CursorShape => Channel::Cursor,
            VideoFrame => Channel::Video,
            ClipboardOffer | ClipboardRequest | ClipboardData => Channel::Clipboard,
            QosReport => Channel::Stats,
            _ => Channel::Control,
        }
    }
}

/// The pre-negotiated DataChannels — `docs/PROTOCOL.md` §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    /// `ctl`, id 0 — reliable ordered. Handshake and session control.
    Control,
    /// `input-k`, id 1 — reliable ordered. Keys, buttons, wheel, text.
    InputKeys,
    /// `input-p`, id 2 — unreliable unordered. Pointer motion only.
    InputPointer,
    /// `cursor`, id 3 — unreliable, 250 ms lifetime. Host to controller.
    Cursor,
    /// `stats`, id 4 — unreliable unordered. Telemetry.
    Stats,
    /// `clip`, id 5 — reliable ordered.
    Clipboard,
    /// `file`, id 6 — reliable ordered.
    File,
    /// `video`, id 7 — unreliable, 500 ms lifetime.
    ///
    /// Compressed video. `docs/PROTOCOL.md` §9 specifies SRTP for the media plane, and that remains
    /// the target; this channel exists so the pipeline can run end to end over SCTP before the RTP
    /// packetiser is built. The reliability settings are chosen for the same reason pointer motion
    /// is unreliable — a retransmission that arrives after its frame was due is bandwidth spent for
    /// nothing at 220 ms RTT.
    Video,
}

impl Channel {
    /// The channel label used in the DataChannel negotiation.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Channel::Control => "ctl",
            Channel::InputKeys => "input-k",
            Channel::InputPointer => "input-p",
            Channel::Cursor => "cursor",
            Channel::Stats => "stats",
            Channel::Clipboard => "clip",
            Channel::File => "file",
            Channel::Video => "video",
        }
    }

    /// The pre-negotiated SCTP stream identifier.
    #[must_use]
    pub fn stream_id(self) -> u16 {
        match self {
            Channel::Control => 0,
            Channel::InputKeys => 1,
            Channel::InputPointer => 2,
            Channel::Cursor => 3,
            Channel::Stats => 4,
            Channel::Clipboard => 5,
            Channel::File => 6,
            Channel::Video => 7,
        }
    }

    /// Every channel, in stream-id order.
    #[must_use]
    pub fn all() -> [Channel; 8] {
        [
            Channel::Control,
            Channel::InputKeys,
            Channel::InputPointer,
            Channel::Cursor,
            Channel::Stats,
            Channel::Clipboard,
            Channel::File,
            Channel::Video,
        ]
    }
}

// ---------------------------------------------------------------------------------------------
// Modifiers
// ---------------------------------------------------------------------------------------------

/// Keyboard modifier state — `docs/PROTOCOL.md` §7.9.
///
/// Bits 0–7 are byte-identical to the USB HID boot-protocol keyboard modifier byte, which makes
/// translation to and from HID reports a no-op rather than a table lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Modifiers(pub u16);

impl Modifiers {
    /// No modifiers held.
    pub const NONE: Modifiers = Modifiers(0);
    /// Left Control.
    pub const LEFT_CTRL: u16 = 0x0001;
    /// Left Shift.
    pub const LEFT_SHIFT: u16 = 0x0002;
    /// Left Alt.
    pub const LEFT_ALT: u16 = 0x0004;
    /// Left GUI (Windows / Command).
    pub const LEFT_GUI: u16 = 0x0008;
    /// Right Control.
    pub const RIGHT_CTRL: u16 = 0x0010;
    /// Right Shift.
    pub const RIGHT_SHIFT: u16 = 0x0020;
    /// Right Alt / AltGr.
    pub const RIGHT_ALT: u16 = 0x0040;
    /// Right GUI.
    pub const RIGHT_GUI: u16 = 0x0080;
    /// Caps Lock (lock state, not the physical key).
    pub const CAPS_LOCK: u16 = 0x0100;
    /// Num Lock.
    pub const NUM_LOCK: u16 = 0x0200;
    /// Scroll Lock.
    pub const SCROLL_LOCK: u16 = 0x0400;

    /// Bits currently assigned a meaning. Bits 11–15 are reserved.
    pub const KNOWN_MASK: u16 = 0x07FF;

    /// Returns `true` if any of `mask`'s bits are set.
    #[must_use]
    pub fn contains(self, mask: u16) -> bool {
        self.0 & mask != 0
    }

    /// The low 8 bits, which are exactly the HID boot-protocol modifier byte.
    #[must_use]
    pub fn hid_byte(self) -> u8 {
        (self.0 & 0x00FF) as u8
    }
}

// ---------------------------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------------------------

/// Which mouse button a [`Payload::MouseButton`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum MouseButtonId {
    Left = 1,
    Right = 2,
    Middle = 3,
    X1 = 4,
    X2 = 5,
}

impl MouseButtonId {
    fn from_u8(v: u8) -> Result<Self, DecodeError> {
        Ok(match v {
            1 => Self::Left,
            2 => Self::Right,
            3 => Self::Middle,
            4 => Self::X1,
            5 => Self::X2,
            other => {
                return Err(DecodeError::InvalidField {
                    field: "button",
                    value: u32::from(other),
                })
            }
        })
    }
}

/// Press / release / repeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum KeyAction {
    Up = 0,
    Down = 1,
    Repeat = 2,
}

impl KeyAction {
    fn from_u8(v: u8, field: &'static str, allow_repeat: bool) -> Result<Self, DecodeError> {
        Ok(match v {
            0 => Self::Up,
            1 => Self::Down,
            2 if allow_repeat => Self::Repeat,
            other => {
                return Err(DecodeError::InvalidField {
                    field,
                    value: u32::from(other),
                })
            }
        })
    }
}

/// How the sender wants the encoder to repair a decode failure — `docs/PROTOCOL.md` §7.10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyframeMode {
    /// Full IDR. The last resort — 15–30× the cost of a P frame, and the trigger for the
    /// congestion spiral described in `docs/ARCHITECTURE.md` §2.2.
    Idr = 0,
    /// Encode the next frame against an acknowledged long-term reference. 2–4× a P frame.
    /// Strongly preferred whenever the receiver holds a valid LTR.
    Ltr = 1,
}

/// HID usage page for standard keyboard keys.
pub const USAGE_PAGE_KEYBOARD: u16 = 0x0007;
/// HID usage page for consumer controls (volume, media transport).
pub const USAGE_PAGE_CONSUMER: u16 = 0x000C;

/// Decoded control frame body.
///
/// [`Payload::Unknown`] exists so that a frame with a type this build does not implement round-trips
/// as data rather than becoming an error — that is what makes §2.2 forward compatibility real
/// instead of aspirational.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)] // Field semantics live in PROTOCOL.md §7, next to the byte offsets.
pub enum Payload {
    Ping {
        token: u32,
    },
    Pong {
        token: u32,
        host_delay_us: u16,
    },
    EndSession {
        code: u16,
    },
    Error {
        code: u16,
        message: String,
    },

    MouseMove {
        display_id: u8,
        flags: u8,
        x_norm: u16,
        y_norm: u16,
        modifiers: Modifiers,
    },
    MouseMoveRelative {
        /// Q13.3 fixed point: units of 1/8 device pixel.
        dx: i16,
        /// Q13.3 fixed point: units of 1/8 device pixel.
        dy: i16,
        modifiers: Modifiers,
        display_id: u8,
    },
    MouseButton {
        button: MouseButtonId,
        action: KeyAction,
        /// Carried on the button event itself, because pointer motion travels on an unreliable
        /// channel and a dropped move would otherwise place the click at the wrong location.
        x_norm: u16,
        y_norm: u16,
        modifiers: Modifiers,
        display_id: u8,
        click_count: u8,
    },
    MouseWheel {
        /// Units of 1/120 notch; 120 is one traditional detent.
        delta_v: i16,
        delta_h: i16,
        modifiers: Modifiers,
        display_id: u8,
        flags: u8,
    },
    KeyEvent {
        usage_page: u16,
        usage_id: u16,
        action: KeyAction,
        flags: u8,
        modifiers: Modifiers,
    },
    KeyStateSync {
        modifiers: Modifiers,
        authoritative: bool,
        /// HID usage IDs on page 0x0007 currently held down.
        pressed: Vec<u16>,
    },
    TextInput {
        commit: bool,
        preedit: bool,
        text: String,
    },

    RequestKeyframe {
        mode: KeyframeMode,
        ltr_index: u8,
        reason: u16,
    },
    LtrAck {
        ltr_index: u8,
        frame_id: u16,
    },
    CursorUpdate {
        shape_id: u32,
        x_norm: u16,
        y_norm: u16,
        display_id: u8,
        visible: bool,
    },
    CursorShape {
        shape_id: u32,
        width: u16,
        height: u16,
        hotspot_x: u16,
        hotspot_y: u16,
        format: u8,
        data: Vec<u8>,
    },

    /// One fragment of one compressed frame.
    ///
    /// Frames are fragmented because SCTP will not carry a message larger than the negotiated
    /// ceiling, and a keyframe is always larger. Every fragment repeats the frame's metadata so a
    /// receiver can classify a frame — and decide whether it is even worth reassembling — from
    /// whichever fragment reaches it first, rather than being blind until fragment zero arrives.
    VideoFrame {
        /// Identifies the frame these fragments belong to. Wraps; only equality is meaningful.
        frame_id: u32,
        /// This fragment's position, from zero.
        fragment_index: u16,
        /// How many fragments the whole frame was split into. Always at least one.
        fragment_count: u16,
        /// 0 = delta, 1 = keyframe, 2 = LTR recovery.
        kind: u8,
        /// Temporal layer, so the receiver knows what is discardable.
        temporal_layer: u8,
        /// Presentation timestamp in microseconds since the session epoch.
        pts_us: u64,
        /// This fragment of the compressed bitstream, Annex B for H.264.
        data: Vec<u8>,
    },

    QosReport(QosReport),

    /// A type this build does not implement. Ignored by the session, preserved for diagnostics.
    Unknown {
        msg_type: u8,
        body: Vec<u8>,
    },
}

/// Application-level quality telemetry — `docs/PROTOCOL.md` §7.11.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(missing_docs)]
pub struct QosReport {
    pub rtt_ms: u16,
    pub jitter_ms: u16,
    pub loss_permille: u16,
    pub frames_decoded: u16,
    pub frames_dropped: u16,
    /// Q8.8 fixed point.
    pub render_fps_q8: u16,
    pub playout_delay_ms: u16,
    pub decode_time_us: u16,
}

// ---------------------------------------------------------------------------------------------
// Frame
// ---------------------------------------------------------------------------------------------

/// A complete control frame: header plus decoded payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFrame {
    /// Frame header.
    pub header: Header,
    /// Decoded body.
    pub payload: Payload,
}

impl Payload {
    /// Splits a compressed frame into wire-sized [`Payload::VideoFrame`] fragments.
    ///
    /// Lives here rather than in the host so that every sender fragments identically — the receiver
    /// has one reassembler, and two senders that disagree about fragment boundaries would corrupt
    /// bitstreams in a way that looks like a decoder bug.
    ///
    /// An empty frame still yields one fragment. A zero-fragment frame would be indistinguishable
    /// from "nothing sent", and the receiver's count check rejects it anyway.
    #[must_use]
    pub fn fragment_video(
        frame_id: u32,
        kind: u8,
        temporal_layer: u8,
        pts_us: u64,
        data: &[u8],
    ) -> Vec<Payload> {
        let chunks: Vec<&[u8]> = if data.is_empty() {
            vec![&[]]
        } else {
            data.chunks(MAX_VIDEO_FRAGMENT).collect()
        };
        let fragment_count = chunks.len() as u16;
        chunks
            .into_iter()
            .enumerate()
            .map(|(i, chunk)| Payload::VideoFrame {
                frame_id,
                fragment_index: i as u16,
                fragment_count,
                kind,
                temporal_layer,
                pts_us,
                data: chunk.to_vec(),
            })
            .collect()
    }
}

impl ControlFrame {
    /// Builds a frame, deriving the message type from the payload.
    #[must_use]
    pub fn new(payload: Payload, sequence: u16, timestamp_ms: u32) -> Self {
        let msg_type = match &payload {
            Payload::Unknown { msg_type, .. } => *msg_type,
            other => payload_type(other) as u8,
        };
        Self {
            header: Header {
                version: PROTO_VERSION,
                flags: Flags::NONE,
                msg_type,
                sequence,
                timestamp_ms,
            },
            payload,
        }
    }

    /// Marks this frame as generated by state reconciliation rather than by the user.
    #[must_use]
    pub fn synthetic(mut self) -> Self {
        self.header.flags = self.header.flags.with_synthetic();
        self
    }

    /// Serialises the frame to bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 24);
        self.header.encode_into(&mut out);
        encode_payload(&self.payload, &mut out);
        out
    }

    /// Parses a complete frame from one SCTP message.
    ///
    /// SCTP preserves message boundaries, so there is no length prefix on the wire — `buf` is
    /// exactly one frame.
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let header = Header::decode(buf)?;
        let body = &buf[HEADER_LEN..];
        let payload = decode_payload(header.msg_type, body)?;
        Ok(Self { header, payload })
    }
}

fn payload_type(p: &Payload) -> MessageType {
    use MessageType as T;
    match p {
        Payload::Ping { .. } => T::Ping,
        Payload::Pong { .. } => T::Pong,
        Payload::EndSession { .. } => T::EndSession,
        Payload::Error { .. } => T::Error,
        Payload::MouseMove { .. } => T::MouseMove,
        Payload::MouseMoveRelative { .. } => T::MouseMoveRelative,
        Payload::MouseButton { .. } => T::MouseButton,
        Payload::MouseWheel { .. } => T::MouseWheel,
        Payload::KeyEvent { .. } => T::KeyEvent,
        Payload::KeyStateSync { .. } => T::KeyStateSync,
        Payload::TextInput { .. } => T::TextInput,
        Payload::RequestKeyframe { .. } => T::RequestKeyframe,
        Payload::LtrAck { .. } => T::LtrAck,
        Payload::CursorUpdate { .. } => T::CursorUpdate,
        Payload::CursorShape { .. } => T::CursorShape,
        Payload::VideoFrame { .. } => T::VideoFrame,
        Payload::QosReport(_) => T::QosReport,
        // Callers must construct Unknown frames through ControlFrame::new, which reads the code
        // from the variant itself; this arm is unreachable in practice.
        Payload::Unknown { .. } => T::Error,
    }
}

fn encode_payload(p: &Payload, out: &mut Vec<u8>) {
    match p {
        Payload::Ping { token } => out.extend_from_slice(&token.to_be_bytes()),
        Payload::Pong {
            token,
            host_delay_us,
        } => {
            out.extend_from_slice(&token.to_be_bytes());
            out.extend_from_slice(&host_delay_us.to_be_bytes());
            out.extend_from_slice(&[0, 0]); // reserved
        }
        Payload::EndSession { code } => out.extend_from_slice(&code.to_be_bytes()),
        Payload::Error { code, message } => {
            let bytes = truncate_utf8(message, 256).as_bytes();
            out.extend_from_slice(&code.to_be_bytes());
            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        Payload::MouseMove {
            display_id,
            flags,
            x_norm,
            y_norm,
            modifiers,
        } => {
            out.push(*display_id);
            out.push(*flags);
            out.extend_from_slice(&x_norm.to_be_bytes());
            out.extend_from_slice(&y_norm.to_be_bytes());
            out.extend_from_slice(&modifiers.0.to_be_bytes());
        }
        Payload::MouseMoveRelative {
            dx,
            dy,
            modifiers,
            display_id,
        } => {
            out.extend_from_slice(&dx.to_be_bytes());
            out.extend_from_slice(&dy.to_be_bytes());
            out.extend_from_slice(&modifiers.0.to_be_bytes());
            out.push(*display_id);
            out.push(0); // reserved
        }
        Payload::MouseButton {
            button,
            action,
            x_norm,
            y_norm,
            modifiers,
            display_id,
            click_count,
        } => {
            out.push(*button as u8);
            out.push(*action as u8);
            out.extend_from_slice(&x_norm.to_be_bytes());
            out.extend_from_slice(&y_norm.to_be_bytes());
            out.extend_from_slice(&modifiers.0.to_be_bytes());
            out.push(*display_id);
            out.push(*click_count);
        }
        Payload::MouseWheel {
            delta_v,
            delta_h,
            modifiers,
            display_id,
            flags,
        } => {
            out.extend_from_slice(&delta_v.to_be_bytes());
            out.extend_from_slice(&delta_h.to_be_bytes());
            out.extend_from_slice(&modifiers.0.to_be_bytes());
            out.push(*display_id);
            out.push(*flags);
        }
        Payload::KeyEvent {
            usage_page,
            usage_id,
            action,
            flags,
            modifiers,
        } => {
            out.extend_from_slice(&usage_page.to_be_bytes());
            out.extend_from_slice(&usage_id.to_be_bytes());
            out.push(*action as u8);
            out.push(*flags);
            out.extend_from_slice(&modifiers.0.to_be_bytes());
        }
        Payload::KeyStateSync {
            modifiers,
            authoritative,
            pressed,
        } => {
            let n = pressed.len().min(MAX_PRESSED_KEYS);
            out.extend_from_slice(&modifiers.0.to_be_bytes());
            out.push(n as u8);
            out.push(u8::from(*authoritative));
            for usage in &pressed[..n] {
                out.extend_from_slice(&usage.to_be_bytes());
            }
        }
        Payload::TextInput {
            commit,
            preedit,
            text,
        } => {
            let bytes = truncate_utf8(text, MAX_TEXT_INPUT).as_bytes();
            let flags = u8::from(*commit) | (u8::from(*preedit) << 1);
            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            out.push(flags);
            out.push(0); // reserved
            out.extend_from_slice(bytes);
        }
        Payload::RequestKeyframe {
            mode,
            ltr_index,
            reason,
        } => {
            out.push(*mode as u8);
            out.push(*ltr_index);
            out.extend_from_slice(&reason.to_be_bytes());
        }
        Payload::LtrAck {
            ltr_index,
            frame_id,
        } => {
            out.push(*ltr_index);
            out.push(0); // reserved
            out.extend_from_slice(&frame_id.to_be_bytes());
        }
        Payload::CursorUpdate {
            shape_id,
            x_norm,
            y_norm,
            display_id,
            visible,
        } => {
            out.extend_from_slice(&shape_id.to_be_bytes());
            out.extend_from_slice(&x_norm.to_be_bytes());
            out.extend_from_slice(&y_norm.to_be_bytes());
            out.push(*display_id);
            out.push(u8::from(*visible));
        }
        Payload::CursorShape {
            shape_id,
            width,
            height,
            hotspot_x,
            hotspot_y,
            format,
            data,
        } => {
            out.extend_from_slice(&shape_id.to_be_bytes());
            out.extend_from_slice(&width.to_be_bytes());
            out.extend_from_slice(&height.to_be_bytes());
            out.extend_from_slice(&hotspot_x.to_be_bytes());
            out.extend_from_slice(&hotspot_y.to_be_bytes());
            out.push(*format);
            out.push(0); // reserved
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(data);
        }
        Payload::VideoFrame {
            frame_id,
            fragment_index,
            fragment_count,
            kind,
            temporal_layer,
            pts_us,
            data,
        } => {
            out.extend_from_slice(&frame_id.to_be_bytes());
            out.extend_from_slice(&fragment_index.to_be_bytes());
            out.extend_from_slice(&fragment_count.to_be_bytes());
            out.push(*kind);
            out.push(*temporal_layer);
            out.extend_from_slice(&pts_us.to_be_bytes());
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(data);
        }
        Payload::QosReport(q) => {
            for v in [
                q.rtt_ms,
                q.jitter_ms,
                q.loss_permille,
                q.frames_decoded,
                q.frames_dropped,
                q.render_fps_q8,
                q.playout_delay_ms,
                q.decode_time_us,
            ] {
                out.extend_from_slice(&v.to_be_bytes());
            }
        }
        Payload::Unknown { body, .. } => out.extend_from_slice(body),
    }
}

fn decode_payload(msg_type: u8, body: &[u8]) -> Result<Payload, DecodeError> {
    let Some(ty) = MessageType::from_u8(msg_type) else {
        return Ok(Payload::Unknown {
            msg_type,
            body: body.to_vec(),
        });
    };
    let mut r = Reader::new(body);

    Ok(match ty {
        MessageType::Ping => Payload::Ping { token: r.u32()? },
        MessageType::Pong => {
            let token = r.u32()?;
            let host_delay_us = r.u16()?;
            Payload::Pong {
                token,
                host_delay_us,
            }
        }
        MessageType::EndSession => Payload::EndSession { code: r.u16()? },
        MessageType::Error => {
            let code = r.u16()?;
            let len = usize::from(r.u16()?);
            if len > 256 {
                return Err(DecodeError::LengthCap {
                    field: "message",
                    len,
                    max: 256,
                });
            }
            let raw = r.take(len)?;
            let message = std::str::from_utf8(raw)
                .map_err(|_| DecodeError::InvalidText("error message is not valid UTF-8"))?;
            Payload::Error {
                code,
                message: message.to_owned(),
            }
        }

        MessageType::MouseMove => Payload::MouseMove {
            display_id: r.u8()?,
            flags: r.u8()?,
            x_norm: r.u16()?,
            y_norm: r.u16()?,
            modifiers: Modifiers(r.u16()?),
        },
        MessageType::MouseMoveRelative => {
            let dx = r.i16()?;
            let dy = r.i16()?;
            let modifiers = Modifiers(r.u16()?);
            let display_id = r.u8()?;
            r.skip_reserved(1)?;
            Payload::MouseMoveRelative {
                dx,
                dy,
                modifiers,
                display_id,
            }
        }
        MessageType::MouseButton => {
            let button = MouseButtonId::from_u8(r.u8()?)?;
            let action = KeyAction::from_u8(r.u8()?, "action", false)?;
            let x_norm = r.u16()?;
            let y_norm = r.u16()?;
            let modifiers = Modifiers(r.u16()?);
            let display_id = r.u8()?;
            let click_count = r.u8()?;
            if !(1..=3).contains(&click_count) {
                return Err(DecodeError::InvalidField {
                    field: "click_count",
                    value: u32::from(click_count),
                });
            }
            Payload::MouseButton {
                button,
                action,
                x_norm,
                y_norm,
                modifiers,
                display_id,
                click_count,
            }
        }
        MessageType::MouseWheel => Payload::MouseWheel {
            delta_v: r.i16()?,
            delta_h: r.i16()?,
            modifiers: Modifiers(r.u16()?),
            display_id: r.u8()?,
            flags: r.u8()?,
        },
        MessageType::KeyEvent => {
            let usage_page = r.u16()?;
            let usage_id = r.u16()?;
            let action = KeyAction::from_u8(r.u8()?, "action", true)?;
            let flags = r.u8()?;
            let modifiers = Modifiers(r.u16()?);
            validate_usage(usage_page, usage_id)?;
            Payload::KeyEvent {
                usage_page,
                usage_id,
                action,
                flags,
                modifiers,
            }
        }
        MessageType::KeyStateSync => {
            let modifiers = Modifiers(r.u16()?);
            let count = usize::from(r.u8()?);
            let flags = r.u8()?;
            if count > MAX_PRESSED_KEYS {
                return Err(DecodeError::LengthCap {
                    field: "count",
                    len: count,
                    max: MAX_PRESSED_KEYS,
                });
            }
            // The length is validated against a fixed cap *before* the allocation, so a hostile
            // `count` cannot make us reserve memory we then fail to fill.
            let mut pressed = Vec::with_capacity(count);
            for _ in 0..count {
                let usage = r.u16()?;
                validate_usage(USAGE_PAGE_KEYBOARD, usage)?;
                pressed.push(usage);
            }
            Payload::KeyStateSync {
                modifiers,
                authoritative: flags & 0x01 != 0,
                pressed,
            }
        }
        MessageType::TextInput => {
            let len = usize::from(r.u16()?);
            let flags = r.u8()?;
            r.skip_reserved(1)?;
            if len == 0 || len > MAX_TEXT_INPUT {
                return Err(DecodeError::LengthCap {
                    field: "byte_len",
                    len,
                    max: MAX_TEXT_INPUT,
                });
            }
            let raw = r.take(len)?;
            let text = std::str::from_utf8(raw)
                .map_err(|_| DecodeError::InvalidText("text is not valid UTF-8"))?;
            // Tab and newline are legitimate keystrokes; the rest of C0 is not something a user
            // types and is a common injection vector into terminals on the host side.
            if text
                .chars()
                .any(|c| c.is_control() && c != '\t' && c != '\n')
            {
                return Err(DecodeError::InvalidText(
                    "text contains forbidden control characters",
                ));
            }
            Payload::TextInput {
                commit: flags & 0x01 != 0,
                preedit: flags & 0x02 != 0,
                text: text.to_owned(),
            }
        }

        MessageType::RequestKeyframe => {
            let mode_raw = r.u8()?;
            let mode = match mode_raw {
                0 => KeyframeMode::Idr,
                1 => KeyframeMode::Ltr,
                other => {
                    return Err(DecodeError::InvalidField {
                        field: "mode",
                        value: u32::from(other),
                    })
                }
            };
            Payload::RequestKeyframe {
                mode,
                ltr_index: r.u8()?,
                reason: r.u16()?,
            }
        }
        MessageType::LtrAck => {
            let ltr_index = r.u8()?;
            r.skip_reserved(1)?;
            Payload::LtrAck {
                ltr_index,
                frame_id: r.u16()?,
            }
        }
        MessageType::CursorUpdate => {
            let shape_id = r.u32()?;
            let x_norm = r.u16()?;
            let y_norm = r.u16()?;
            let display_id = r.u8()?;
            let flags = r.u8()?;
            Payload::CursorUpdate {
                shape_id,
                x_norm,
                y_norm,
                display_id,
                visible: flags & 0x01 != 0,
            }
        }
        MessageType::CursorShape => {
            let shape_id = r.u32()?;
            let width = r.u16()?;
            let height = r.u16()?;
            let hotspot_x = r.u16()?;
            let hotspot_y = r.u16()?;
            let format = r.u8()?;
            r.skip_reserved(1)?;
            let data_len = r.u32()? as usize;

            if width == 0 || width > MAX_CURSOR_DIM {
                return Err(DecodeError::InvalidField {
                    field: "width",
                    value: u32::from(width),
                });
            }
            if height == 0 || height > MAX_CURSOR_DIM {
                return Err(DecodeError::InvalidField {
                    field: "height",
                    value: u32::from(height),
                });
            }
            if hotspot_x >= width {
                return Err(DecodeError::InvalidField {
                    field: "hotspot_x",
                    value: u32::from(hotspot_x),
                });
            }
            if hotspot_y >= height {
                return Err(DecodeError::InvalidField {
                    field: "hotspot_y",
                    value: u32::from(hotspot_y),
                });
            }
            if data_len > MAX_CURSOR_DATA {
                return Err(DecodeError::LengthCap {
                    field: "data_len",
                    len: data_len,
                    max: MAX_CURSOR_DATA,
                });
            }
            // For raw BGRA the length is fully determined by the dimensions. Checking it closes a
            // mismatch that would otherwise reach the renderer as an out-of-bounds read.
            if format == 0 {
                let expected = usize::from(width) * usize::from(height) * 4;
                if data_len != expected {
                    return Err(DecodeError::LengthCap {
                        field: "data_len",
                        len: data_len,
                        max: expected,
                    });
                }
            }
            let data = r.take(data_len)?.to_vec();
            Payload::CursorShape {
                shape_id,
                width,
                height,
                hotspot_x,
                hotspot_y,
                format,
                data,
            }
        }

        MessageType::VideoFrame => {
            let frame_id = r.u32()?;
            let fragment_index = r.u16()?;
            let fragment_count = r.u16()?;
            let kind = r.u8()?;
            let temporal_layer = r.u8()?;
            let pts_us = u64::from(r.u32()?) << 32 | u64::from(r.u32()?);
            let len = r.u32()? as usize;
            if kind > 2 {
                return Err(DecodeError::InvalidField {
                    field: "kind",
                    value: u32::from(kind),
                });
            }
            // A frame is at least one fragment, and an index must fall inside the count. Checking
            // both here means the reassembler can index without re-validating, and cannot be made
            // to allocate a slot table for a frame that will never complete.
            if fragment_count == 0 || fragment_count > MAX_VIDEO_FRAGMENTS {
                return Err(DecodeError::InvalidField {
                    field: "fragment_count",
                    value: u32::from(fragment_count),
                });
            }
            if fragment_index >= fragment_count {
                return Err(DecodeError::InvalidField {
                    field: "fragment_index",
                    value: u32::from(fragment_index),
                });
            }
            // Capped before the allocation: a hostile length must not make us reserve memory we
            // then fail to fill.
            if len > MAX_VIDEO_FRAGMENT {
                return Err(DecodeError::LengthCap {
                    field: "data_len",
                    len,
                    max: MAX_VIDEO_FRAGMENT,
                });
            }
            let data = r.take(len)?.to_vec();
            Payload::VideoFrame {
                frame_id,
                fragment_index,
                fragment_count,
                kind,
                temporal_layer,
                pts_us,
                data,
            }
        }
        MessageType::QosReport => Payload::QosReport(QosReport {
            rtt_ms: r.u16()?,
            jitter_ms: r.u16()?,
            loss_permille: r.u16()?,
            frames_decoded: r.u16()?,
            frames_dropped: r.u16()?,
            render_fps_q8: r.u16()?,
            playout_delay_ms: r.u16()?,
            decode_time_us: r.u16()?,
        }),

        // Handshake and clipboard bodies are CBOR and are parsed a layer up; at this level they
        // are opaque. Preserving them as Unknown keeps the framing layer honest about what it owns.
        _ => Payload::Unknown {
            msg_type,
            body: body.to_vec(),
        },
    })
}

/// Truncates a string to at most `max_bytes`, never splitting a UTF-8 codepoint.
///
/// Slicing a `&str` by byte index would panic mid-codepoint, and slicing the underlying bytes would
/// emit an invalid UTF-8 sequence that the peer then rejects — turning an over-long message into a
/// mysteriously dropped one. Backing up to the nearest char boundary avoids both.
fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Range-checks a HID usage against the pages and values we accept.
fn validate_usage(page: u16, usage: u16) -> Result<(), DecodeError> {
    match page {
        USAGE_PAGE_KEYBOARD => {
            // 0x01..=0xE7 covers the entire keyboard/keypad page including the eight modifier
            // usages. Anything outside it is not a key and must not reach the injection layer.
            if !(0x01..=0xE7).contains(&usage) {
                return Err(DecodeError::InvalidField {
                    field: "usage_id",
                    value: u32::from(usage),
                });
            }
        }
        USAGE_PAGE_CONSUMER => {
            if usage == 0 || usage > 0x029C {
                return Err(DecodeError::InvalidField {
                    field: "usage_id",
                    value: u32::from(usage),
                });
            }
        }
        other => {
            return Err(DecodeError::InvalidField {
                field: "usage_page",
                value: u32::from(other),
            })
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Malformed frame budget
// ---------------------------------------------------------------------------------------------

/// Enforces the malformed-frame budget from `docs/PROTOCOL.md` §6.5.
///
/// Bounds an attacker's ability to probe the parser while still tolerating the genuine version
/// skew that forward compatibility permits. Time is passed in rather than read, so this is
/// testable without sleeping.
#[derive(Debug, Clone)]
pub struct MalformedCounter {
    window_ms: u32,
    limit: u32,
    window_start_ms: u32,
    count: u32,
}

impl Default for MalformedCounter {
    fn default() -> Self {
        Self::new(100, 10_000)
    }
}

impl MalformedCounter {
    /// Creates a counter permitting `limit` malformed frames per `window_ms`.
    #[must_use]
    pub fn new(limit: u32, window_ms: u32) -> Self {
        Self {
            window_ms,
            limit,
            window_start_ms: 0,
            count: 0,
        }
    }

    /// Records one malformed frame at `now_ms`.
    ///
    /// Returns `true` if the session must be terminated.
    pub fn record(&mut self, now_ms: u32) -> bool {
        if now_ms.wrapping_sub(self.window_start_ms) > self.window_ms {
            self.window_start_ms = now_ms;
            self.count = 0;
        }
        self.count += 1;
        self.count > self.limit
    }

    /// Malformed frames counted in the current window.
    #[must_use]
    pub fn count(&self) -> u32 {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example from `docs/PROTOCOL.md` §7.12. If this test fails, either the code or the
    /// specification has drifted — and both are wrong until they agree.
    #[test]
    fn spec_example_mouse_move() {
        let expected: [u8; 16] = [
            0x10, 0x10, 0x04, 0xD2, 0x00, 0x01, 0xE2, 0x40, 0x00, 0x00, 0x80, 0x00, 0x40, 0x00,
            0x00, 0x00,
        ];
        let frame = ControlFrame::new(
            Payload::MouseMove {
                display_id: 0,
                flags: 0,
                x_norm: 32768,
                y_norm: 16384,
                modifiers: Modifiers::NONE,
            },
            1234,
            123_456,
        );
        assert_eq!(frame.encode(), expected);
        assert_eq!(ControlFrame::decode(&expected).unwrap(), frame);
    }

    /// `docs/PROTOCOL.md` §7.12 — press `A` with Left Shift held.
    #[test]
    fn spec_example_key_event() {
        let expected: [u8; 16] = [
            0x10, 0x14, 0x04, 0xD3, 0x00, 0x01, 0xE2, 0x44, 0x00, 0x07, 0x00, 0x04, 0x01, 0x00,
            0x00, 0x02,
        ];
        let frame = ControlFrame::new(
            Payload::KeyEvent {
                usage_page: USAGE_PAGE_KEYBOARD,
                usage_id: 0x0004,
                action: KeyAction::Down,
                flags: 0,
                modifiers: Modifiers(Modifiers::LEFT_SHIFT),
            },
            1235,
            123_460,
        );
        assert_eq!(frame.encode(), expected);
        assert_eq!(ControlFrame::decode(&expected).unwrap(), frame);
    }

    /// `docs/PROTOCOL.md` §7.12 — Left Shift and `A` held, authoritative.
    #[test]
    fn spec_example_key_state_sync() {
        let expected: [u8; 16] = [
            0x10, 0x15, 0x04, 0xD4, 0x00, 0x01, 0xE2, 0xA8, 0x00, 0x02, 0x02, 0x01, 0x00, 0xE1,
            0x00, 0x04,
        ];
        let frame = ControlFrame::new(
            Payload::KeyStateSync {
                modifiers: Modifiers(Modifiers::LEFT_SHIFT),
                authoritative: true,
                pressed: vec![0x00E1, 0x0004],
            },
            1236,
            123_560,
        );
        assert_eq!(frame.encode(), expected);
        assert_eq!(ControlFrame::decode(&expected).unwrap(), frame);
    }

    #[test]
    fn channel_assignment_matches_reliability_design() {
        // Pointer motion on an unreliable channel and keys on a reliable one is the whole basis of
        // the input design; a regression here is silent and severe.
        assert_eq!(MessageType::MouseMove.channel(), Channel::InputPointer);
        assert_eq!(
            MessageType::MouseMoveRelative.channel(),
            Channel::InputPointer
        );
        assert_eq!(MessageType::MouseButton.channel(), Channel::InputKeys);
        assert_eq!(MessageType::KeyEvent.channel(), Channel::InputKeys);
        assert_eq!(MessageType::KeyStateSync.channel(), Channel::InputKeys);
        assert_eq!(MessageType::QosReport.channel(), Channel::Stats);
    }

    #[test]
    fn unknown_type_survives_decode() {
        let mut buf = vec![0x10, 0xEE, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        buf.extend_from_slice(b"future");
        let frame = ControlFrame::decode(&buf).unwrap();
        assert_eq!(
            frame.payload,
            Payload::Unknown {
                msg_type: 0xEE,
                body: b"future".to_vec()
            }
        );
    }

    #[test]
    fn wrong_version_is_rejected() {
        let buf = [0x20, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(ControlFrame::decode(&buf), Err(DecodeError::BadVersion(2)));
    }

    #[test]
    fn truncated_payload_is_rejected_not_panicking() {
        for len in 0..16 {
            let buf = vec![0x10u8, 0x10, 0, 0, 0, 0, 0, 0][..len.min(8)]
                .iter()
                .copied()
                .chain(std::iter::repeat_n(0, len.saturating_sub(8)))
                .collect::<Vec<u8>>();
            let _ = ControlFrame::decode(&buf); // must not panic
        }
        let short = [0x10, 0x10, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            ControlFrame::decode(&short),
            Err(DecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn invalid_enum_values_are_rejected() {
        // button = 9 is not a button.
        let buf = [0x10, 0x12, 0, 0, 0, 0, 0, 0, 9, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        assert!(matches!(
            ControlFrame::decode(&buf),
            Err(DecodeError::InvalidField {
                field: "button",
                ..
            })
        ));
    }

    #[test]
    fn out_of_range_hid_usage_is_rejected() {
        let frame = ControlFrame::new(
            Payload::KeyEvent {
                usage_page: USAGE_PAGE_KEYBOARD,
                usage_id: 0x0FFF, // beyond the keyboard page
                action: KeyAction::Down,
                flags: 0,
                modifiers: Modifiers::NONE,
            },
            1,
            0,
        );
        assert!(matches!(
            ControlFrame::decode(&frame.encode()),
            Err(DecodeError::InvalidField {
                field: "usage_id",
                ..
            })
        ));
    }

    #[test]
    fn oversized_key_state_sync_is_rejected_before_allocating() {
        // count = 200 with no body. A parser that allocated first would reserve 200 slots.
        let buf = [0x10, 0x15, 0, 0, 0, 0, 0, 0, 0, 0, 200, 1];
        assert!(matches!(
            ControlFrame::decode(&buf),
            Err(DecodeError::LengthCap { field: "count", .. })
        ));
    }

    #[test]
    fn cursor_shape_dimension_mismatch_is_rejected() {
        // 16x16 BGRA must be exactly 1024 bytes; claim 8 and the renderer would over-read.
        let mut buf = vec![0x10, 0x36, 0, 0, 0, 0, 0, 0];
        buf.extend_from_slice(&1u32.to_be_bytes()); // shape_id
        buf.extend_from_slice(&16u16.to_be_bytes()); // width
        buf.extend_from_slice(&16u16.to_be_bytes()); // height
        buf.extend_from_slice(&0u16.to_be_bytes()); // hotspot_x
        buf.extend_from_slice(&0u16.to_be_bytes()); // hotspot_y
        buf.push(0); // format = BGRA
        buf.push(0); // reserved
        buf.extend_from_slice(&8u32.to_be_bytes()); // data_len, wrong
        buf.extend_from_slice(&[0u8; 8]);
        assert!(matches!(
            ControlFrame::decode(&buf),
            Err(DecodeError::LengthCap {
                field: "data_len",
                ..
            })
        ));
    }

    #[test]
    fn text_input_rejects_control_characters() {
        let frame = ControlFrame::new(
            Payload::TextInput {
                commit: true,
                preedit: false,
                text: "hi\u{7}there".into(),
            },
            1,
            0,
        );
        assert!(matches!(
            ControlFrame::decode(&frame.encode()),
            Err(DecodeError::InvalidText(_))
        ));
    }

    #[test]
    fn oversized_text_truncates_on_a_codepoint_boundary() {
        // Naive byte truncation would split the last multi-byte character and emit invalid UTF-8,
        // which the peer silently rejects — an over-long paste would vanish rather than clip.
        let text = "é".repeat(MAX_TEXT_INPUT); // 2 bytes each
        let frame = ControlFrame::new(
            Payload::TextInput {
                commit: true,
                preedit: false,
                text,
            },
            1,
            0,
        );
        let decoded = ControlFrame::decode(&frame.encode()).expect("must stay valid UTF-8");
        match decoded.payload {
            Payload::TextInput { text, .. } => {
                assert_eq!(text.len(), MAX_TEXT_INPUT);
                assert!(
                    text.chars().all(|c| c == 'é'),
                    "no partial codepoint may survive"
                );
            }
            other => panic!("expected TextInput, got {other:?}"),
        }
    }

    #[test]
    fn oversized_error_message_truncates_cleanly() {
        let frame = ControlFrame::new(
            Payload::Error {
                code: 1,
                message: "字".repeat(200),
            }, // 3 bytes each
            1,
            0,
        );
        let decoded = ControlFrame::decode(&frame.encode()).expect("must stay valid UTF-8");
        match decoded.payload {
            Payload::Error { message, .. } => {
                assert!(message.len() <= 256);
                assert!(message.chars().all(|c| c == '字'));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn text_input_allows_tab_and_newline() {
        let frame = ControlFrame::new(
            Payload::TextInput {
                commit: true,
                preedit: false,
                text: "a\tb\nc".into(),
            },
            1,
            0,
        );
        assert_eq!(ControlFrame::decode(&frame.encode()).unwrap(), frame);
    }

    #[test]
    fn round_trip_all_simple_payloads() {
        let payloads = vec![
            Payload::Ping { token: 0xDEAD_BEEF },
            Payload::Pong {
                token: 0xDEAD_BEEF,
                host_delay_us: 42,
            },
            Payload::EndSession { code: 0 },
            Payload::MouseMoveRelative {
                dx: -128,
                dy: 64,
                modifiers: Modifiers(Modifiers::LEFT_CTRL),
                display_id: 1,
            },
            Payload::MouseWheel {
                delta_v: 120,
                delta_h: -120,
                modifiers: Modifiers::NONE,
                display_id: 0,
                flags: 1,
            },
            Payload::RequestKeyframe {
                mode: KeyframeMode::Ltr,
                ltr_index: 3,
                reason: 0,
            },
            Payload::LtrAck {
                ltr_index: 3,
                frame_id: 9001,
            },
            Payload::CursorUpdate {
                shape_id: 7,
                x_norm: 1,
                y_norm: 2,
                display_id: 0,
                visible: true,
            },
            Payload::QosReport(QosReport {
                rtt_ms: 220,
                jitter_ms: 18,
                loss_permille: 35,
                frames_decoded: 60,
                frames_dropped: 2,
                render_fps_q8: 60 << 8,
                playout_delay_ms: 30,
                decode_time_us: 3500,
            }),
        ];
        for p in payloads {
            let frame = ControlFrame::new(p, 7, 1234);
            let decoded = ControlFrame::decode(&frame.encode()).unwrap();
            assert_eq!(decoded, frame);
        }
    }

    /// The same property the `control_frame` fuzz target asserts, exercised on stable so it runs
    /// in ordinary CI rather than only under `cargo +nightly fuzz`.
    ///
    /// Anything that decodes must re-encode to bytes that decode back to an identical value. A
    /// violation means two distinct byte strings map to one frame, or that a frame changes meaning
    /// on a round trip through a relay or a log replay.
    #[test]
    fn arbitrary_bytes_never_panic_and_always_round_trip() {
        use rand::{RngCore, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5EED_1234_ABCD_0001);
        let mut accepted = 0usize;

        for _ in 0..20_000 {
            let len = (rng.next_u32() % 64) as usize;
            let mut buf = vec![0u8; len];
            rng.fill_bytes(&mut buf);
            // Bias the version nibble toward valid so a useful share of inputs get past the header.
            if !buf.is_empty() && rng.next_u32() % 2 == 0 {
                buf[0] = (PROTO_VERSION << 4) | (buf[0] & 0x0F);
            }

            let Ok(frame) = ControlFrame::decode(&buf) else {
                continue;
            };
            accepted += 1;
            let encoded = frame.encode();
            let reparsed = ControlFrame::decode(&encoded)
                .expect("a frame we produced must be one we can parse");
            assert_eq!(
                frame, reparsed,
                "round trip changed the frame; input {buf:02x?}"
            );
        }

        assert!(
            accepted > 100,
            "only {accepted} inputs decoded; the test is not exercising much"
        );
    }

    #[test]
    fn malformed_budget_terminates_only_past_the_limit() {
        let mut c = MalformedCounter::new(3, 1000);
        assert!(!c.record(0));
        assert!(!c.record(10));
        assert!(!c.record(20));
        assert!(c.record(30), "fourth frame in the window must terminate");

        // A new window resets the budget: honest version skew should not accumulate forever.
        let mut c = MalformedCounter::new(3, 1000);
        assert!(!c.record(0));
        assert!(!c.record(2000));
        assert_eq!(c.count(), 1);
    }
}
