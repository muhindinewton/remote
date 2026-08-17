//! WebRTC transport for the RDA remote desktop engine.
//!
//! Owns the peer connection, the ICE policy and the DataChannel topology. Three things in here are
//! deliberately not the WebRTC defaults, because the defaults are tuned for conferencing on short
//! links and this is neither:
//!
//! - **Channels are pre-negotiated** ([`channels`]) — in-band DCEP costs a round trip per channel,
//!   which is over a second of setup across seven channels at 220 ms RTT.
//! - **Relay candidates are capped at two PoPs** ([`ice`]) — candidate count multiplies the ICE
//!   check matrix, and each check round costs an RTT.
//! - **Reliability is per channel, not per session** ([`channels`]) — pointer motion and keystrokes
//!   have opposite requirements, and SCTP's per-stream head-of-line blocking is what lets us give
//!   each what it needs.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod channels;
pub mod ice;
pub mod session;

pub use channels::{ChannelSpec, CHANNELS};
pub use ice::{PathKind, RoutingPreference, ICE_TIMEOUT, P2P_GRACE};
pub use session::{PeerConnectionState, Session, SessionRole, TransportError, TransportEvent};
