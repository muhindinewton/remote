//! Session establishment: signaling to a connected, authenticated peer.
//!
//! The seam every earlier phase tested from one side and none crossed. [`negotiate`] pumps SDP and
//! ICE between the signaling client and the transport until the peer connection is up; [`auth`]
//! then runs the PIN handshake over the control channel so the host can issue a capability grant.
//!
//! Shared by both binaries deliberately: two implementations of a handshake is how the two ends of
//! a handshake come to disagree.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod auth;
pub mod negotiate;

pub use negotiate::{accept_connection, connect_to_host, NegotiateError, Negotiated};
