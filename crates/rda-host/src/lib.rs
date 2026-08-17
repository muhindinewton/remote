//! The host agent: the machine whose screen and keyboard are at stake.
//!
//! This crate owns the part of the session state machine where authorization actually happens
//! ([`session`]) and the thread that drives capture ([`capture_thread`]). Everything it exposes is
//! built so the dangerous operation — injecting input — cannot be reached without passing through
//! the authorization gate first.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod capture_thread;
pub mod serve;
pub mod session;

pub use serve::{serve, ServeOptions};
pub use session::{ConsentDecision, HostSession, SessionError, SessionState};
