//! C ABI bridge from the Rust engine to Flutter — `docs/ARCHITECTURE.md` §1.6.
//!
//! **This crate contains no logic.** Every function here translates between C types and a Rust API
//! that lives elsewhere. That rule exists because code inside an FFI boundary is invisible to
//! Rust's test tooling and awkward to reason about; keeping it a pure translation layer means the
//! things worth testing are tested where they live.
//!
//! ## The contract
//!
//! - All handles are opaque pointers from [`Box::into_raw`]. They are freed by exactly one
//!   `*_destroy` call and are inert afterwards.
//! - Every entry point tolerates a null handle and returns an error rather than dereferencing it.
//!   Dart can and will pass null after a hot restart.
//! - Fallible calls return an [`RdaStatus`] code. `0` is success; details are retrievable with
//!   [`rda_last_error`], which returns a pointer valid until the next call on that thread.
//! - Pixel buffers are borrowed, never transferred. [`rda_client_frame_data`] hands out a pointer
//!   valid only until the next [`rda_client_poll_frame`] on the same client, which is what lets the
//!   UI upload straight into a texture with no copy.
//!
//! ## Threading
//!
//! A client is **not** thread-safe and must be used from one thread. Flutter's FFI calls run on the
//! Dart isolate's thread, and the hardware decoder is thread-affine anyway, so this costs nothing
//! and removes a whole class of race.

// `deny` rather than `forbid`: a C ABI is unsafe by construction. Every `unsafe` block here carries
// the invariant it relies on, and there is no unsafe outside the entry points themselves.
#![deny(missing_docs)]
#![allow(clippy::missing_safety_doc)]

mod client;
mod error;
mod input;

pub use client::*;
pub use error::*;
pub use input::*;

/// Status code returned by fallible entry points.
///
/// A plain `i32` rather than an enum so the ABI is stable across compilers and easy to match in
/// Dart. Negative values are errors.
pub type RdaStatus = i32;

/// The call succeeded.
pub const RDA_OK: RdaStatus = 0;
/// A required pointer argument was null.
pub const RDA_ERR_NULL_ARGUMENT: RdaStatus = -1;
/// An argument was outside its permitted range.
pub const RDA_ERR_INVALID_ARGUMENT: RdaStatus = -2;
/// The operation is not valid in the client's current state.
pub const RDA_ERR_WRONG_STATE: RdaStatus = -3;
/// Decoding failed.
pub const RDA_ERR_DECODE: RdaStatus = -4;
/// No frame is ready. Not a failure — the caller should try again next vsync.
pub const RDA_ERR_NO_FRAME: RdaStatus = -5;
/// The platform lacks a required capability, such as a hardware decoder.
pub const RDA_ERR_UNSUPPORTED: RdaStatus = -6;
/// A string argument was not valid UTF-8.
pub const RDA_ERR_BAD_UTF8: RdaStatus = -7;

/// Returns the ABI version this library implements.
///
/// Dart checks this at startup. A mismatch means the bundled dynamic library is stale — which
/// happens constantly during development and produces baffling crashes if it goes undetected.
#[no_mangle]
pub extern "C" fn rda_abi_version() -> u32 {
    1
}

/// Initialises logging. Safe to call more than once; later calls do nothing.
#[no_mangle]
pub extern "C" fn rda_init_logging() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_env("RDA_LOG")
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .try_init();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_abi_version_is_stable() {
        // Bumping this is a deliberate breaking change: Dart refuses to load a mismatched library.
        assert_eq!(rda_abi_version(), 1);
    }

    #[test]
    fn initialising_logging_twice_is_harmless() {
        rda_init_logging();
        rda_init_logging();
    }

    #[test]
    fn status_codes_are_distinct_and_only_success_is_zero() {
        let codes = [
            RDA_OK,
            RDA_ERR_NULL_ARGUMENT,
            RDA_ERR_INVALID_ARGUMENT,
            RDA_ERR_WRONG_STATE,
            RDA_ERR_DECODE,
            RDA_ERR_NO_FRAME,
            RDA_ERR_UNSUPPORTED,
            RDA_ERR_BAD_UTF8,
        ];
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len(), "duplicate status code");
        assert!(
            codes.iter().filter(|&&c| c == 0).count() == 1,
            "only success may be zero"
        );
        assert!(
            codes.iter().filter(|&&c| c != 0).all(|&c| c < 0),
            "errors must be negative"
        );
    }
}
