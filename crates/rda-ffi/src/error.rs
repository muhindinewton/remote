//! Error reporting across the FFI boundary.
//!
//! A status code tells Dart *that* something failed; this tells it *what*. The message is stored
//! per thread so two isolates cannot overwrite each other's, and the returned pointer stays valid
//! until the next call on the same thread — the same contract as `strerror`, which Dart developers
//! already understand.

use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};

thread_local! {
    /// The last error, kept alive so the pointer handed to C stays valid.
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// Records an error message for the current thread.
pub(crate) fn set_last_error(message: impl Into<String>) {
    let text = message.into();
    // Interior nul bytes cannot cross into C, so replace rather than drop the message: a mangled
    // diagnostic beats no diagnostic.
    let sanitised = text.replace('\0', "?");
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = CString::new(sanitised).ok();
    });
}

/// Clears the current thread's error.
pub(crate) fn clear_last_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

/// Returns the last error message on this thread, or null if there is none.
///
/// The pointer is valid until the next call into this library on the same thread. Callers that need
/// to keep the text must copy it, which is what Dart's `toDartString()` does anyway.
#[no_mangle]
pub extern "C" fn rda_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| {
        slot.borrow()
            .as_ref()
            .map_or(std::ptr::null(), |s| s.as_ptr())
    })
}

/// Reads a C string argument into a Rust `&str`.
///
/// Returns `None` for null or non-UTF-8 input, and records why. Dart strings are UTF-8, so a
/// failure here means a genuinely malformed argument rather than an encoding mismatch.
///
/// # Safety
///
/// `ptr` must be null or point at a nul-terminated string that outlives the borrow.
pub(crate) unsafe fn borrow_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        set_last_error("required string argument was null");
        return None;
    }
    // SAFETY: the caller guarantees a valid nul-terminated string for the borrow's lifetime.
    match unsafe { CStr::from_ptr(ptr) }.to_str() {
        Ok(s) => Some(s),
        Err(e) => {
            set_last_error(format!("string argument is not valid UTF-8: {e}"));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_error_is_reported_as_null() {
        clear_last_error();
        assert!(rda_last_error().is_null());
    }

    #[test]
    fn a_recorded_error_round_trips() {
        set_last_error("decoder is waiting for a keyframe");
        let ptr = rda_last_error();
        assert!(!ptr.is_null());
        // SAFETY: the pointer was just produced by this thread and nothing has run since.
        let text = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(text, "decoder is waiting for a keyframe");
        clear_last_error();
    }

    #[test]
    fn an_interior_nul_does_not_lose_the_message() {
        // A mangled diagnostic beats silently reporting no error at all.
        set_last_error("bad\0message");
        let ptr = rda_last_error();
        assert!(!ptr.is_null(), "the message must survive sanitisation");
        // SAFETY: as above.
        assert_eq!(
            unsafe { CStr::from_ptr(ptr) }.to_str().unwrap(),
            "bad?message"
        );
        clear_last_error();
    }

    #[test]
    fn errors_are_per_thread() {
        // Two Dart isolates must not overwrite each other's diagnostics.
        set_last_error("main thread");
        let handle = std::thread::spawn(|| {
            assert!(
                rda_last_error().is_null(),
                "a fresh thread starts with no error"
            );
            set_last_error("worker thread");
            // SAFETY: pointer produced on this thread, nothing has run since.
            unsafe { CStr::from_ptr(rda_last_error()) }
                .to_str()
                .unwrap()
                .to_owned()
        });
        assert_eq!(handle.join().unwrap(), "worker thread");
        // SAFETY: as above.
        assert_eq!(
            unsafe { CStr::from_ptr(rda_last_error()) }
                .to_str()
                .unwrap(),
            "main thread"
        );
        clear_last_error();
    }

    #[test]
    fn borrowing_a_null_string_fails_rather_than_dereferencing() {
        clear_last_error();
        // SAFETY: null is explicitly permitted by the contract.
        assert!(unsafe { borrow_str(std::ptr::null()) }.is_none());
        assert!(!rda_last_error().is_null(), "the failure must be explained");
        clear_last_error();
    }

    #[test]
    fn borrowing_a_valid_string_works() {
        let owned = CString::new("K7M2-9QXR-4TVB").unwrap();
        // SAFETY: `owned` outlives the borrow.
        let borrowed = unsafe { borrow_str(owned.as_ptr()) };
        assert_eq!(borrowed, Some("K7M2-9QXR-4TVB"));
    }

    #[test]
    fn borrowing_invalid_utf8_fails() {
        // Dart strings are UTF-8, so this means a genuinely malformed argument.
        let bytes = [0xFFu8, 0xFE, 0x00];
        // SAFETY: the array is nul-terminated and outlives the borrow.
        let result = unsafe { borrow_str(bytes.as_ptr().cast()) };
        assert!(result.is_none());
        clear_last_error();
    }
}
