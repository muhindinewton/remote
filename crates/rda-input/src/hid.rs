//! USB HID usage IDs and their mapping to platform key codes — `docs/ARCHITECTURE.md` §4.2.
//!
//! The wire carries **physical key positions** as HID Usage Page 0x07 usage IDs, not characters and
//! not platform key codes. The reason is concrete: a controller on an AZERTY layout pressing the key
//! labelled `A` must produce whatever the *host's* layout produces at that position. Sending the
//! character `a` breaks shortcuts; sending a Windows virtual-key code breaks everything that is not
//! Windows, and is itself layout-dependent.
//!
//! The mapping is generated from the USB HID Usage Tables cross-referenced with Chromium's
//! `ui/events/keycodes/dom/dom_code_data.inc`, which is the canonical battle-tested table for this
//! exact problem. It is vendored here as data rather than pulled from a thin crate so it is
//! reviewable and diffable.
//!
//! Text that cannot be expressed as a key position — dead keys, compose sequences, CJK IME output —
//! travels as Unicode on a separate message type instead.

/// HID Usage Page 0x07: Keyboard / Keypad.
pub const PAGE_KEYBOARD: u16 = 0x0007;
/// HID Usage Page 0x0C: Consumer controls (volume, media transport).
pub const PAGE_CONSUMER: u16 = 0x000C;

/// Lowest valid keyboard usage.
pub const KEYBOARD_USAGE_MIN: u16 = 0x01;
/// Highest valid keyboard usage we accept (`RightGUI`).
pub const KEYBOARD_USAGE_MAX: u16 = 0xE7;

/// Modifier usages, in the bit order of the HID boot-protocol modifier byte.
pub const MODIFIER_USAGES: [u16; 8] = [
    0xE0, // Left Control
    0xE1, // Left Shift
    0xE2, // Left Alt
    0xE3, // Left GUI
    0xE4, // Right Control
    0xE5, // Right Shift
    0xE6, // Right Alt
    0xE7, // Right GUI
];

/// Returns the modifier bitmask bit for a usage, if it is a modifier key.
#[must_use]
pub fn modifier_bit(usage: u16) -> Option<u16> {
    MODIFIER_USAGES
        .iter()
        .position(|&u| u == usage)
        .map(|i| 1u16 << i)
}

/// Returns `true` if the usage is one of the eight modifier keys.
#[must_use]
pub fn is_modifier(usage: u16) -> bool {
    (0xE0..=0xE7).contains(&usage)
}

/// Whether a usage is one we will ever inject.
///
/// The allowlist is a real defence, not bookkeeping: the injection layer is handed values parsed
/// from a hostile network, and a usage outside this range reaching a platform API is undefined
/// behaviour at the OS boundary.
#[must_use]
pub fn is_valid_keyboard_usage(usage: u16) -> bool {
    (KEYBOARD_USAGE_MIN..=KEYBOARD_USAGE_MAX).contains(&usage)
}

/// One row of the mapping table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyMapping {
    /// HID Usage Page 0x07 usage id.
    pub usage: u16,
    /// PS/2 set-1 scan code, as `SendInput` wants it on Windows. The high byte `0xE0` marks an
    /// extended key, which the Windows backend translates into `KEYEVENTF_EXTENDEDKEY`.
    pub windows_scancode: u16,
    /// macOS `CGKeyCode` (Carbon virtual key code).
    pub macos_keycode: u16,
    /// Linux `evdev` `KEY_*` code.
    pub linux_evdev: u16,
    /// Stable name, for logs and debugging. Never used for injection.
    pub name: &'static str,
}

/// Sentinel for "this platform has no code for this key".
pub const NO_CODE: u16 = 0xFFFF;

/// The mapping table.
///
/// Ordered by usage id so [`lookup`] can binary search. The ordering is asserted by a test — a
/// misordered entry would silently make one key unreachable rather than failing loudly.
pub const KEY_TABLE: &[KeyMapping] = &[
    m(0x04, 0x1E, 0x00, 30, "KeyA"),
    m(0x05, 0x30, 0x0B, 48, "KeyB"),
    m(0x06, 0x2E, 0x08, 46, "KeyC"),
    m(0x07, 0x20, 0x02, 32, "KeyD"),
    m(0x08, 0x12, 0x0E, 18, "KeyE"),
    m(0x09, 0x21, 0x03, 33, "KeyF"),
    m(0x0A, 0x22, 0x05, 34, "KeyG"),
    m(0x0B, 0x23, 0x04, 35, "KeyH"),
    m(0x0C, 0x17, 0x22, 23, "KeyI"),
    m(0x0D, 0x24, 0x26, 36, "KeyJ"),
    m(0x0E, 0x25, 0x28, 37, "KeyK"),
    m(0x0F, 0x26, 0x25, 38, "KeyL"),
    m(0x10, 0x32, 0x2E, 50, "KeyM"),
    m(0x11, 0x31, 0x2D, 49, "KeyN"),
    m(0x12, 0x18, 0x1F, 24, "KeyO"),
    m(0x13, 0x19, 0x23, 25, "KeyP"),
    m(0x14, 0x10, 0x0C, 16, "KeyQ"),
    m(0x15, 0x13, 0x0F, 19, "KeyR"),
    m(0x16, 0x1F, 0x01, 31, "KeyS"),
    m(0x17, 0x14, 0x11, 20, "KeyT"),
    m(0x18, 0x16, 0x20, 22, "KeyU"),
    m(0x19, 0x2F, 0x09, 47, "KeyV"),
    m(0x1A, 0x11, 0x0D, 17, "KeyW"),
    m(0x1B, 0x2D, 0x07, 45, "KeyX"),
    m(0x1C, 0x15, 0x10, 21, "KeyY"),
    m(0x1D, 0x2C, 0x06, 44, "KeyZ"),
    m(0x1E, 0x02, 0x12, 2, "Digit1"),
    m(0x1F, 0x03, 0x13, 3, "Digit2"),
    m(0x20, 0x04, 0x14, 4, "Digit3"),
    m(0x21, 0x05, 0x15, 5, "Digit4"),
    m(0x22, 0x06, 0x17, 6, "Digit5"),
    m(0x23, 0x07, 0x16, 7, "Digit6"),
    m(0x24, 0x08, 0x1A, 8, "Digit7"),
    m(0x25, 0x09, 0x1C, 9, "Digit8"),
    m(0x26, 0x0A, 0x19, 10, "Digit9"),
    m(0x27, 0x0B, 0x1D, 11, "Digit0"),
    m(0x28, 0x1C, 0x24, 28, "Enter"),
    m(0x29, 0x01, 0x35, 1, "Escape"),
    m(0x2A, 0x0E, 0x33, 14, "Backspace"),
    m(0x2B, 0x0F, 0x30, 15, "Tab"),
    m(0x2C, 0x39, 0x31, 57, "Space"),
    m(0x2D, 0x0C, 0x1B, 12, "Minus"),
    m(0x2E, 0x0D, 0x18, 13, "Equal"),
    m(0x2F, 0x1A, 0x21, 26, "BracketLeft"),
    m(0x30, 0x1B, 0x1E, 27, "BracketRight"),
    m(0x31, 0x2B, 0x2A, 43, "Backslash"),
    m(0x33, 0x27, 0x29, 39, "Semicolon"),
    m(0x34, 0x28, 0x27, 40, "Quote"),
    m(0x35, 0x29, 0x32, 41, "Backquote"),
    m(0x36, 0x33, 0x2B, 51, "Comma"),
    m(0x37, 0x34, 0x2F, 52, "Period"),
    m(0x38, 0x35, 0x2C, 53, "Slash"),
    m(0x39, 0x3A, 0x39, 58, "CapsLock"),
    m(0x3A, 0x3B, 0x7A, 59, "F1"),
    m(0x3B, 0x3C, 0x78, 60, "F2"),
    m(0x3C, 0x3D, 0x63, 61, "F3"),
    m(0x3D, 0x3E, 0x76, 62, "F4"),
    m(0x3E, 0x3F, 0x60, 63, "F5"),
    m(0x3F, 0x40, 0x61, 64, "F6"),
    m(0x40, 0x41, 0x62, 65, "F7"),
    m(0x41, 0x42, 0x64, 66, "F8"),
    m(0x42, 0x43, 0x65, 67, "F9"),
    m(0x43, 0x44, 0x6D, 68, "F10"),
    m(0x44, 0x57, 0x67, 87, "F11"),
    m(0x45, 0x58, 0x6F, 88, "F12"),
    m(0x46, 0xE037, 0x69, 99, "PrintScreen"),
    m(0x47, 0x46, NO_CODE, 70, "ScrollLock"),
    m(0x48, 0x45, NO_CODE, 119, "Pause"),
    m(0x49, 0xE052, 0x72, 110, "Insert"),
    m(0x4A, 0xE047, 0x73, 102, "Home"),
    m(0x4B, 0xE049, 0x74, 104, "PageUp"),
    m(0x4C, 0xE053, 0x75, 111, "Delete"),
    m(0x4D, 0xE04F, 0x77, 107, "End"),
    m(0x4E, 0xE051, 0x79, 109, "PageDown"),
    m(0x4F, 0xE04D, 0x7C, 106, "ArrowRight"),
    m(0x50, 0xE04B, 0x7B, 105, "ArrowLeft"),
    m(0x51, 0xE050, 0x7D, 108, "ArrowDown"),
    m(0x52, 0xE048, 0x7E, 103, "ArrowUp"),
    m(0x53, 0x45, 0x47, 69, "NumLock"),
    m(0x54, 0xE035, 0x4B, 98, "NumpadDivide"),
    m(0x55, 0x37, 0x43, 55, "NumpadMultiply"),
    m(0x56, 0x4A, 0x4E, 74, "NumpadSubtract"),
    m(0x57, 0x4E, 0x45, 78, "NumpadAdd"),
    m(0x58, 0xE01C, 0x4C, 96, "NumpadEnter"),
    m(0x59, 0x4F, 0x53, 79, "Numpad1"),
    m(0x5A, 0x50, 0x54, 80, "Numpad2"),
    m(0x5B, 0x51, 0x55, 81, "Numpad3"),
    m(0x5C, 0x4B, 0x56, 75, "Numpad4"),
    m(0x5D, 0x4C, 0x57, 76, "Numpad5"),
    m(0x5E, 0x4D, 0x58, 77, "Numpad6"),
    m(0x5F, 0x47, 0x59, 71, "Numpad7"),
    m(0x60, 0x48, 0x5B, 72, "Numpad8"),
    m(0x61, 0x49, 0x5C, 73, "Numpad9"),
    m(0x62, 0x52, 0x52, 82, "Numpad0"),
    m(0x63, 0x53, 0x41, 83, "NumpadDecimal"),
    m(0x64, 0x56, 0x0A, 86, "IntlBackslash"),
    m(0x65, 0xE05D, 0x6E, 127, "ContextMenu"),
    m(0x67, 0x59, 0x51, 117, "NumpadEqual"),
    // Volume keys live on the *keyboard* page, not the consumer page — Flutter reports
    // `audioVolumeUp` as 0x00070080. Omitting them meant a controller could send a usage the host
    // then rejected as unknown, so the key did nothing and said nothing. macOS has no CGKeyCode for
    // these at all: volume there is a system-defined NSEvent, not a key code, so it is NO_CODE.
    m(0x7F, 0xE020, NO_CODE, 113, "AudioVolumeMute"),
    m(0x80, 0xE030, NO_CODE, 115, "AudioVolumeUp"),
    m(0x81, 0xE02E, NO_CODE, 114, "AudioVolumeDown"),
    m(0xE0, 0x1D, 0x3B, 29, "ControlLeft"),
    m(0xE1, 0x2A, 0x38, 42, "ShiftLeft"),
    m(0xE2, 0x38, 0x3A, 56, "AltLeft"),
    m(0xE3, 0xE05B, 0x37, 125, "MetaLeft"),
    m(0xE4, 0xE01D, 0x3E, 97, "ControlRight"),
    m(0xE5, 0x36, 0x3C, 54, "ShiftRight"),
    m(0xE6, 0xE038, 0x3D, 100, "AltRight"),
    m(0xE7, 0xE05C, 0x36, 126, "MetaRight"),
];

const fn m(
    usage: u16,
    windows_scancode: u16,
    macos_keycode: u16,
    linux_evdev: u16,
    name: &'static str,
) -> KeyMapping {
    KeyMapping {
        usage,
        windows_scancode,
        macos_keycode,
        linux_evdev,
        name,
    }
}

/// Looks up a HID usage.
///
/// Returns `None` for usages we have no mapping for, which the injection layer treats as
/// "discard this event" rather than guessing at a code.
#[must_use]
pub fn lookup(usage: u16) -> Option<&'static KeyMapping> {
    KEY_TABLE
        .binary_search_by_key(&usage, |m| m.usage)
        .ok()
        .map(|i| &KEY_TABLE[i])
}

/// Looks up by name. Test and debugging convenience only.
#[must_use]
pub fn lookup_by_name(name: &str) -> Option<&'static KeyMapping> {
    KEY_TABLE.iter().find(|m| m.name == name)
}

impl KeyMapping {
    /// The platform code for the target this build runs on, or `None` if unmapped.
    #[must_use]
    pub fn platform_code(&self) -> Option<u16> {
        let code = if cfg!(target_os = "windows") {
            self.windows_scancode
        } else if cfg!(target_os = "macos") {
            self.macos_keycode
        } else {
            self.linux_evdev
        };
        (code != NO_CODE).then_some(code)
    }

    /// Whether the Windows scan code needs the extended-key flag.
    #[must_use]
    pub fn windows_extended(&self) -> bool {
        self.windows_scancode & 0xFF00 == 0xE000
    }

    /// The low byte of the Windows scan code, which is what `SendInput` actually takes.
    #[must_use]
    pub fn windows_scancode_low(&self) -> u16 {
        self.windows_scancode & 0x00FF
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_sorted_so_binary_search_works() {
        // A misordered entry would make some key silently unreachable rather than failing loudly.
        for pair in KEY_TABLE.windows(2) {
            assert!(
                pair[0].usage < pair[1].usage,
                "table is unsorted at {} -> {}",
                pair[0].name,
                pair[1].name
            );
        }
    }

    #[test]
    fn names_and_usages_are_unique() {
        let names: std::collections::HashSet<_> = KEY_TABLE.iter().map(|m| m.name).collect();
        assert_eq!(names.len(), KEY_TABLE.len(), "duplicate key name");
        let usages: std::collections::HashSet<_> = KEY_TABLE.iter().map(|m| m.usage).collect();
        assert_eq!(usages.len(), KEY_TABLE.len(), "duplicate usage");
    }

    #[test]
    fn lookup_finds_representative_keys() {
        assert_eq!(lookup(0x04).unwrap().name, "KeyA");
        assert_eq!(lookup(0x28).unwrap().name, "Enter");
        assert_eq!(lookup(0xE1).unwrap().name, "ShiftLeft");
        assert_eq!(lookup(0x2C).unwrap().name, "Space");
    }

    #[test]
    fn unmapped_usages_return_none_rather_than_guessing() {
        assert!(lookup(0x00).is_none());
        assert!(lookup(0x32).is_none()); // gap in the table
        assert!(lookup(0xFFFF).is_none());
    }

    #[test]
    fn every_modifier_is_mapped_and_recognised() {
        for (i, &usage) in MODIFIER_USAGES.iter().enumerate() {
            assert!(lookup(usage).is_some(), "modifier {usage:#04x} is unmapped");
            assert!(is_modifier(usage));
            assert_eq!(modifier_bit(usage), Some(1u16 << i));
        }
        assert!(!is_modifier(0x04));
        assert_eq!(modifier_bit(0x04), None);
    }

    #[test]
    fn modifier_bits_match_the_protocol_bitmask() {
        // The wire modifier bitmask and the HID boot-protocol modifier byte must agree bit for bit,
        // or translation silently swaps Ctrl and Shift.
        use rda_proto::control::Modifiers;
        assert_eq!(modifier_bit(0xE0), Some(Modifiers::LEFT_CTRL));
        assert_eq!(modifier_bit(0xE1), Some(Modifiers::LEFT_SHIFT));
        assert_eq!(modifier_bit(0xE2), Some(Modifiers::LEFT_ALT));
        assert_eq!(modifier_bit(0xE3), Some(Modifiers::LEFT_GUI));
        assert_eq!(modifier_bit(0xE4), Some(Modifiers::RIGHT_CTRL));
        assert_eq!(modifier_bit(0xE5), Some(Modifiers::RIGHT_SHIFT));
        assert_eq!(modifier_bit(0xE6), Some(Modifiers::RIGHT_ALT));
        assert_eq!(modifier_bit(0xE7), Some(Modifiers::RIGHT_GUI));
    }

    #[test]
    fn every_mapped_usage_is_within_the_allowlist() {
        for entry in KEY_TABLE {
            assert!(
                is_valid_keyboard_usage(entry.usage),
                "{} at {:#04x} is outside the accepted range",
                entry.name,
                entry.usage
            );
        }
    }

    #[test]
    fn extended_windows_keys_are_flagged_correctly() {
        // Arrow keys, navigation and the right-hand modifiers are extended; letters are not.
        assert!(lookup_by_name("ArrowUp").unwrap().windows_extended());
        assert!(lookup_by_name("ControlRight").unwrap().windows_extended());
        assert!(lookup_by_name("NumpadDivide").unwrap().windows_extended());
        assert!(!lookup_by_name("KeyA").unwrap().windows_extended());
        assert!(!lookup_by_name("ShiftLeft").unwrap().windows_extended());

        assert_eq!(
            lookup_by_name("ArrowUp").unwrap().windows_scancode_low(),
            0x48
        );
        assert_eq!(lookup_by_name("KeyA").unwrap().windows_scancode_low(), 0x1E);
    }

    #[test]
    fn platform_codes_resolve_on_this_build() {
        // Whatever platform the tests run on, the common keys must have a usable code.
        for name in [
            "KeyA",
            "Enter",
            "Space",
            "Tab",
            "ShiftLeft",
            "ControlLeft",
            "ArrowUp",
        ] {
            let entry = lookup_by_name(name).unwrap();
            assert!(
                entry.platform_code().is_some(),
                "{name} has no code on this platform"
            );
        }
    }

    #[test]
    fn macos_unmapped_keys_are_marked_rather_than_zero() {
        // ScrollLock and Pause genuinely do not exist on macOS. They must be NO_CODE, not 0 —
        // 0 is a real key code there (KeyA), so a zero default would type an 'a'.
        let scroll = lookup_by_name("ScrollLock").unwrap();
        assert_eq!(scroll.macos_keycode, NO_CODE);
        #[cfg(target_os = "macos")]
        assert!(scroll.platform_code().is_none());
    }

    #[test]
    fn keyboard_page_volume_keys_are_mapped() {
        // Found by the Dart test in app/test/input_mapping_test.dart: Flutter reports these on the
        // keyboard page (0x0007), so a controller sends them and the host must recognise them
        // rather than rejecting the usage as unknown.
        for (usage, name) in [
            (0x7Fu16, "AudioVolumeMute"),
            (0x80, "AudioVolumeUp"),
            (0x81, "AudioVolumeDown"),
        ] {
            let entry =
                lookup(usage).unwrap_or_else(|| panic!("{name} at {usage:#04x} is unmapped"));
            assert_eq!(entry.name, name);
            assert!(is_valid_keyboard_usage(usage));
        }
        // macOS handles volume as a system-defined event rather than a key code, so there is
        // deliberately nothing to map to there.
        assert_eq!(lookup(0x80).unwrap().macos_keycode, NO_CODE);
    }

    #[test]
    fn letters_and_digits_are_completely_covered() {
        for usage in 0x04..=0x1D {
            assert!(lookup(usage).is_some(), "letter usage {usage:#04x} missing");
        }
        for usage in 0x1E..=0x27 {
            assert!(lookup(usage).is_some(), "digit usage {usage:#04x} missing");
        }
        for usage in 0x3A..=0x45 {
            assert!(
                lookup(usage).is_some(),
                "function key usage {usage:#04x} missing"
            );
        }
    }
}
