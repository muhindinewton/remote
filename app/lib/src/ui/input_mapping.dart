// Pure input mapping, extracted from the widget so it can be tested.
//
// These three functions are where keyboard and pointer correctness actually lives, and none of them
// needs a window, a native library or a running session. Leaving them buried in a `State` class
// would mean the only way to check them is to run the app on a device — which is exactly the code
// that then never gets checked.

import 'package:flutter/gestures.dart';
import 'package:flutter/services.dart';

/// Modifier bits, matching `docs/PROTOCOL.md` §7.9.
///
/// Bits 0–7 are byte-identical to the USB HID boot-protocol modifier byte, which is what makes
/// translation on the host a no-op rather than a table lookup.
abstract final class ModifierBits {
  static const int leftCtrl = 0x0001;
  static const int leftShift = 0x0002;
  static const int leftAlt = 0x0004;
  static const int leftGui = 0x0008;
  static const int rightCtrl = 0x0010;
  static const int rightShift = 0x0020;
  static const int rightAlt = 0x0040;
  static const int rightGui = 0x0080;
}

/// HID usage page 0x07, keyboard/keypad. The only page the host accepts.
const int hidPageKeyboard = 0x0007;

/// Lowest and highest usage ids the host will inject.
const int hidUsageMin = 0x01;
const int hidUsageMax = 0xE7;

/// Extracts the HID usage id from a Flutter physical key, or null if it is not one we send.
///
/// Flutter's `usbHidUsage` packs the usage page in the high 16 bits — `0x00070004` for the key at
/// the `A` position — so the id is the low half. This is the happy accident the whole keyboard
/// design rests on: Flutter already speaks the identity the wire protocol chose, so a controller on
/// any layout sends the key *position* the user pressed rather than the character it produced.
int? hidUsageFor(PhysicalKeyboardKey key) {
  final packed = key.usbHidUsage;
  final page = (packed >> 16) & 0xFFFF;
  final usage = packed & 0xFFFF;
  if (page != hidPageKeyboard) return null;
  if (usage < hidUsageMin || usage > hidUsageMax) return null;
  return usage;
}

/// The modifier bitmask implied by a set of held HID usages.
int modifiersFor(Iterable<int> heldUsages) {
  var bits = 0;
  for (final usage in heldUsages) {
    switch (usage) {
      case 0xE0:
        bits |= ModifierBits.leftCtrl;
      case 0xE1:
        bits |= ModifierBits.leftShift;
      case 0xE2:
        bits |= ModifierBits.leftAlt;
      case 0xE3:
        bits |= ModifierBits.leftGui;
      case 0xE4:
        bits |= ModifierBits.rightCtrl;
      case 0xE5:
        bits |= ModifierBits.rightShift;
      case 0xE6:
        bits |= ModifierBits.rightAlt;
      case 0xE7:
        bits |= ModifierBits.rightGui;
    }
  }
  return bits;
}

/// Converts a local widget position to the normalised coordinates the wire uses.
///
/// `0..=65535` across the canvas, so the value is independent of window size and DPI and survives a
/// host resolution change in flight. Clamped rather than rejected: a position slightly outside the
/// canvas is a rounding artefact far more often than an error, and dropping it would make the
/// cursor stutter at the edges.
(int, int) normalisePosition(Offset local, Size canvas) {
  if (canvas.width <= 0 || canvas.height <= 0) return (0, 0);
  final x = (local.dx / canvas.width).clamp(0.0, 1.0);
  final y = (local.dy / canvas.height).clamp(0.0, 1.0);
  return ((x * 65535).round(), (y * 65535).round());
}

/// Maps Flutter's button bitmask to the wire's button id.
int buttonIdFor(int flutterButtons) {
  if (flutterButtons & kSecondaryMouseButton != 0) return 2;
  if (flutterButtons & kMiddleMouseButton != 0) return 3;
  if (flutterButtons & kBackMouseButton != 0) return 4;
  if (flutterButtons & kForwardMouseButton != 0) return 5;
  return 1;
}

/// Logical pixels Flutter reports for one traditional scroll detent.
const double logicalPixelsPerDetent = 50.0;

/// Converts a Flutter scroll delta to the wire's 1/120-of-a-detent units.
///
/// The vertical sign is inverted because Flutter's positive Y points down the page while the wire's
/// positive vertical means scrolling up. Getting this backwards is invisible in review and
/// immediately obvious to anyone using it.
(int, int) scrollDeltaFor(Offset flutterDelta) {
  final v = (-flutterDelta.dy / logicalPixelsPerDetent * 120).round().clamp(-32768, 32767);
  final h = (flutterDelta.dx / logicalPixelsPerDetent * 120).round().clamp(-32768, 32767);
  return (v, h);
}
