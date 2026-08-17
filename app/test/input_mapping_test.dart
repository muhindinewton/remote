// Tests for the input mapping.
//
// The most valuable assertion here is the first one: it checks that Flutter's
// `PhysicalKeyboardKey.usbHidUsage` really does carry the same USB HID usage ids that the Rust
// table in `crates/rda-input/src/hid.rs` maps from. The whole keyboard design assumes those two
// independently-written tables agree, and nothing else in either language would notice if they
// stopped.

import 'package:flutter/gestures.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rda_viewer/src/ui/input_mapping.dart';

void main() {
  group('HID usage extraction', () {
    test('Flutter usages match the Rust HID table', () {
      // Left column: Flutter's physical key. Right column: the usage id in
      // crates/rda-input/src/hid.rs KEY_TABLE. If these ever diverge, every keystroke lands on the
      // wrong key on the host and nothing reports an error.
      // A list of pairs rather than a map: `PhysicalKeyboardKey` has no primitive equality, so it
      // cannot be a const map key.
      const expected = <(PhysicalKeyboardKey, int)>[
        (PhysicalKeyboardKey.keyA, 0x04),
        (PhysicalKeyboardKey.keyZ, 0x1D),
        (PhysicalKeyboardKey.digit1, 0x1E),
        (PhysicalKeyboardKey.digit0, 0x27),
        (PhysicalKeyboardKey.enter, 0x28),
        (PhysicalKeyboardKey.escape, 0x29),
        (PhysicalKeyboardKey.backspace, 0x2A),
        (PhysicalKeyboardKey.tab, 0x2B),
        (PhysicalKeyboardKey.space, 0x2C),
        (PhysicalKeyboardKey.f1, 0x3A),
        (PhysicalKeyboardKey.f12, 0x45),
        (PhysicalKeyboardKey.arrowRight, 0x4F),
        (PhysicalKeyboardKey.arrowLeft, 0x50),
        (PhysicalKeyboardKey.arrowDown, 0x51),
        (PhysicalKeyboardKey.arrowUp, 0x52),
        (PhysicalKeyboardKey.controlLeft, 0xE0),
        (PhysicalKeyboardKey.shiftLeft, 0xE1),
        (PhysicalKeyboardKey.altLeft, 0xE2),
        (PhysicalKeyboardKey.metaLeft, 0xE3),
        (PhysicalKeyboardKey.controlRight, 0xE4),
        (PhysicalKeyboardKey.shiftRight, 0xE5),
        (PhysicalKeyboardKey.altRight, 0xE6),
        (PhysicalKeyboardKey.metaRight, 0xE7),
      ];

      for (final (key, usage) in expected) {
        expect(
          hidUsageFor(key),
          usage,
          reason: '${key.debugName} should be HID usage '
              '0x${usage.toRadixString(16).padLeft(2, '0')}',
        );
      }
    });

    test('keys outside the keyboard page are refused', () {
      // Consumer-page keys (0x000C) carry transport controls. The host accepts only page 0x0007,
      // so sending these would be wasted bandwidth at best.
      expect(hidUsageFor(PhysicalKeyboardKey.mediaPlayPause), isNull); // 0x000c00cd
      expect(hidUsageFor(PhysicalKeyboardKey.browserBack), isNull); // 0x000c0224

      // `fn` is reported on page 0x0000, which is not a HID page at all.
      expect(hidUsageFor(PhysicalKeyboardKey.fn), isNull); // 0x00000012
    });

    test('volume keys are on the keyboard page, not the consumer page', () {
      // This assumption is easy to get backwards, and getting it backwards means volume keys are
      // silently dropped. Flutter reports them as 0x0007007f-0x00070081, so they *are* sent — and
      // crates/rda-input/src/hid.rs was missing them until this test found the gap.
      expect(hidUsageFor(PhysicalKeyboardKey.audioVolumeMute), 0x7F);
      expect(hidUsageFor(PhysicalKeyboardKey.audioVolumeUp), 0x80);
      expect(hidUsageFor(PhysicalKeyboardKey.audioVolumeDown), 0x81);
    });

    test('the usage range matches what the host accepts', () {
      // rda-input validates 0x01..=0xE7 and drops anything else, so anything we send outside that
      // is guaranteed-wasted bandwidth.
      for (final key in <PhysicalKeyboardKey>[
        PhysicalKeyboardKey.keyA,
        PhysicalKeyboardKey.f12,
        PhysicalKeyboardKey.metaRight,
        PhysicalKeyboardKey.numpadEnter,
        PhysicalKeyboardKey.contextMenu,
      ]) {
        final usage = hidUsageFor(key)!;
        expect(usage, greaterThanOrEqualTo(hidUsageMin));
        expect(usage, lessThanOrEqualTo(hidUsageMax));
      }
    });
  });

  group('modifier bitmask', () {
    test('bits match the HID boot-protocol byte order', () {
      // The low 8 bits must be byte-identical to the HID modifier byte, or the host swaps Ctrl and
      // Shift while translating.
      expect(modifiersFor([0xE0]), ModifierBits.leftCtrl);
      expect(modifiersFor([0xE1]), ModifierBits.leftShift);
      expect(modifiersFor([0xE2]), ModifierBits.leftAlt);
      expect(modifiersFor([0xE3]), ModifierBits.leftGui);
      expect(modifiersFor([0xE4]), ModifierBits.rightCtrl);
      expect(modifiersFor([0xE5]), ModifierBits.rightShift);
      expect(modifiersFor([0xE6]), ModifierBits.rightAlt);
      expect(modifiersFor([0xE7]), ModifierBits.rightGui);
    });

    test('combines and ignores non-modifiers', () {
      expect(
        modifiersFor([0xE0, 0xE1, 0x04]),
        ModifierBits.leftCtrl | ModifierBits.leftShift,
      );
      expect(modifiersFor([0x04, 0x05]), 0);
      expect(modifiersFor([]), 0);
    });
  });

  group('coordinate normalisation', () {
    test('spans the full range across the canvas', () {
      const canvas = Size(800, 600);
      expect(normalisePosition(const Offset(0, 0), canvas), (0, 0));
      expect(normalisePosition(const Offset(800, 600), canvas), (65535, 65535));

      final (x, y) = normalisePosition(const Offset(400, 300), canvas);
      expect(x, closeTo(32767, 2));
      expect(y, closeTo(32767, 2));
    });

    test('is independent of canvas size', () {
      // The point of normalising: the same relative position must produce the same wire value
      // whatever the window size or DPI.
      final small = normalisePosition(const Offset(100, 50), const Size(200, 100));
      final large = normalisePosition(const Offset(800, 400), const Size(1600, 800));
      expect(small, large);
    });

    test('clamps rather than escaping the range', () {
      // A position slightly outside the canvas is a rounding artefact far more often than an error,
      // and dropping it would make the cursor stutter at the edges.
      const canvas = Size(800, 600);
      expect(normalisePosition(const Offset(-50, -50), canvas), (0, 0));
      expect(normalisePosition(const Offset(9999, 9999), canvas), (65535, 65535));
    });

    test('a zero-sized canvas does not divide by zero', () {
      expect(normalisePosition(const Offset(10, 10), Size.zero), (0, 0));
    });
  });

  group('mouse buttons', () {
    test('map to the wire ids', () {
      expect(buttonIdFor(kPrimaryMouseButton), 1);
      expect(buttonIdFor(kSecondaryMouseButton), 2);
      expect(buttonIdFor(kMiddleMouseButton), 3);
      expect(buttonIdFor(kBackMouseButton), 4);
      expect(buttonIdFor(kForwardMouseButton), 5);
    });

    test('an empty mask falls back to the primary button', () {
      expect(buttonIdFor(0), 1);
    });
  });

  group('scroll conversion', () {
    test('one detent is 120 wire units', () {
      final (v, _) = scrollDeltaFor(const Offset(0, -logicalPixelsPerDetent));
      expect(v, 120);
    });

    test('the vertical sign is inverted', () {
      // Flutter's positive Y points down the page; the wire's positive vertical means scrolling up.
      // Getting this backwards is invisible in review and immediately obvious in use.
      final (down, _) = scrollDeltaFor(const Offset(0, logicalPixelsPerDetent));
      expect(down, -120);
    });

    test('horizontal is not inverted', () {
      final (_, h) = scrollDeltaFor(const Offset(logicalPixelsPerDetent, 0));
      expect(h, 120);
    });

    test('a huge fling stays inside the wire type', () {
      // delta_v is an i16 on the wire; an unclamped fling would wrap and scroll the wrong way.
      final (v, h) = scrollDeltaFor(const Offset(1e9, -1e9));
      expect(v, lessThanOrEqualTo(32767));
      expect(h, lessThanOrEqualTo(32767));
      expect(v, greaterThanOrEqualTo(-32768));
      expect(h, greaterThanOrEqualTo(-32768));
    });

    test('sub-detent trackpad scrolling survives as a fraction', () {
      // A trackpad emits small continuous deltas; quantising them to whole detents would turn a
      // smooth gesture into jumps.
      final (v, _) = scrollDeltaFor(const Offset(0, -5));
      expect(v, 12);
      expect(v, isNot(0));
    });
  });
}
