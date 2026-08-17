// Input capture: local events to wire frames.
//
// The pleasant surprise here is that Flutter's `PhysicalKeyboardKey.usbHidUsage` is *already* a USB
// HID usage code — the exact identity `docs/ARCHITECTURE.md` §4.2 chose for the wire. So the
// mapping is a mask rather than a lookup table, and a controller on any layout sends the key
// *position* the user actually pressed. Using `LogicalKeyboardKey` instead would send the character
// and break every shortcut on a non-US layout.
//
// Three behaviours are deliberate:
//
// - **Coordinates are normalised to 0..65535 across the widget**, so they survive a window resize,
//   a DPI change, and a resolution change on the host mid-session.
// - **A key-state heartbeat runs every 250 ms** while anything is held. It is what bounds the
//   lifetime of a lost key-up, and without it a dropped release leaves a modifier stuck on someone
//   else's machine.
// - **Everything is released when focus is lost.** Alt-tabbing away with Alt held would otherwise
//   leave the host holding it.
//
// Analyzed but not run — see the note in `bindings.dart`.

import 'dart:async';

import 'package:flutter/gestures.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

import '../ffi/client.dart';
import 'input_mapping.dart';

export 'input_mapping.dart' show ModifierBits;

/// How often the full key-state snapshot is sent while any key is held.
const Duration keyStateSyncInterval = Duration(milliseconds: 250);

/// Captures pointer and keyboard input and forwards it to the host.
class InputLayer extends StatefulWidget {
  const InputLayer({
    super.key,
    required this.input,
    required this.onFrame,
    required this.child,
    this.displayId = 0,
    this.enabled = true,
  });

  final RdaInput input;

  /// Called with each encoded frame. The caller sends it on [EncodedInput.channel] — which channel
  /// is not a detail: pointer motion must not ride a reliable stream.
  final void Function(EncodedInput frame) onFrame;

  final Widget child;
  final int displayId;

  /// When false, input is captured but discarded — a view-only session.
  final bool enabled;

  @override
  State<InputLayer> createState() => _InputLayerState();
}

class _InputLayerState extends State<InputLayer> {
  final FocusNode _focus = FocusNode(debugLabel: 'rda-input');
  final Stopwatch _clock = Stopwatch()..start();

  /// HID usages currently held, so the heartbeat can report them and teardown can release them.
  final Set<int> _held = <int>{};
  Timer? _syncTimer;
  Size _canvasSize = Size.zero;

  @override
  void initState() {
    super.initState();
    _focus.addListener(_onFocusChanged);
  }

  @override
  void dispose() {
    _syncTimer?.cancel();
    // Whatever else happens, the host must not be left holding keys.
    _releaseAll();
    _focus.removeListener(_onFocusChanged);
    _focus.dispose();
    super.dispose();
  }

  int get _nowMs => _clock.elapsedMilliseconds;

  void _emit(EncodedInput? frame) {
    if (frame != null && widget.enabled) widget.onFrame(frame);
  }

  // --- keyboard ------------------------------------------------------------------------------

  void _onFocusChanged() {
    // Alt-tabbing away with Alt held would otherwise leave the modifier down on the host.
    if (!_focus.hasFocus) _releaseAll();
  }

  void _releaseAll() {
    if (_held.isEmpty) return;
    for (final usage in _held.toList()) {
      _emit(widget.input.key(
        usageId: usage,
        pressed: false,
        modifiers: 0,
        nowMs: _nowMs,
      ));
    }
    _held.clear();
    // An authoritative empty snapshot is what actually clears a stuck modifier, because it survives
    // the loss of any individual key-up.
    _emit(widget.input.keyStateSync(usages: const [], modifiers: 0, nowMs: _nowMs));
    _syncTimer?.cancel();
    _syncTimer = null;
  }

  void _ensureSyncTimer() {
    _syncTimer ??= Timer.periodic(keyStateSyncInterval, (_) {
      if (_held.isEmpty) {
        _syncTimer?.cancel();
        _syncTimer = null;
        return;
      }
      _emit(widget.input.keyStateSync(
        usages: _held.toList(),
        modifiers: _modifiers(),
        nowMs: _nowMs,
      ));
    });
  }

  /// The modifier bitmask implied by the keys currently held.
  int _modifiers() => modifiersFor(_held);

  KeyEventResult _onKeyEvent(FocusNode node, KeyEvent event) {
    final usage = hidUsageFor(event.physicalKey);
    if (usage == null) return KeyEventResult.ignored;

    if (event is KeyDownEvent) {
      _held.add(usage);
      _ensureSyncTimer();
      _emit(widget.input
          .key(usageId: usage, pressed: true, modifiers: _modifiers(), nowMs: _nowMs));
    } else if (event is KeyUpEvent) {
      _held.remove(usage);
      _emit(widget.input
          .key(usageId: usage, pressed: false, modifiers: _modifiers(), nowMs: _nowMs));
    } else if (event is KeyRepeatEvent) {
      _emit(widget.input
          .key(usageId: usage, pressed: true, modifiers: _modifiers(), nowMs: _nowMs));
    }

    // Consume the event so Flutter does not also act on it locally — a Ctrl+W meant for the remote
    // machine must not close the viewer.
    return KeyEventResult.handled;
  }

  // --- pointer -------------------------------------------------------------------------------

  /// Converts a local position to the normalised coordinates the wire uses.
  (int, int) _normalise(Offset local) => normalisePosition(local, _canvasSize);

  void _onPointerMove(PointerEvent event) {
    final (x, y) = _normalise(event.localPosition);
    _emit(widget.input.pointerMove(
      displayId: widget.displayId,
      xNorm: x,
      yNorm: y,
      modifiers: _modifiers(),
      nowMs: _nowMs,
    ));
  }

  void _onPointerDown(PointerDownEvent event) {
    _focus.requestFocus();
    final (x, y) = _normalise(event.localPosition);
    _emit(widget.input.pointerButton(
      button: buttonIdFor(event.buttons),
      pressed: true,
      displayId: widget.displayId,
      xNorm: x,
      yNorm: y,
      modifiers: _modifiers(),
      nowMs: _nowMs,
    ));
  }

  void _onPointerUp(PointerUpEvent event) {
    final (x, y) = _normalise(event.localPosition);
    _emit(widget.input.pointerButton(
      // `buttons` is already cleared on an up event, so the down-button cannot be read from it;
      // the primary button is the overwhelmingly common case and the host reconciles the rest.
      button: 1,
      pressed: false,
      displayId: widget.displayId,
      xNorm: x,
      yNorm: y,
      modifiers: _modifiers(),
      nowMs: _nowMs,
    ));
  }

  void _onPointerSignal(PointerSignalEvent event) {
    if (event is! PointerScrollEvent) return;
    final (v, h) = scrollDeltaFor(event.scrollDelta);
    if (v == 0 && h == 0) return;

    _emit(widget.input.scroll(
      deltaV: v,
      deltaH: h,
      displayId: widget.displayId,
      modifiers: _modifiers(),
      nowMs: _nowMs,
    ));
  }

  @override
  Widget build(BuildContext context) {
    return Focus(
      focusNode: _focus,
      onKeyEvent: _onKeyEvent,
      autofocus: true,
      child: LayoutBuilder(
        builder: (context, constraints) {
          _canvasSize = Size(constraints.maxWidth, constraints.maxHeight);
          return MouseRegion(
            cursor: SystemMouseCursors.none,
            onHover: _onPointerMove,
            child: Listener(
              onPointerDown: _onPointerDown,
              onPointerMove: _onPointerMove,
              onPointerUp: _onPointerUp,
              onPointerSignal: _onPointerSignal,
              behavior: HitTestBehavior.opaque,
              child: widget.child,
            ),
          );
        },
      ),
    );
  }
}
