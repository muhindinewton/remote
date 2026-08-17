// A safe Dart wrapper over the raw bindings.
//
// Two responsibilities: keep the unsafe pointer discipline in one place, and honour the borrow
// contract the Rust side declares. `rda_client_frame_data` hands out a pointer that is valid only
// until the next `poll_frame` on the same client — so [RdaClient.pollFrame] copies out of it
// immediately, and nothing else in the app ever sees a raw pointer.
//
// Analyzed but not run — see the note in `bindings.dart`.

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.dart';

/// A decoded frame, copied out of native memory.
class VideoFrame {
  const VideoFrame({
    required this.pixels,
    required this.width,
    required this.height,
    required this.stride,
  });

  /// BGRA8 pixels.
  final Uint8List pixels;
  final int width;
  final int height;

  /// Bytes per row. Frequently larger than `width * 4`, because decoders align rows —
  /// assuming otherwise shears the image diagonally.
  final int stride;

  /// Whether the decoder padded each row.
  bool get isPadded => stride != width * 4;
}

/// Live link statistics for the status bar.
class LinkTelemetry {
  const LinkTelemetry({
    required this.rttMs,
    required this.lossPermille,
    required this.playoutDelayMs,
    required this.bweBps,
    required this.framesRendered,
    required this.framesDropped,
    required this.relayed,
  });

  const LinkTelemetry.empty()
      : rttMs = 0,
        lossPermille = 0,
        playoutDelayMs = 0,
        bweBps = 0,
        framesRendered = 0,
        framesDropped = 0,
        relayed = false;

  final int rttMs;
  final int lossPermille;
  final int playoutDelayMs;
  final int bweBps;
  final int framesRendered;
  final int framesDropped;
  final bool relayed;

  double get lossPercent => lossPermille / 10.0;
  double get bweMbps => bweBps / 1000000.0;
}

/// Thrown when the native library reports a failure.
class RdaException implements Exception {
  RdaException(this.status, this.message);

  final int status;
  final String message;

  @override
  String toString() => 'RdaException($status): $message';
}

/// The client engine: decoding, playout and telemetry.
///
/// Must be used from a single isolate — the hardware decoder is thread-affine.
class RdaClient {
  RdaClient._(this._bindings, this._handle)
      : _telemetryOut = calloc<RdaTelemetryStruct>();

  final RdaBindings _bindings;
  Pointer<RdaClientHandle> _handle;
  final Pointer<RdaTelemetryStruct> _telemetryOut;
  bool _disposed = false;

  /// Loads the library and creates a client.
  ///
  /// Throws if the bundled library is a different ABI version — the most common development
  /// failure, and one that otherwise shows up as an inexplicable crash much later.
  factory RdaClient.open() {
    final bindings = RdaBindings(RdaBindings.open());
    final abi = bindings.abiVersion();
    if (abi != expectedAbiVersion) {
      throw RdaException(
        rdaErrUnsupported,
        'native library is ABI v$abi, this build expects v$expectedAbiVersion; '
        'the bundled librda_ffi is stale',
      );
    }
    bindings.initLogging();

    final handle = bindings.clientCreate();
    if (handle == nullptr) {
      throw RdaException(rdaErrUnsupported, _readError(bindings));
    }
    return RdaClient._(bindings, handle);
  }

  static String _readError(RdaBindings bindings) {
    final ptr = bindings.lastError();
    if (ptr == nullptr) return 'unknown error';
    return ptr.cast<Utf8>().toDartString();
  }

  void _check(int status) {
    if (status != rdaOk) {
      throw RdaException(status, _readError(_bindings));
    }
  }

  void _requireLive() {
    if (_disposed) {
      throw StateError('RdaClient used after dispose()');
    }
  }

  /// Whether decoding runs on dedicated hardware.
  bool get isHardware {
    _requireLive();
    return _bindings.clientIsHardware(_handle);
  }

  /// Sets the peer device this session is connected to.
  void setPeer(String deviceId) {
    _requireLive();
    final native = deviceId.toNativeUtf8();
    try {
      _check(_bindings.clientSetPeer(_handle, native.cast<Uint8>()));
    } finally {
      calloc.free(native);
    }
  }

  /// Hands a compressed frame from the transport to the jitter buffer.
  void submitFrame(
    Uint8List data, {
    required int ptsUs,
    required bool isKeyframe,
    int temporalLayer = 0,
    required int nowMs,
  }) {
    _requireLive();
    if (data.isEmpty) return;

    final buffer = calloc<Uint8>(data.length);
    try {
      buffer.asTypedList(data.length).setAll(0, data);
      _check(_bindings.clientSubmitFrame(
        _handle,
        buffer,
        data.length,
        ptsUs,
        isKeyframe,
        temporalLayer,
        nowMs,
      ));
    } finally {
      calloc.free(buffer);
    }
  }

  /// Advances playout and returns a frame if one became due.
  ///
  /// Returns null when nothing is ready, which at 60 fps against a 30 fps stream is most ticks and
  /// is not an error. The pixels are copied out here because the native pointer is only valid until
  /// the next call — everything above this line gets a plain [Uint8List].
  VideoFrame? pollFrame(int nowMs) {
    _requireLive();
    final status = _bindings.clientPollFrame(_handle, nowMs);
    if (status == rdaErrNoFrame) return null;
    if (status != rdaOk) {
      // A decode failure is recoverable: the render loop keeps the previous picture and asks for a
      // keyframe. Throwing here would tear down the session over a single corrupt frame.
      return null;
    }

    final data = _bindings.clientFrameData(_handle);
    if (data == nullptr) return null;

    final len = _bindings.clientFrameLen(_handle);
    if (len == 0) return null;

    return VideoFrame(
      // `asTypedList` is a view into native memory; the copy is what makes it safe to keep.
      pixels: Uint8List.fromList(data.asTypedList(len)),
      width: _bindings.clientFrameWidth(_handle),
      height: _bindings.clientFrameHeight(_handle),
      stride: _bindings.clientFrameStride(_handle),
    );
  }

  /// Whether the decoder wants a keyframe. Reading clears the flag.
  bool takeKeyframeRequest() {
    _requireLive();
    return _bindings.clientTakeKeyframeRequest(_handle);
  }

  /// Feeds transport statistics in so the status bar reflects the real link.
  void updateLink({
    required int rttMs,
    required int lossPermille,
    required int bweBps,
    required bool relayed,
    required int nowMs,
  }) {
    _requireLive();
    _check(_bindings.clientUpdateLink(
      _handle,
      rttMs,
      lossPermille.clamp(0, 1000),
      bweBps,
      relayed,
      nowMs,
    ));
  }

  /// Reads current telemetry.
  LinkTelemetry telemetry() {
    _requireLive();
    _check(_bindings.clientTelemetry(_handle, _telemetryOut));
    final t = _telemetryOut.ref;
    return LinkTelemetry(
      rttMs: t.rttMs,
      lossPermille: t.lossPermille,
      playoutDelayMs: t.playoutDelayMs,
      bweBps: t.bweBps,
      framesRendered: t.framesRendered,
      framesDropped: t.framesDropped,
      relayed: t.relayed,
    );
  }

  /// Clears decoder and buffer state after an unrecoverable loss.
  void reset() {
    _requireLive();
    _check(_bindings.clientReset(_handle));
  }

  /// Releases native resources. Safe to call more than once.
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    _bindings.clientDestroy(_handle);
    _handle = nullptr;
    calloc.free(_telemetryOut);
  }
}

/// Encodes input events into wire frames.
///
/// Coalescing happens in Rust, so this stays a thin pass-through. That matters: `rda-proto` is the
/// single source of truth for the wire format, and a second encoder written in Dart would drift
/// from it without anyone noticing.
class RdaInput {
  RdaInput._(this._bindings, this._handle) : _out = calloc<RdaInputFrameStruct>();

  final RdaBindings _bindings;
  Pointer<RdaInputHandle> _handle;
  final Pointer<RdaInputFrameStruct> _out;
  bool _disposed = false;

  /// Creates an encoder whose timestamps are relative to `epochMs`.
  factory RdaInput.create(RdaBindings bindings, int epochMs) {
    return RdaInput._(bindings, bindings.inputCreate(epochMs));
  }

  /// Reads whatever the last call produced, or null if it was coalesced away.
  EncodedInput? _take() {
    final frame = _out.ref;
    if (frame.len == 0 || frame.data == nullptr) return null;
    return EncodedInput(
      // Copied immediately: the native buffer is reused by the next call.
      bytes: Uint8List.fromList(frame.data.asTypedList(frame.len)),
      channel: frame.channel == 2 ? InputChannel.pointer : InputChannel.keys,
    );
  }

  /// Encodes pointer motion. Returns null when the event was coalesced.
  EncodedInput? pointerMove({
    required int displayId,
    required int xNorm,
    required int yNorm,
    required int modifiers,
    required int nowMs,
  }) {
    if (_disposed) return null;
    final status = _bindings.inputPointerMove(
        _handle, displayId, xNorm, yNorm, modifiers, nowMs, _out);
    return status == rdaOk ? _take() : null;
  }

  /// Encodes a button press or release.
  EncodedInput? pointerButton({
    required int button,
    required bool pressed,
    required int displayId,
    required int xNorm,
    required int yNorm,
    required int modifiers,
    int clickCount = 1,
    required int nowMs,
  }) {
    if (_disposed) return null;
    final status = _bindings.inputPointerButton(_handle, button, pressed,
        displayId, xNorm, yNorm, modifiers, clickCount, nowMs, _out);
    return status == rdaOk ? _take() : null;
  }

  /// Encodes a scroll event, in units of 1/120 of a detent.
  EncodedInput? scroll({
    required int deltaV,
    required int deltaH,
    required int displayId,
    required int modifiers,
    required int nowMs,
  }) {
    if (_disposed) return null;
    final status = _bindings.inputScroll(
        _handle, deltaV, deltaH, displayId, modifiers, nowMs, _out);
    return status == rdaOk ? _take() : null;
  }

  /// Encodes a key event from a HID usage id.
  EncodedInput? key({
    required int usageId,
    required bool pressed,
    required int modifiers,
    required int nowMs,
  }) {
    if (_disposed) return null;
    final status =
        _bindings.inputKey(_handle, usageId, pressed, modifiers, nowMs, _out);
    return status == rdaOk ? _take() : null;
  }

  /// Encodes the periodic full key-state snapshot.
  EncodedInput? keyStateSync({
    required List<int> usages,
    required int modifiers,
    required int nowMs,
  }) {
    if (_disposed) return null;
    final list = calloc<Uint16>(usages.isEmpty ? 1 : usages.length);
    try {
      for (var i = 0; i < usages.length; i++) {
        list[i] = usages[i];
      }
      final status = _bindings.inputKeyStateSync(
          _handle, list, usages.length, modifiers, nowMs, _out);
      return status == rdaOk ? _take() : null;
    } finally {
      calloc.free(list);
    }
  }

  /// Releases native resources. Safe to call more than once.
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    _bindings.inputDestroy(_handle);
    _handle = nullptr;
    calloc.free(_out);
  }
}

/// Which DataChannel an encoded input frame must be sent on.
///
/// Not cosmetic: pointer motion rides an unreliable channel so a lost packet cannot freeze the
/// cursor for a second, while keys ride a reliable one so a lost key-up cannot leave a modifier
/// stuck. Sending on the wrong one produces exactly those bugs.
enum InputChannel {
  /// `input-k`, reliable and ordered.
  keys,

  /// `input-p`, unreliable and unordered.
  pointer,
}

/// One encoded input frame, ready for the transport.
class EncodedInput {
  const EncodedInput({required this.bytes, required this.channel});

  final Uint8List bytes;
  final InputChannel channel;
}
