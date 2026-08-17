// Raw `dart:ffi` bindings to librda_ffi.
//
// This file mirrors `crates/rda-ffi` one function at a time and contains no logic of its own —
// the same rule the Rust side follows, for the same reason. Anything that looks like a decision
// belongs in `client.dart`.
//
// VERIFIED BY `flutter analyze` under the strict settings in `analysis_options.yaml`, and every
// symbol looked up below has a matching `#[no_mangle]` export confirmed with `nm` against the built
// `cdylib`. What is *not* verified is a running session: building the macOS desktop app needs a full
// Xcode installation, which is not present here.

import 'dart:ffi';
import 'dart:io' show Platform;

/// Opaque handles. Their layout is never inspected from Dart.
final class RdaClientHandle extends Opaque {}

final class RdaInputHandle extends Opaque {}

/// Telemetry snapshot. Field order and types must match `RdaTelemetry` in `client.rs` exactly —
/// a mismatch here is silent memory corruption, not a compile error.
final class RdaTelemetryStruct extends Struct {
  @Uint32()
  external int rttMs;

  @Uint16()
  external int lossPermille;

  @Uint32()
  external int playoutDelayMs;

  @Uint32()
  external int bweBps;

  @Uint64()
  external int framesRendered;

  @Uint64()
  external int framesDropped;

  @Bool()
  external bool relayed;
}

/// One encoded input frame. `len == 0` means the event was coalesced away, which is normal.
final class RdaInputFrameStruct extends Struct {
  external Pointer<Uint8> data;

  @Size()
  external int len;

  @Uint8()
  external int channel;
}

// Status codes, mirroring the constants in `lib.rs`.
const int rdaOk = 0;
const int rdaErrNullArgument = -1;
const int rdaErrInvalidArgument = -2;
const int rdaErrWrongState = -3;
const int rdaErrDecode = -4;
const int rdaErrNoFrame = -5;
const int rdaErrUnsupported = -6;
const int rdaErrBadUtf8 = -7;

/// The ABI version this Dart code was written against.
///
/// Checked at startup against [RdaBindings.abiVersion]. A stale bundled dylib is the single most
/// common cause of baffling crashes during development, and this turns it into a clear message.
const int expectedAbiVersion = 1;

/// Loads and binds the native library.
class RdaBindings {
  RdaBindings(DynamicLibrary library)
      : abiVersion = library
            .lookupFunction<Uint32 Function(), int Function()>('rda_abi_version'),
        initLogging = library
            .lookupFunction<Void Function(), void Function()>('rda_init_logging'),
        lastError = library.lookupFunction<Pointer<Uint8> Function(),
            Pointer<Uint8> Function()>('rda_last_error'),
        clientCreate = library.lookupFunction<Pointer<RdaClientHandle> Function(),
            Pointer<RdaClientHandle> Function()>('rda_client_create'),
        clientDestroy = library.lookupFunction<
            Void Function(Pointer<RdaClientHandle>),
            void Function(Pointer<RdaClientHandle>)>('rda_client_destroy'),
        clientSetPeer = library.lookupFunction<
            Int32 Function(Pointer<RdaClientHandle>, Pointer<Uint8>),
            int Function(Pointer<RdaClientHandle>, Pointer<Uint8>)>(
          'rda_client_set_peer',
        ),
        clientSubmitFrame = library.lookupFunction<
            Int32 Function(Pointer<RdaClientHandle>, Pointer<Uint8>, Size, Uint64,
                Bool, Uint8, Uint64),
            int Function(Pointer<RdaClientHandle>, Pointer<Uint8>, int, int, bool,
                int, int)>('rda_client_submit_frame'),
        clientPollFrame = library.lookupFunction<
            Int32 Function(Pointer<RdaClientHandle>, Uint64),
            int Function(Pointer<RdaClientHandle>, int)>('rda_client_poll_frame'),
        clientFrameWidth = library.lookupFunction<
            Uint32 Function(Pointer<RdaClientHandle>),
            int Function(Pointer<RdaClientHandle>)>('rda_client_frame_width'),
        clientFrameHeight = library.lookupFunction<
            Uint32 Function(Pointer<RdaClientHandle>),
            int Function(Pointer<RdaClientHandle>)>('rda_client_frame_height'),
        clientFrameStride = library.lookupFunction<
            Size Function(Pointer<RdaClientHandle>),
            int Function(Pointer<RdaClientHandle>)>('rda_client_frame_stride'),
        clientFrameLen = library.lookupFunction<
            Size Function(Pointer<RdaClientHandle>),
            int Function(Pointer<RdaClientHandle>)>('rda_client_frame_len'),
        clientFrameData = library.lookupFunction<
            Pointer<Uint8> Function(Pointer<RdaClientHandle>),
            Pointer<Uint8> Function(Pointer<RdaClientHandle>)>(
          'rda_client_frame_data',
        ),
        clientTelemetry = library.lookupFunction<
            Int32 Function(Pointer<RdaClientHandle>, Pointer<RdaTelemetryStruct>),
            int Function(Pointer<RdaClientHandle>, Pointer<RdaTelemetryStruct>)>(
          'rda_client_telemetry',
        ),
        clientUpdateLink = library.lookupFunction<
            Int32 Function(
                Pointer<RdaClientHandle>, Uint32, Uint16, Uint32, Bool, Uint64),
            int Function(Pointer<RdaClientHandle>, int, int, int, bool, int)>(
          'rda_client_update_link',
        ),
        clientReset = library.lookupFunction<
            Int32 Function(Pointer<RdaClientHandle>),
            int Function(Pointer<RdaClientHandle>)>('rda_client_reset'),
        clientIsHardware = library.lookupFunction<
            Bool Function(Pointer<RdaClientHandle>),
            bool Function(Pointer<RdaClientHandle>)>('rda_client_is_hardware'),
        clientTakeKeyframeRequest = library.lookupFunction<
            Bool Function(Pointer<RdaClientHandle>),
            bool Function(Pointer<RdaClientHandle>)>(
          'rda_client_take_keyframe_request',
        ),
        inputCreate = library.lookupFunction<
            Pointer<RdaInputHandle> Function(Uint64),
            Pointer<RdaInputHandle> Function(int)>('rda_input_create'),
        inputDestroy = library.lookupFunction<
            Void Function(Pointer<RdaInputHandle>),
            void Function(Pointer<RdaInputHandle>)>('rda_input_destroy'),
        inputPointerMove = library.lookupFunction<
            Int32 Function(Pointer<RdaInputHandle>, Uint8, Uint16, Uint16, Uint16,
                Uint64, Pointer<RdaInputFrameStruct>),
            int Function(Pointer<RdaInputHandle>, int, int, int, int, int,
                Pointer<RdaInputFrameStruct>)>('rda_input_pointer_move'),
        inputPointerButton = library.lookupFunction<
            Int32 Function(Pointer<RdaInputHandle>, Uint8, Bool, Uint8, Uint16,
                Uint16, Uint16, Uint8, Uint64, Pointer<RdaInputFrameStruct>),
            int Function(Pointer<RdaInputHandle>, int, bool, int, int, int, int,
                int, int, Pointer<RdaInputFrameStruct>)>(
          'rda_input_pointer_button',
        ),
        inputScroll = library.lookupFunction<
            Int32 Function(Pointer<RdaInputHandle>, Int16, Int16, Uint8, Uint16,
                Uint64, Pointer<RdaInputFrameStruct>),
            int Function(Pointer<RdaInputHandle>, int, int, int, int, int,
                Pointer<RdaInputFrameStruct>)>('rda_input_scroll'),
        inputKey = library.lookupFunction<
            Int32 Function(Pointer<RdaInputHandle>, Uint16, Bool, Uint16, Uint64,
                Pointer<RdaInputFrameStruct>),
            int Function(Pointer<RdaInputHandle>, int, bool, int, int,
                Pointer<RdaInputFrameStruct>)>('rda_input_key'),
        inputKeyStateSync = library.lookupFunction<
            Int32 Function(Pointer<RdaInputHandle>, Pointer<Uint16>, Size, Uint16,
                Uint64, Pointer<RdaInputFrameStruct>),
            int Function(Pointer<RdaInputHandle>, Pointer<Uint16>, int, int, int,
                Pointer<RdaInputFrameStruct>)>('rda_input_key_state_sync');

  final int Function() abiVersion;
  final void Function() initLogging;
  final Pointer<Uint8> Function() lastError;

  final Pointer<RdaClientHandle> Function() clientCreate;
  final void Function(Pointer<RdaClientHandle>) clientDestroy;
  final int Function(Pointer<RdaClientHandle>, Pointer<Uint8>) clientSetPeer;
  final int Function(
      Pointer<RdaClientHandle>, Pointer<Uint8>, int, int, bool, int, int) clientSubmitFrame;
  final int Function(Pointer<RdaClientHandle>, int) clientPollFrame;
  final int Function(Pointer<RdaClientHandle>) clientFrameWidth;
  final int Function(Pointer<RdaClientHandle>) clientFrameHeight;
  final int Function(Pointer<RdaClientHandle>) clientFrameStride;
  final int Function(Pointer<RdaClientHandle>) clientFrameLen;
  final Pointer<Uint8> Function(Pointer<RdaClientHandle>) clientFrameData;
  final int Function(Pointer<RdaClientHandle>, Pointer<RdaTelemetryStruct>) clientTelemetry;
  final int Function(Pointer<RdaClientHandle>, int, int, int, bool, int) clientUpdateLink;
  final int Function(Pointer<RdaClientHandle>) clientReset;
  final bool Function(Pointer<RdaClientHandle>) clientIsHardware;
  final bool Function(Pointer<RdaClientHandle>) clientTakeKeyframeRequest;

  final Pointer<RdaInputHandle> Function(int) inputCreate;
  final void Function(Pointer<RdaInputHandle>) inputDestroy;
  final int Function(Pointer<RdaInputHandle>, int, int, int, int, int,
      Pointer<RdaInputFrameStruct>) inputPointerMove;
  final int Function(Pointer<RdaInputHandle>, int, bool, int, int, int, int, int,
      int, Pointer<RdaInputFrameStruct>) inputPointerButton;
  final int Function(Pointer<RdaInputHandle>, int, int, int, int, int,
      Pointer<RdaInputFrameStruct>) inputScroll;
  final int Function(Pointer<RdaInputHandle>, int, bool, int, int,
      Pointer<RdaInputFrameStruct>) inputKey;
  final int Function(Pointer<RdaInputHandle>, Pointer<Uint16>, int, int, int,
      Pointer<RdaInputFrameStruct>) inputKeyStateSync;

  /// Opens the platform's dynamic library.
  ///
  /// On Android the library is bundled into the APK and looked up by name; everywhere else it sits
  /// beside the executable. `DynamicLibrary.process()` is deliberately not used on iOS/macOS here
  /// because a statically linked build would need a different lookup entirely, and guessing wrong
  /// produces a confusing "symbol not found" rather than a clear "library missing".
  static DynamicLibrary open() {
    if (Platform.isMacOS) return DynamicLibrary.open('librda_ffi.dylib');
    if (Platform.isIOS) return DynamicLibrary.process();
    if (Platform.isAndroid) return DynamicLibrary.open('librda_ffi.so');
    if (Platform.isLinux) return DynamicLibrary.open('librda_ffi.so');
    if (Platform.isWindows) return DynamicLibrary.open('rda_ffi.dll');
    throw UnsupportedError('no rda_ffi build for ${Platform.operatingSystem}');
  }
}
