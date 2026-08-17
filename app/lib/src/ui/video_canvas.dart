// The video canvas.
//
// The requirement is "zero UI-thread blocking", and the way that is achieved matters:
//
// **Decoding to a `ui.Image` happens off the UI thread.** `ui.ImageDescriptor.raw` +
// `instantiateCodec` hands the pixel upload to the engine's raster/IO threads. The obvious
// alternative — building an `Image` synchronously, or painting pixels in a `CustomPainter` — does
// the work on the UI thread and drops frames the moment the picture gets large.
//
// **The render loop is a `Ticker`, not a `Timer`.** A ticker fires in step with the display's
// vsync, so a frame is decoded exactly when one can actually be shown. A timer at 60 Hz drifts
// against the refresh rate and produces periodic judder that looks like a network problem.
//
// **Only one decode is in flight at a time.** Without that guard a slow frame lets work pile up
// and the app falls further behind with every tick — the failure mode is a viewer that gets
// steadily laggier and never recovers.
//
// Analyzed but not run — see the note in `bindings.dart`.

import 'dart:async';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/scheduler.dart';

import '../ffi/client.dart';

/// Displays the remote screen.
class VideoCanvas extends StatefulWidget {
  const VideoCanvas({
    super.key,
    required this.client,
    this.onKeyframeRequested,
    this.onStalled,
  });

  final RdaClient client;

  /// Called when the decoder wants the sender to emit a keyframe.
  final VoidCallback? onKeyframeRequested;

  /// Called when no frame has arrived for a while, so the UI can say so.
  final VoidCallback? onStalled;

  @override
  State<VideoCanvas> createState() => _VideoCanvasState();
}

class _VideoCanvasState extends State<VideoCanvas>
    with SingleTickerProviderStateMixin {
  Ticker? _ticker;
  ui.Image? _image;

  /// Guards against overlapping decodes. Without it a slow frame lets work pile up and the viewer
  /// falls further behind on every tick.
  bool _decoding = false;

  final Stopwatch _clock = Stopwatch()..start();
  DateTime _lastFrameAt = DateTime.now();

  @override
  void initState() {
    super.initState();
    _ticker = createTicker(_onTick)..start();
  }

  @override
  void dispose() {
    _ticker?.dispose();
    _image?.dispose();
    super.dispose();
  }

  Future<void> _onTick(Duration _) async {
    if (_decoding || !mounted) return;

    final frame = widget.client.pollFrame(_clock.elapsedMilliseconds);
    if (frame == null) {
      // Half a second with nothing to show means the stream has stalled, which is worth saying
      // rather than leaving a frozen picture with no explanation.
      if (DateTime.now().difference(_lastFrameAt).inMilliseconds > 500) {
        widget.onStalled?.call();
        _lastFrameAt = DateTime.now();
      }
      if (widget.client.takeKeyframeRequest()) {
        widget.onKeyframeRequested?.call();
      }
      return;
    }

    _decoding = true;
    try {
      final image = await _toImage(frame);
      if (!mounted) {
        image.dispose();
        return;
      }
      setState(() {
        // Dispose the outgoing image explicitly. Leaving it to the GC means holding several
        // full-resolution textures at 60 fps, which is a visible memory climb.
        _image?.dispose();
        _image = image;
      });
      _lastFrameAt = DateTime.now();
    } finally {
      _decoding = false;
    }
  }

  /// Uploads BGRA pixels to a GPU-backed image without touching the UI thread.
  Future<ui.Image> _toImage(VideoFrame frame) async {
    final buffer = await ui.ImmutableBuffer.fromUint8List(frame.pixels);
    final descriptor = ui.ImageDescriptor.raw(
      buffer,
      width: frame.width,
      height: frame.height,
      // The decoder hands back BGRA. Declaring RGBA here would swap red and blue — a mistake that
      // looks like a colour-space bug and is not one.
      pixelFormat: ui.PixelFormat.bgra8888,
      rowBytes: frame.stride,
    );
    final codec = await descriptor.instantiateCodec();
    final image = (await codec.getNextFrame()).image;
    codec.dispose();
    descriptor.dispose();
    buffer.dispose();
    return image;
  }

  @override
  Widget build(BuildContext context) {
    final image = _image;
    if (image == null) {
      return const ColoredBox(
        color: Color(0xFF101014),
        child: Center(
          child: Text(
            'Waiting for the first frame…',
            style: TextStyle(color: Color(0xFF8A8A94)),
          ),
        ),
      );
    }

    return ColoredBox(
      color: const Color(0xFF000000),
      child: FittedBox(
        fit: BoxFit.contain,
        child: SizedBox(
          width: image.width.toDouble(),
          height: image.height.toDouble(),
          child: RawImage(
            image: image,
            // Nearest-neighbour would alias text badly on any non-integer scale, and text is most
            // of what a remote desktop shows.
            filterQuality: FilterQuality.medium,
          ),
        ),
      ),
    );
  }
}
