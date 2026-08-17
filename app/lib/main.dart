// The viewer application.
//
// Deliberately thin: connection UI, a canvas, a status bar. Every decision that matters — decoding,
// playout timing, input encoding, rate adaptation — lives in Rust, where it is tested. A Flutter
// front end that starts making protocol decisions is a Flutter front end that will disagree with
// the host about them.
//
// Analyzed but not run — see the note in `src/ffi/bindings.dart`.

import 'dart:async';

import 'package:flutter/material.dart';

import 'src/ffi/bindings.dart';
import 'src/ffi/client.dart';
import 'src/ui/input_layer.dart';
import 'src/ui/video_canvas.dart';

void main() {
  runApp(const RdaViewerApp());
}

class RdaViewerApp extends StatelessWidget {
  const RdaViewerApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Remote Desktop',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark(useMaterial3: true),
      home: const ConnectScreen(),
    );
  }
}

/// Where a session starts: enter the host's device id.
class ConnectScreen extends StatefulWidget {
  const ConnectScreen({super.key});

  @override
  State<ConnectScreen> createState() => _ConnectScreenState();
}

class _ConnectScreenState extends State<ConnectScreen> {
  final TextEditingController _deviceId = TextEditingController();
  String? _error;

  @override
  void dispose() {
    _deviceId.dispose();
    super.dispose();
  }

  void _connect() {
    final id = _deviceId.text.trim();
    if (id.isEmpty) {
      setState(() => _error = 'Enter the device ID shown on the remote machine.');
      return;
    }
    Navigator.of(context).push(
      MaterialPageRoute<void>(builder: (_) => SessionScreen(deviceId: id)),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 380),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text(
                'Connect to a remote machine',
                style: TextStyle(fontSize: 22, fontWeight: FontWeight.w600),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 24),
              TextField(
                controller: _deviceId,
                autofocus: true,
                textCapitalization: TextCapitalization.characters,
                decoration: InputDecoration(
                  labelText: 'Device ID',
                  hintText: 'K7M2-9QXR-4TVB',
                  border: const OutlineInputBorder(),
                  errorText: _error,
                ),
                onSubmitted: (_) => _connect(),
              ),
              const SizedBox(height: 16),
              FilledButton(onPressed: _connect, child: const Text('Connect')),
              const SizedBox(height: 24),
              // The plain-language consent framing from ARCHITECTURE.md §5.2 belongs on the *host*
              // side, but saying plainly what a session does is worth doing on both ends.
              Text(
                'The remote machine must accept the connection and will show a PIN.',
                style: Theme.of(context).textTheme.bodySmall,
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

/// The live session: video, input, telemetry.
class SessionScreen extends StatefulWidget {
  const SessionScreen({super.key, required this.deviceId});

  final String deviceId;

  @override
  State<SessionScreen> createState() => _SessionScreenState();
}

class _SessionScreenState extends State<SessionScreen> {
  RdaClient? _client;
  RdaInput? _input;
  String? _fatalError;
  LinkTelemetry _telemetry = const LinkTelemetry.empty();
  bool _stalled = false;
  Timer? _telemetryTimer;

  @override
  void initState() {
    super.initState();
    _start();
  }

  /// Polls telemetry once a second for the status bar.
  ///
  /// Deliberately not per frame: the numbers are for a human reading a status line, and a `setState`
  /// at 60 Hz would rebuild the widget tree far more often than anyone can read it.
  void _startTelemetryPolling() {
    _telemetryTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      final client = _client;
      if (client == null || !mounted) return;
      try {
        final snapshot = client.telemetry();
        // Compare against the previous reading *before* replacing it: a frame arriving since the
        // last poll means the stream recovered, so the stall warning clears rather than staying
        // stuck on after a transient hiccup.
        final recovered = snapshot.framesRendered > _telemetry.framesRendered;
        setState(() {
          _telemetry = snapshot;
          if (recovered) {
            _stalled = false;
          }
        });
      } on RdaException {
        // A telemetry read failing is not worth tearing the session down over; the status bar
        // simply stops updating.
      }
    });
  }

  void _start() {
    try {
      final client = RdaClient.open();
      client.setPeer(widget.deviceId);
      final input = RdaInput.create(RdaBindings(RdaBindings.open()), 0);
      setState(() {
        _client = client;
        _input = input;
      });
      _startTelemetryPolling();
    } on Object catch (e) {
      // A missing hardware decoder or a stale dylib both land here, and both deserve a real
      // message rather than a blank screen.
      setState(() => _fatalError = e.toString());
    }
  }

  @override
  void dispose() {
    _telemetryTimer?.cancel();
    _input?.dispose();
    _client?.dispose();
    super.dispose();
  }

  /// Sends an encoded input frame on the channel it names.
  ///
  /// Wiring this to `rda-transport` is the remaining step: the transport is built and tested
  /// (Phase 2), but the client half of the session state machine that owns a live peer connection
  /// is not yet assembled here.
  void _sendInput(EncodedInput frame) {
    // ignore: avoid_print
    assert(() {
      // Kept as an assert so it costs nothing in release, but makes the channel split visible
      // while the transport is being wired up.
      return true;
    }());
  }

  void _requestKeyframe() {
    // Likewise routed through the transport once the client session is assembled. The host answers
    // this with a cheap LTR recovery where it can, not necessarily a full keyframe.
  }

  @override
  Widget build(BuildContext context) {
    final error = _fatalError;
    if (error != null) {
      return Scaffold(
        appBar: AppBar(title: Text(widget.deviceId)),
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.error_outline, size: 40),
                const SizedBox(height: 12),
                const Text('Could not start the session'),
                const SizedBox(height: 8),
                Text(error, textAlign: TextAlign.center),
              ],
            ),
          ),
        ),
      );
    }

    final client = _client;
    final input = _input;
    if (client == null || input == null) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }

    return Scaffold(
      body: Column(
        children: [
          Expanded(
            child: InputLayer(
              input: input,
              onFrame: _sendInput,
              child: VideoCanvas(
                client: client,
                onKeyframeRequested: _requestKeyframe,
                onStalled: () => setState(() => _stalled = true),
              ),
            ),
          ),
          TelemetryBar(
            deviceId: widget.deviceId,
            telemetry: _telemetry,
            hardware: client.isHardware,
            stalled: _stalled,
          ),
        ],
      ),
    );
  }
}

/// The status bar.
///
/// Shows the numbers that explain what a user is feeling. On a 220 ms path "it feels slow" is
/// usually the truth rather than a fault, and showing the RTT is the difference between a user who
/// understands that and one who files a bug.
class TelemetryBar extends StatelessWidget {
  const TelemetryBar({
    super.key,
    required this.deviceId,
    required this.telemetry,
    required this.hardware,
    this.stalled = false,
  });

  final String deviceId;
  final LinkTelemetry telemetry;
  final bool hardware;
  final bool stalled;

  @override
  Widget build(BuildContext context) {
    final style = Theme.of(context).textTheme.bodySmall;
    return Container(
      height: 28,
      color: stalled ? const Color(0xFF4A1F1F) : const Color(0xFF16161C),
      padding: const EdgeInsets.symmetric(horizontal: 12),
      child: Row(
        children: [
          Text(deviceId, style: style),
          const Spacer(),
          if (stalled) Text('stream stalled', style: style),
          if (stalled) const SizedBox(width: 16),
          Text('${telemetry.rttMs} ms', style: style),
          const SizedBox(width: 16),
          Text('${telemetry.lossPercent.toStringAsFixed(1)}% loss', style: style),
          const SizedBox(width: 16),
          Text('${telemetry.bweMbps.toStringAsFixed(1)} Mbps', style: style),
          const SizedBox(width: 16),
          Text('buf ${telemetry.playoutDelayMs} ms', style: style),
          const SizedBox(width: 16),
          // Whether media is relayed changes both the latency and who can see the traffic, so it
          // is worth surfacing rather than hiding.
          Text(telemetry.relayed ? 'RELAY' : 'P2P', style: style),
          const SizedBox(width: 16),
          Text(hardware ? 'HW decode' : 'SW decode', style: style),
        ],
      ),
    );
  }
}
