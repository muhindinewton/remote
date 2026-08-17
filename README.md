# rda — Remote Desktop Engine

An open-source remote access system (AnyDesk / RustDesk class) built on a Rust core with a Flutter UI,
transporting screen, audio and input over native WebRTC.

The defining constraint is **distance**. The primary corridor is USA ↔ Nairobi, Kenya — 180–250 ms RTT,
jitter-prone, with real packet loss on the last mile. A design that is correct at 5 ms RTT is frequently
wrong at 220 ms, and this codebase inverts several WebRTC defaults because of it.

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Architecture & protocol specification | **Complete** — [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/PROTOCOL.md](docs/PROTOCOL.md) |
| 2 | Signaling, NAT traversal, transport, telemetry | **Complete** — 124 tests passing |
| 3 | Host engine: capture, input injection, authorization | **Complete** |
| 4 | Video encoding & streaming pipeline | **Complete** |
| 5 | Flutter GUI & client rendering | **Complete** — analyzed and unit-tested; not run (needs full Xcode) |
| 6 | E2E testing, long-distance tuning, deployment | **Complete** — 528 Rust + 17 Dart tests |

The whole loop runs end to end today, with a real viewer window — see
[Installing it on two machines](#installing-it-on-two-machines).

## Workspace

| Crate | Owns |
|---|---|
| [`rda-proto`](crates/rda-proto) | Wire types, control frame codec, validation. `forbid(unsafe_code)`, fuzzed. The executable form of `docs/PROTOCOL.md` |
| [`rda-telemetry`](crates/rda-telemetry) | RTT / loss / jitter estimation, plus the NACK, FEC and degradation-ladder policies that depend on them |
| [`rda-signal-server`](crates/rda-signal-server) | Rendezvous: device registry, presence, SDP and ICE relay, TURN credential minting |
| [`rda-signal-client`](crates/rda-signal-client) | Signaling client, identity, reconnect with jittered backoff |
| [`rda-transport`](crates/rda-transport) | WebRTC peer connection, ICE policy, DataChannel topology |
| [`rda-crypto`](crates/rda-crypto) | Device identity, SPAKE2 PIN auth, DTLS fingerprint binding, unattended tokens, short authentication string |
| [`rda-input`](crates/rda-input) | HID mapping, injection backends, state reconciliation, capability enforcement |
| [`rda-capture`](crates/rda-capture) | Screen capture abstraction, damage tracking, latest-frame-wins sink |
| [`rda-encode`](crates/rda-encode) | Colour conversion, hardware H.264/HEVC, adaptive bitrate control |
| [`rda-decode`](crates/rda-decode) | Hardware H.264 decode and the client-side jitter buffer |
| [`rda-ffi`](crates/rda-ffi) | C ABI bridge (`cdylib`) exposing the client engine to Flutter |
| [`rda-netsim`](crates/rda-netsim) | Deterministic link impairment, so corridor claims are testable in CI |
| [`rda-session`](crates/rda-session) | The seam between signaling and transport: ICE negotiation and the authenticated handshake, shared by both ends |
| [`rda-host`](crates/rda-host) | Host agent: authorization state machine, capture thread, and the `serve` loop |
| [`rda-client`](crates/rda-client) | Viewer: connects, authenticates, decodes, renders a window and forwards input |

## Build and test

```sh
cargo build --workspace
cargo test --workspace          # 528 tests
cargo clippy --workspace --all-targets -- -D warnings
```

Check a host machine's permissions before anything else — both macOS and Linux fail *silently*
by default, returning black frames or discarding injected events with no error at all:

```sh
cargo run -p rda-host -- doctor
```

See what the encoder actually achieves on this machine:

```sh
cargo run --release -p rda-host -- encode
```

Run the signaling server:

```sh
RDA_TURN_SECRET=<shared-secret-matching-coturn> \
RDA_DOMAIN=example.net \
RDA_BIND=0.0.0.0:8080 \
cargo run -p rda-signal-server
```

TLS is terminated by a reverse proxy, not by this process. `wss://` is required in production
(`docs/PROTOCOL.md` §3.1).

## Installing it on two machines

Nothing is bundled as an installer yet, so installation is `cargo install`. That is genuinely enough
— both binaries are self-contained and put themselves on `PATH`.

**On both machines**, install Rust (<https://rustup.rs>), then:

```sh
git clone <this repo> && cd remote
cargo install --path crates/rda-host      # the machine being controlled
cargo install --path crates/rda-client    # the machine doing the controlling
```

Linux additionally needs the X11 and uinput development headers:

```sh
sudo apt install libx11-dev libxkbcommon-dev libwayland-dev pkg-config    # Debian/Ubuntu
sudo usermod -aG input "$USER"                                           # then log out and back in
```

**On the host machine, run the doctor first.** Screen capture and input injection fail *silently* on
macOS and Linux — black frames, discarded events, no error — so guessing is not a viable diagnostic:

```sh
rda-host doctor
```

On macOS this is where you grant **Screen Recording** and, if you want input, **Accessibility**, both
under System Settings → Privacy & Security. Grant them to the terminal you launch from.

### Where the signaling server goes

You need exactly one, reachable by both machines. It is the rendezvous that carries the SDP and ICE
exchange; peers cannot find each other without it. It is small — JSON over WebSocket, a few messages
per session — and it never sees your screen, which stays end-to-end encrypted between the peers.

**Same network.** Run it on either machine and point both at that machine's LAN address:

```sh
RDA_DOMAIN= cargo run --release -p rda-signal-server        # e.g. on 192.168.0.101
```

`RDA_DOMAIN=` (empty) is not cosmetic. With a domain set, the server hands out STUN/TURN URLs for a
PoP fleet; if that fleet does not exist, every peer spends real time resolving names that do not
resolve. On this machine that cost about eleven seconds of blocked runtime and *every* ICE check
timed out behind it. On a LAN you need no relay at all, so hand out none.

**Different networks, same country.** Put the server on any host with a public address, and put TLS
in front of it — `wss://` is required (`docs/PROTOCOL.md` §3.1) and the server does not terminate TLS
itself. Direct peer-to-peer will work for many home connections. When it does not, you need TURN:
see [deploy/](deploy/), which has the signaling server and coturn as one unit. Note the header on
`deploy/docker-compose.yml` — those manifests have never been run.

### Running a session

**Host** — prints its device id and a PIN, then waits. It keeps running and serves one session after
another, so you start it once and leave it:

```sh
rda-host serve --server ws://192.168.0.101:8080/ws --allow-input
```

The device id is stable across restarts, derived from a key file in the platform config directory
(`~/Library/Application Support/rda/host.key`, `%APPDATA%\rda\`, or `$XDG_CONFIG_HOME/rda/`). It is
the machine's address — save it. `rda-host id` prints it without starting a session.

Input injection is **off** without `--allow-input`. The handshake still runs and every guard, rate
limit and validation rule still executes; the events land in a recorder instead of the OS, so the
path is proven without handing over the machine.

**Viewer** — opens a window showing the host's screen and forwards your keyboard and mouse to it:

```sh
rda-client --server ws://192.168.0.101:8080/ws --peer <DEVICE-ID> --pin <PIN>
```

Escape or closing the window ends the session; the host returns to waiting for the next one. Both
ends print a four-word short authentication string and **they must match**. Comparing them aloud is
what defeats a man-in-the-middle on first contact, where there is no pinned key to check against.

For CI or a machine with no display, `--headless --out ./frames` writes PNGs instead of opening a
window — which is also the easiest way to check the picture is *right* rather than merely present.

A release-build run, 2940×1912, host and viewer both local:

```
video out     327 frames, 696.4 KiB      received  225 frames (592.6 KiB)
capture       327 produced, 0 dropped     decoded   225
encoder       327 encoded, 0 paced        link      5.8% loss reported to the host
link          5.8% loss, 61 ms rtt        playout   28 ms target
  settled on  rung 2: 2037 kbps, 30 fps
input in      124 events
  injected    124
  refused     0
```

Without `--allow-input` the same run reports `injected 0, refused 124` and `granted: ["view"]` — the
capability gate, doing its job.

Sent frames exceed received ones because the video channel is unreliable with a 500 ms lifetime:
fragments that would arrive too late to display are not retransmitted, which is the entire point of
the channel's configuration. **Build in release.** A debug build cannot keep up with colour
conversion at this resolution, and the latest-frame-wins sink then discards most of what it captures,
which measures the CPU rather than the pipeline.

### If you point the viewer at the host's own screen

You get an infinite mirror, which is a good smoke test — it proves the picture is live — but it is
pathological content. The recursion is visually complex enough to saturate the encoder, which drives
real loss, which walks the degradation ladder to its bottom rung. That is the adaptation working, not
failing. Judge quality against a normal desktop.

## Congestion control, and why it is ours

The architecture assumed WebRTC would supply a bandwidth estimate, the way a browser does. **It does
not.** In webrtc-rs 0.12 both `available_outgoing_bitrate` and `current_round_trip_time` have exactly
one assignment in the whole dependency tree — the literal `0.0` — and the `interceptor` crate ships
TWCC *transport* with no estimator on top of it. There is no GCC, no BBR, and moving video to RTP
would not change that. So the two numbers the encoder needs are measured here:

| Signal | Where it comes from | Honest description |
|---|---|---|
| **Loss** | The viewer, from gaps in the wire sequence, reported every second as `QosReport` (§7.11) | Real. SCTP abandons fragments under `max_packet_life_time` and tells the sender nothing, so the receiver is the only party that can see it |
| **RTT** | `Ping`/`Pong` on the control channel (§7.11) | Real, less the peer's self-reported processing time |
| **Bandwidth** | `BitrateEstimator` — the loss-based half of GCC (draft-ietf-rmcat-gcc-02 §5.5) | Partial. See below |

`BitrateEstimator` implements GCC's published loss rules: below 2 % loss the rate rises 5 %, above
10 % it falls by half the loss fraction, and in between it holds. GCC's *other* half — the
arrival-time filter and overuse detector that react before a queue overflows — is absent, because it
needs per-packet arrival timing that only RTP carries. The receiver's jitter-buffer depth is used as
a coarse stand-in: growth withholds an increase, but never forces a cut, since a merely jittery link
is most of this corridor most of the time.

**Expect it to react late on a deeply buffered path.** Loss is a lagging signal. This will hold a
session together; it will not hold latency down the way a delay-based controller does.

Watch it work — the host's closing summary reports where it settled:

```
link          13 reports in, 5.8% loss, 61 ms rtt, bwe 3.31 Mbps
  settled on  rung 2: 2037 kbps, 30 fps, 100% scale
```

On a clean link the same run settles on rung 1 at 5.9 Mbps and 60 fps.

### Known limits of this path

- **Video rides a DataChannel, not RTP.** `docs/PROTOCOL.md` §7.13 specifies this as the OPTIONAL
  path; RTP remains the normal one. Moving to it would buy real packet pacing and TWCC arrival times
  — the input the delay-based controller needs — but not an estimator, which still has to be ours.
- **One viewer at a time.** The host serves one controller, then returns to waiting for the next.
  It does not multiplex.
- **The viewer window is `minifb`, not the Flutter UI.** A CPU framebuffer blit, no GPU path, no
  cursor shape, no clipboard, no multi-monitor selection. It is a real usable viewer, not the
  finished product.
- **Host and viewer keep separate identity files** (`host.key`, `controller.key`). A device should
  have one identity and a per-session role, but the registry keys peers by device id and a second
  registration evicts the first — so sharing one file makes the viewer knock the host offline. That
  collapses to a single file once both roles live in one agent process.
- **The identity file is a `0600` file, not the OS keystore.** Same guarantee as an SSH private key,
  and it refuses to load if the permissions are wider. Keychain/DPAPI/Secret Service additionally
  protect the key at rest; `Keystore` is a trait so that swap is one implementation.
- **On macOS, the first run of a freshly built binary may fail to connect.** ICE candidates are
  exchanged and then no pair ever succeeds, ending in `negotiation timed out after 30s`. The OS
  gates inbound UDP per binary, and a newly written executable is a new binary to it. Run it again;
  it has succeeded every time on the second attempt.

Fuzzing (requires nightly and `cargo install cargo-fuzz`):

```sh
cd crates/rda-proto/fuzz
cargo +nightly fuzz run control_frame
cargo +nightly fuzz run signaling_json
```

The same round-trip property runs on stable as an ordinary test, so CI covers it without nightly.

## Platform support

| | Screen capture | Input injection | Hardware encoding |
|---|---|---|---|
| macOS | Implemented (Core Graphics). Needs Screen Recording permission | Implemented (`CGEventPost`). Needs Accessibility permission | Implemented (VideoToolbox), encode **and** decode. H.264 / HEVC — **not AV1** |
| Windows | Phase 6 (DXGI Desktop Duplication) | Written, cross-target checked, **not run**. UIPI blocks elevated windows | Phase 6 (NVENC / QuickSync / AMF) |
| Linux | Phase 6 (PipeWire + portal) | Written, cross-target checked, **not run**. `uinput` device registration incomplete | Phase 6 (VAAPI) |

Only macOS is executed and tested here. The Windows and Linux input backends compile under
`cargo check --target`, which catches type and API errors but proves nothing about runtime
behaviour — they are marked as such in their module docs rather than presented as done.

Two limitations are architectural rather than unfinished work, and are stated plainly in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): Windows cannot inject into elevated windows or the
UAC prompt without a SYSTEM service, and unattended access on a locked Wayland session has no
generic mechanism at all.

## Three decisions that differ from WebRTC defaults

These are the ones most likely to be "corrected" by someone who has not read
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Each has a test that fails if it is reverted.

**1. Retransmission is mostly off.** A NACK costs a full RTT — at 220 ms that is ~7 frames at 30 fps, so
the repaired packet arrives after its frame was due. Resilience comes from FEC and loss-tolerant encoding
instead; NACK is retained only for reference frames, where losing the reference costs more than waiting.
See `rda_telemetry::should_nack`.

**2. Pointer motion is unreliable and unordered; keystrokes are reliable and ordered.** SCTP's minimum
retransmission timeout is typically one second, so a lost packet on a reliable stream freezes that stream
for a second or more. A frozen cursor is far worse than a dropped position update — and a lost key-up is a
stuck modifier. Because pointer moves can vanish, **button events carry their own coordinates**.
See `rda_transport::channels`.

**3. Marseille, not Johannesburg.** US ↔ Nairobi traffic transits Europe: SEACOM and PEACE both run
Mombasa → Suez → Mediterranean → France. Johannesburg looks like the midpoint on a map and frequently adds
a full Europe round trip instead. Relay candidates are also capped at two PoPs, because each extra
candidate multiplies the ICE check matrix and every check round costs an RTT.
See `rda_signal_server::relay`.

## What the pipeline achieves

Measured on an M-series Mac with `cargo run --release -p rda-host -- encode`, capturing a 5K Retina
desktop through VideoToolbox:

```
encoder: macos-videotoolbox (hardware: true)
  raw:          2775.4 Mbps
  compressed:      0.9 Mbps
  ratio:          3003x
  mean frame: 7501 bytes
  keyframes: 1
```

One keyframe across the whole run, because a keyframe is an event here rather than a heartbeat. An
idle desktop produces **zero bytes** — damage detection stops the pipeline before conversion, which
leaves the whole pipe free for the burst when the user does act.

Three decisions in [`rda-encode`](crates/rda-encode) are specifically about a 220 ms link:

**FEC comes out of the video budget, not on top of it.** At 10% loss the FEC schedule adds ~35%
overhead. Sizing video at the full estimate and then adding redundancy exceeds the link by a third
*exactly when it is already failing*. `RateController` divides instead — asserted by
`fec_overhead_is_taken_out_of_the_budget_not_added_to_it`.

**Colour is full-range with box-filtered chroma, because the content is text.** Studio swing crushes
the pure black and white that dominate a desktop, and nearest-neighbour 4:2:0 downsampling makes
thin coloured text fringe badly. `box_filtering_beats_nearest_neighbour_on_thin_coloured_detail`
measures the difference rather than asserting it.

**An IDR is a budgeted event.** Repeated recovery requests are coalesced to one per second, an
acknowledged long-term reference is repaired at 2–4× a P frame instead of 15–30×, and when an IDR is
genuinely unavoidable the target bitrate halves for its duration so the burst is paced.

## Verifying it over the real corridor

The corridor cannot be reached from a developer's desk, so it is manufactured three ways — see
[scripts/CHECKLIST.md](scripts/CHECKLIST.md) for the full sequence.

**Simulated, in CI.** [`rda-netsim`](crates/rda-netsim) models the link deterministically and
[`corridor_e2e`](crates/rda-netsim/tests/corridor_e2e.rs) drives the *real* hardware encoder, rate
controller and jitter buffer across it:

```
                 lan  rtt   2ms  encoded   61  played   61 (100%)   7009 kbps  buf  15ms
     us-kenya-direct  rtt 220ms  encoded   61  played   61 (100%)   5378 kbps  buf  24ms
    us-kenya-relayed  rtt 260ms  encoded   61  played   61 (100%)   1998 kbps  buf  51ms
  us-kenya-congested  rtt 250ms  encoded   61  played   53 ( 87%)    695 kbps  buf 120ms
             hostile  rtt 250ms  encoded   61  played   21 ( 34%)    318 kbps  buf 185ms
```

The playout buffer adapting **15 → 185 ms** as the link degrades is the design working; a buffer
stuck at its floor would stutter on a real link. The rate controller settles at 695 kbps inside an
800 kbps ceiling rather than hammering it. Loss is modelled with **Gilbert–Elliott bursts**, not
independent per-packet drops — independent loss flatters FEC badly, because a code that recovers one
loss per protected set handles scattered loss trivially and burst loss not at all.

**Locally impaired.** [`scripts/impair.sh`](scripts/impair.sh) applies the same profiles with Linux
`tc`/`netem`; [`scripts/impair-macos.sh`](scripts/impair-macos.sh) does it with `dnctl`/`pfctl`,
because `tc` is Linux-only and the host side is developed on macOS.

**On the real path.** Level C in the checklist — including replacing the estimated PoP latencies
with measurements from an actual Kenyan vantage point, and confirming or refuting the prediction
that Marseille beats Johannesburg.

## Deployment

[`deploy/`](deploy/) has one compose stack per PoP: signaling plus a coturn relay, with a
[deployment guide](deploy/README.md) covering placement, firewall rules and the operational traps.
The manifests are **not validated by running** — Docker is not installed in the development
environment — though the container health check invokes a `--health-check` flag that *is* implemented
and verified.

## The Flutter viewer

[`app/`](app/) is a complete Flutter application: connection screen, video canvas, input capture and
a telemetry bar, talking to [`rda-ffi`](crates/rda-ffi) over `dart:ffi`.

```sh
cd app
flutter analyze   # strict: strict-casts, strict-inference, strict-raw-types
flutter test      # 17 tests
```

**The Dart analyzes clean and its mapping logic is unit-tested; it has not been *run*.** Building the
macOS desktop app needs a full Xcode installation, which is not present here. Every symbol
[`bindings.dart`](app/lib/src/ffi/bindings.dart) looks up is verified present in the built `cdylib`
with `nm`.

The most valuable Dart test is a **cross-language consistency check**: it asserts that Flutter's
`PhysicalKeyboardKey.usbHidUsage` values match the independently-written HID table in
[`crates/rda-input/src/hid.rs`](crates/rda-input/src/hid.rs). Nothing in either language would
notice if those two drifted — every keystroke would simply land on the wrong key. It has already
earned its place: it found that volume keys sit on the *keyboard* page (`0x7F`–`0x81`), not the
consumer page, and that the Rust table was missing them.

The Rust half **is** fully verified: 34 tests over the FFI surface, including that every entry point
survives a null handle (Dart passes null after a hot restart), that the borrow contract on frame
pixels holds, and that a real hardware-encoded keyframe flows through to borrowable BGRA.

Three things in the viewer are worth knowing about:

**Flutter's `PhysicalKeyboardKey.usbHidUsage` is already a USB HID usage code** — the exact identity
the wire protocol chose. So the key mapping is a mask, not a lookup table, and a controller on any
layout sends the key *position* the user pressed. Using `LogicalKeyboardKey` instead would send the
character and break every shortcut on a non-US layout.

**Frames reach the GPU without touching the UI thread.** `ui.ImageDescriptor.raw` +
`instantiateCodec` hands the upload to the engine's raster threads; a `CustomPainter` would do it on
the UI thread and drop frames as soon as the picture got large. The render loop is a `Ticker`, so it
runs in step with vsync rather than drifting against it.

**Only one decode is in flight at a time.** Without that guard a slow frame lets work pile up and the
viewer falls further behind every tick — a failure mode that looks like a network problem and is not.

## The authorization gate

Input injection is total system control, so it is not guarded by a boolean anyone can forget to
check. `rda_input::Injector::apply` requires a `SessionGrant`, and the only thing that produces one
is `HostSession::complete_pin_auth` — after the PAKE round, key confirmation, address-book check
and fingerprint binding have all passed. A caller that skipped the handshake has nothing to pass,
so the mistake is a compile error rather than a review finding.

[crates/rda-host/tests/authorization_gate.rs](crates/rda-host/tests/authorization_gate.rs) asserts
the property end to end against the real crypto: an unauthenticated peer, a peer that only got
consent, a peer mid-PAKE, a wrong PIN, a view-only session, and a man-in-the-middle **holding the
correct PIN** each reach the OS zero times — alongside a positive case proving the path works at
all.

## Licence

MIT OR Apache-2.0.
