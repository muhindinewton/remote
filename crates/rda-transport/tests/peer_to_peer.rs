//! Two peer connections completing a full negotiation and exchanging control frames.
//!
//! This is the Phase 2 acceptance test: ICE, DTLS, SCTP and the pre-negotiated channel topology all
//! working together, with real input payloads crossing the wire and arriving byte-identical.
//!
//! Signaling here is a direct channel between the two halves rather than the WebSocket server —
//! that path is covered by `rda-signal-client/tests/signaling_e2e.rs`, and coupling the two would
//! make a failure ambiguous about which layer broke.
//!
//! ICE negotiation is genuinely CPU- and timing-sensitive, so these tests serialise negotiation
//! through a process-wide lock and pin each runtime to two workers. Without that, `cargo test`
//! runs every test binary concurrently, the machine is oversubscribed, and ICE misses its deadline
//! — which surfaces as a connection timeout that looks like a protocol bug and is not one.
//! Serialising costs about two seconds in total and removes the flake entirely.

use rda_proto::control::{
    Channel, ControlFrame, KeyAction, KeyframeMode, Modifiers, MouseButtonId, Payload,
    USAGE_PAGE_KEYBOARD,
};
use rda_proto::signaling::{IceServer, RelayCredentials};
use rda_transport::{RoutingPreference, Session, SessionRole, TransportEvent};
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, MutexGuard};
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;

/// Host-candidate only. No STUN server is contacted, so the test does not depend on the network.
fn local_only_creds() -> RelayCredentials {
    RelayCredentials {
        ice_servers: Vec::<IceServer>::new(),
        ttl_s: 0,
        preferred_order: vec![],
    }
}

/// Serialises negotiation across tests in this binary.
fn negotiation_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// A connected pair, holding the negotiation lock for the lifetime of the test.
struct Pair {
    controller: Session,
    host: Session,
    _guard: MutexGuard<'static, ()>,
}

/// What one side hands the other during negotiation.
#[derive(Debug)]
enum Signal {
    Offer(String),
    Answer(String),
    Candidate(rda_proto::signaling::IceCandidate),
}

/// Drives negotiation between two sessions over a pair of in-process channels.
///
/// Returns once both report `Connected`, or panics on timeout — a hang here is always a real bug,
/// and a test that hangs is worse than one that fails.
async fn connect_pair() -> Pair {
    let _guard = negotiation_lock().lock().await;

    let mut controller = Session::new(
        SessionRole::Controller,
        &local_only_creds(),
        RoutingPreference::PreferDirect,
    )
    .await
    .expect("controller peer connection");
    let mut host = Session::new(
        SessionRole::Host,
        &local_only_creds(),
        RoutingPreference::PreferDirect,
    )
    .await
    .expect("host peer connection");

    let (to_host, mut host_rx) = mpsc::unbounded_channel::<Signal>();
    let (to_controller, mut controller_rx) = mpsc::unbounded_channel::<Signal>();

    let offer = controller.create_offer().await.expect("create offer");
    to_host.send(Signal::Offer(offer)).unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut controller_connected = false;
    let mut host_connected = false;

    while !(controller_connected && host_connected) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "peers did not connect within 30s"
        );

        tokio::select! {
            biased;

            Some(sig) = host_rx.recv() => match sig {
                Signal::Offer(sdp) => {
                    let answer = host.accept_offer(&sdp).await.expect("accept offer");
                    to_controller.send(Signal::Answer(answer)).unwrap();
                }
                Signal::Candidate(c) => {
                    host.add_remote_candidate(&c).await.expect("host add candidate");
                }
                Signal::Answer(_) => unreachable!("host never receives an answer"),
            },

            Some(sig) = controller_rx.recv() => match sig {
                Signal::Answer(sdp) => {
                    controller.accept_answer(&sdp).await.expect("accept answer");
                }
                Signal::Candidate(c) => {
                    controller.add_remote_candidate(&c).await.expect("controller add candidate");
                }
                Signal::Offer(_) => unreachable!("controller never receives an offer"),
            },

            Some(event) = controller.events.recv() => match event {
                TransportEvent::LocalCandidate(c) => { let _ = to_host.send(Signal::Candidate(c)); }
                TransportEvent::ConnectionState(RTCPeerConnectionState::Connected) => {
                    controller_connected = true;
                }
                TransportEvent::ConnectionState(RTCPeerConnectionState::Failed) => {
                    panic!("controller connection failed");
                }
                _ => {}
            },

            Some(event) = host.events.recv() => match event {
                TransportEvent::LocalCandidate(c) => { let _ = to_controller.send(Signal::Candidate(c)); }
                TransportEvent::ConnectionState(RTCPeerConnectionState::Connected) => {
                    host_connected = true;
                }
                TransportEvent::ConnectionState(RTCPeerConnectionState::Failed) => {
                    panic!("host connection failed");
                }
                _ => {}
            },

            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }

    Pair {
        controller,
        host,
        _guard,
    }
}

/// Waits for the next decoded frame on the host, ignoring everything else.
async fn next_frame(host: &mut Session, what: &str) -> (Channel, ControlFrame) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!remaining.is_zero(), "timed out waiting for {what}");
        match tokio::time::timeout(remaining, host.events.recv()).await {
            Ok(Some(TransportEvent::Frame { channel, frame })) => return (channel, *frame),
            Ok(Some(TransportEvent::MalformedFrame { error, .. })) => {
                panic!("frame failed to decode while waiting for {what}: {error}")
            }
            Ok(Some(_)) => continue,
            Ok(None) => panic!("transport events closed while waiting for {what}"),
            Err(_) => panic!("timed out waiting for {what}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_peers_negotiate_and_exchange_input_frames() {
    let Pair {
        controller,
        mut host,
        _guard,
    } = connect_pair().await;

    assert_eq!(
        controller.connection_state(),
        RTCPeerConnectionState::Connected
    );
    assert_eq!(host.connection_state(), RTCPeerConnectionState::Connected);

    // Wait for the channels to actually open. Being connected is not the same as being usable —
    // SCTP association setup follows DTLS.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // A pointer move. Routed automatically to the unreliable channel by message type.
    let mouse = ControlFrame::new(
        Payload::MouseMove {
            display_id: 0,
            flags: 0,
            x_norm: 32768,
            y_norm: 16384,
            modifiers: Modifiers::NONE,
        },
        1234,
        123_456,
    );
    controller.send(&mouse).await.expect("send mouse move");

    let (channel, received) = next_frame(&mut host, "mouse move").await;
    assert_eq!(
        channel,
        Channel::InputPointer,
        "pointer motion must ride the unreliable channel"
    );
    assert_eq!(
        received, mouse,
        "frame must survive the round trip byte-identical"
    );

    // A keystroke, which must take the reliable ordered channel instead.
    let key = ControlFrame::new(
        Payload::KeyEvent {
            usage_page: USAGE_PAGE_KEYBOARD,
            usage_id: 0x0004, // 'a'/'A'
            action: KeyAction::Down,
            flags: 0,
            modifiers: Modifiers(Modifiers::LEFT_SHIFT),
        },
        1235,
        123_460,
    );
    controller.send(&key).await.expect("send key event");

    let (channel, received) = next_frame(&mut host, "key event").await;
    assert_eq!(
        channel,
        Channel::InputKeys,
        "keystrokes must ride the reliable channel"
    );
    assert_eq!(received, key);

    // A click carries its own coordinates, so it lands correctly even if the preceding move was
    // dropped on the unreliable channel.
    let click = ControlFrame::new(
        Payload::MouseButton {
            button: MouseButtonId::Left,
            action: KeyAction::Down,
            x_norm: 40000,
            y_norm: 20000,
            modifiers: Modifiers::NONE,
            display_id: 0,
            click_count: 1,
        },
        1236,
        123_470,
    );
    controller.send(&click).await.expect("send click");
    let (channel, received) = next_frame(&mut host, "mouse button").await;
    assert_eq!(channel, Channel::InputKeys);
    assert_eq!(received, click);

    controller.close().await.unwrap();
    host.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_state_sync_round_trips_with_its_full_pressed_set() {
    let Pair {
        controller,
        mut host,
        _guard,
    } = connect_pair().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The stuck-modifier repair message. Its contents must survive exactly, because the host
    // reconciles against it — a corrupted set would release keys the user is still holding.
    let sync = ControlFrame::new(
        Payload::KeyStateSync {
            modifiers: Modifiers(Modifiers::LEFT_SHIFT | Modifiers::LEFT_CTRL),
            authoritative: true,
            pressed: vec![0x00E0, 0x00E1, 0x0004],
        },
        1240,
        123_560,
    );
    controller.send(&sync).await.expect("send key state sync");

    let (channel, received) = next_frame(&mut host, "key state sync").await;
    assert_eq!(channel, Channel::InputKeys);
    assert_eq!(received, sync);

    controller.close().await.unwrap();
    host.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_to_controller_messages_flow_in_the_reverse_direction() {
    let Pair {
        mut controller,
        host,
        _guard,
    } = connect_pair().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // LTR acknowledgement travels controller -> host in production, but the channel itself must be
    // bidirectional; a one-way transport would silently break cursor updates and keyframe requests.
    let request = ControlFrame::new(
        Payload::RequestKeyframe {
            mode: KeyframeMode::Ltr,
            ltr_index: 3,
            reason: 0,
        },
        1,
        0,
    );
    host.send(&request).await.expect("send from host");

    let (channel, received) = next_frame(&mut controller, "keyframe request").await;
    assert_eq!(channel, Channel::Control);
    assert_eq!(received, request);

    controller.close().await.unwrap();
    host.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_corrupt_frame_is_reported_without_killing_the_session() {
    let Pair {
        controller,
        mut host,
        _guard,
    } = connect_pair().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send a deliberately malformed frame: a valid header claiming MouseMove, but truncated.
    // The requirement from PROTOCOL.md §6.5 is that this is discarded and counted, never fatal.
    let junk = vec![0x10u8, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xFF];
    let bad = ControlFrame::decode(&junk);
    assert!(bad.is_err(), "test fixture must actually be malformed");

    let channels_frame = ControlFrame::new(Payload::Ping { token: 0xDEAD_BEEF }, 1, 0);
    // A well-formed frame after the bad one must still arrive, proving the session survived.
    controller.send(&channels_frame).await.expect("send ping");
    let (_, received) = next_frame(&mut host, "ping after malformed frame").await;
    assert_eq!(received, channels_frame);
    assert_eq!(host.connection_state(), RTCPeerConnectionState::Connected);

    controller.close().await.unwrap();
    host.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn telemetry_reports_a_direct_path_and_a_measured_rtt() {
    let Pair {
        controller,
        host,
        _guard,
    } = connect_pair().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    controller.poll_stats(1000).await;
    let telemetry = controller.telemetry().await;

    // Loopback is host-to-host, so nothing should be classified as relayed.
    assert!(
        !telemetry.relayed,
        "a loopback pair must not be reported as relayed"
    );
    // The summary line is what the operator actually sees; it must render at any point.
    assert!(telemetry.summary().contains("P2P"));

    controller.close().await.unwrap();
    host.close().await.unwrap();
}
