//! End-to-end signaling tests against a real server on a real socket.
//!
//! These exercise the full path — TCP, WebSocket framing, JSON envelope, Ed25519 challenge —
//! rather than calling handler functions directly, because the interesting failures in signaling
//! live in the seams between those layers.

use rda_proto::caps::Capabilities;
use rda_proto::signaling::{
    AuthMode, ConnectRequest, ConnectResponse, ConnectStatus, Message, Role, SdpPayload,
};
use rda_signal_client::{connect, ClientConfig, Identity};
use rda_signal_server::{router, AppState, Config};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;

/// Starts a signaling server on an ephemeral port and returns its ws:// URL.
async fn start_server() -> (String, tokio::task::JoinHandle<()>) {
    let state = AppState::new(Config {
        turn_secret: b"test-secret".to_vec(),
        ..Config::default()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });
    // Give the accept loop a moment to become ready.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (format!("ws://{addr}/ws"), handle)
}

fn host_config() -> ClientConfig {
    ClientConfig {
        role: Role::Host,
        caps: Capabilities::from_iter([
            rda_proto::caps::VIDEO_H264,
            rda_proto::caps::VIDEO_AV1,
            rda_proto::caps::INPUT_HID,
        ]),
        agent: Some("test-host/0.1.0".into()),
        // Realistic probe results for a Nairobi host.
        pop_rtt: BTreeMap::from([
            ("iad".into(), 240),
            ("mrs".into(), 100),
            ("lhr".into(), 118),
            ("nbo".into(), 6),
        ]),
    }
}

fn controller_config() -> ClientConfig {
    ClientConfig {
        role: Role::Controller,
        caps: Capabilities::from_iter([rda_proto::caps::VIDEO_H264, rda_proto::caps::INPUT_HID]),
        agent: Some("test-controller/0.1.0".into()),
        // ...and for a US-East controller.
        pop_rtt: BTreeMap::from([
            ("iad".into(), 8),
            ("mrs".into(), 95),
            ("lhr".into(), 78),
            ("nbo".into(), 235),
        ]),
    }
}

/// Waits for a message matching `f`, failing the test rather than hanging forever.
async fn expect_message<T>(
    inbox: &mut mpsc::UnboundedReceiver<rda_proto::signaling::Envelope>,
    what: &str,
    mut f: impl FnMut(&rda_proto::signaling::Envelope) -> Option<T>,
) -> T {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!remaining.is_zero(), "timed out waiting for {what}");
        match tokio::time::timeout(remaining, inbox.recv()).await {
            Ok(Some(env)) => {
                if let Some(v) = f(&env) {
                    return v;
                }
            }
            Ok(None) => panic!("connection closed while waiting for {what}"),
            Err(_) => panic!("timed out waiting for {what}"),
        }
    }
}

#[tokio::test]
async fn a_device_registers_and_gets_its_derived_id_back() {
    let (url, _server) = start_server().await;
    let identity = Identity::generate();

    let conn = connect(&url, &identity, &host_config())
        .await
        .expect("registration must succeed");

    assert_eq!(conn.device_id(), identity.device_id());
    assert_eq!(conn.heartbeat_interval_s(), 30);
}

#[tokio::test]
async fn heartbeats_are_acknowledged() {
    let (url, _server) = start_server().await;
    let identity = Identity::generate();
    let mut conn = connect(&url, &identity, &host_config()).await.unwrap();

    conn.send(None, Message::Heartbeat).unwrap();
    expect_message(&mut conn.inbox, "heartbeat_ack", |e| {
        matches!(e.msg, Message::HeartbeatAck).then_some(())
    })
    .await;
}

#[tokio::test]
async fn a_full_offer_answer_exchange_completes_through_the_server() {
    let (url, _server) = start_server().await;

    let host_identity = Identity::generate();
    let controller_identity = Identity::generate();
    let mut host = connect(&url, &host_identity, &host_config()).await.unwrap();
    let mut controller = connect(&url, &controller_identity, &controller_config())
        .await
        .unwrap();

    // Controller dials the host by its derived device id.
    controller
        .send(
            None,
            Message::ConnectRequest(ConnectRequest {
                target: host_identity.device_id().clone(),
                from_pubkey: controller_identity.pubkey_b64(),
                from_label: Some("Test Controller".into()),
                auth_mode: AuthMode::Pin,
                token: None,
                requested_caps: vec!["view".into(), "input".into()],
            }),
        )
        .unwrap();

    // The host sees the request. The server assigned the session id and stamped it on the
    // envelope, so the host learns it without the controller having to tell it.
    let session_id = expect_message(&mut host.inbox, "connect_request", |e| match &e.msg {
        Message::ConnectRequest(_) => e.sid.clone(),
        _ => None,
    })
    .await;
    assert!(session_id.starts_with("sess_"));

    // Both ends receive relay credentials, ranked for this specific pair.
    let host_creds = expect_message(&mut host.inbox, "host relay_credentials", |e| {
        match &e.msg {
            Message::RelayCredentials(c) => Some(c.clone()),
            _ => None,
        }
    })
    .await;
    let controller_creds = expect_message(
        &mut controller.inbox,
        "controller relay_credentials",
        |e| match &e.msg {
            Message::RelayCredentials(c) => Some(c.clone()),
            _ => None,
        },
    )
    .await;

    // Marseille wins for a US-East controller and a Nairobi host: it sits on the path the
    // traffic already takes. This is the assertion that would fail if someone "optimised" the
    // PoP list toward Johannesburg on the strength of a world map.
    assert_eq!(controller_creds.preferred_order[0], "mrs");
    assert_eq!(host_creds.preferred_order[0], "mrs");

    // Only the top two PoPs carry TURN credentials.
    let relay_entries = controller_creds
        .ice_servers
        .iter()
        .filter(|s| s.username.is_some())
        .count();
    assert_eq!(relay_entries, 2);

    // Host accepts, clamping the requested capabilities.
    host.send(
        Some(session_id.clone()),
        Message::ConnectResponse(ConnectResponse::accept(
            session_id.clone(),
            &["view".to_string(), "input".to_string()],
            rda_proto::caps::SessionCaps {
                view: true,
                input: true,
                ..Default::default()
            },
        )),
    )
    .unwrap();

    let granted = expect_message(&mut controller.inbox, "connect_response", |e| {
        match &e.msg {
            Message::ConnectResponse(r) => Some(r.clone()),
            _ => None,
        }
    })
    .await;
    assert_eq!(granted.status, ConnectStatus::Accepted);
    assert!(granted.granted_caps.contains(&"input".to_string()));

    // SDP offer/answer relayed through the server.
    controller
        .send(
            Some(session_id.clone()),
            Message::Offer(SdpPayload::plain("v=0\r\nOFFER\r\n")),
        )
        .unwrap();
    let offer = expect_message(&mut host.inbox, "offer", |e| match &e.msg {
        Message::Offer(s) => s.sdp.clone(),
        _ => None,
    })
    .await;
    assert!(offer.contains("OFFER"));

    host.send(
        Some(session_id.clone()),
        Message::Answer(SdpPayload::plain("v=0\r\nANSWER\r\n")),
    )
    .unwrap();
    let answer = expect_message(&mut controller.inbox, "answer", |e| match &e.msg {
        Message::Answer(s) => s.sdp.clone(),
        _ => None,
    })
    .await;
    assert!(answer.contains("ANSWER"));

    // Trickled ICE candidates flow in both directions.
    controller
        .send(
            Some(session_id.clone()),
            Message::IceCandidate(rda_proto::signaling::IceCandidate {
                candidate: "candidate:1 1 udp 2130706431 10.0.0.1 54321 typ host".into(),
                sdp_mid: Some("0".into()),
                sdp_mline_index: Some(0),
                username_fragment: Some("Xy7Q".into()),
            }),
        )
        .unwrap();
    let cand = expect_message(&mut host.inbox, "ice_candidate", |e| match &e.msg {
        Message::IceCandidate(c) => Some(c.clone()),
        _ => None,
    })
    .await;
    assert!(cand.candidate.contains("typ host"));
}

#[tokio::test]
async fn dialling_an_unknown_device_reports_offline() {
    let (url, _server) = start_server().await;
    let controller_identity = Identity::generate();
    let mut controller = connect(&url, &controller_identity, &controller_config())
        .await
        .unwrap();

    let absent = Identity::generate();
    controller
        .send(
            None,
            Message::ConnectRequest(ConnectRequest {
                target: absent.device_id().clone(),
                from_pubkey: controller_identity.pubkey_b64(),
                from_label: None,
                auth_mode: AuthMode::Pin,
                token: None,
                requested_caps: vec!["view".into()],
            }),
        )
        .unwrap();

    let resp = expect_message(&mut controller.inbox, "connect_response", |e| {
        match &e.msg {
            Message::ConnectResponse(r) => Some(r.clone()),
            _ => None,
        }
    })
    .await;
    assert_eq!(resp.status, ConnectStatus::Offline);
}

#[tokio::test]
async fn a_controller_cannot_be_dialled() {
    // Controllers are not connection targets. Reporting this as `Offline` rather than a distinct
    // status is deliberate: distinguishing them would turn the ID space into an enumeration oracle.
    let (url, _server) = start_server().await;

    let target_identity = Identity::generate();
    let _target = connect(&url, &target_identity, &controller_config())
        .await
        .unwrap();

    let caller_identity = Identity::generate();
    let mut caller = connect(&url, &caller_identity, &controller_config())
        .await
        .unwrap();

    caller
        .send(
            None,
            Message::ConnectRequest(ConnectRequest {
                target: target_identity.device_id().clone(),
                from_pubkey: caller_identity.pubkey_b64(),
                from_label: None,
                auth_mode: AuthMode::Pin,
                token: None,
                requested_caps: vec!["view".into()],
            }),
        )
        .unwrap();

    let resp = expect_message(&mut caller.inbox, "connect_response", |e| match &e.msg {
        Message::ConnectResponse(r) => Some(r.clone()),
        _ => None,
    })
    .await;
    assert_eq!(resp.status, ConnectStatus::Offline);
}

#[tokio::test]
async fn a_reconnect_evicts_the_previous_connection() {
    let (url, _server) = start_server().await;
    let identity = Identity::generate();

    let mut first = connect(&url, &identity, &host_config()).await.unwrap();
    let _second = connect(&url, &identity, &host_config()).await.unwrap();

    // The displaced connection is told why, rather than silently going dead.
    let reason = expect_message(&mut first.inbox, "peer_gone", |e| match &e.msg {
        Message::PeerGone(p) => Some(p.reason.clone()),
        _ => None,
    })
    .await;
    assert_eq!(reason, "replaced");
}

#[tokio::test]
async fn a_forged_registration_signature_is_refused() {
    let (url, _server) = start_server().await;

    // Answer the challenge with a key that does not match the claimed device id.
    let real = Identity::generate();
    let attacker = Identity::generate();

    use futures_util::{SinkExt, StreamExt};
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

    let challenge = ws.next().await.unwrap().unwrap().into_text().unwrap();
    let env = rda_proto::signaling::Envelope::from_slice(challenge.as_bytes()).unwrap();
    let nonce_b64 = match env.msg {
        Message::Challenge(c) => c.nonce,
        _ => panic!("expected challenge"),
    };
    let nonce = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &nonce_b64,
    )
    .unwrap();

    // Claim the victim's device id but sign with the attacker's key.
    let forged = rda_proto::signaling::Register {
        device_id: real.device_id().clone(),
        pubkey: attacker.pubkey_b64(),
        sig: attacker.sign_registration(&nonce, Role::Host),
        role: Role::Host,
        caps: Capabilities::new(),
        agent: None,
        pop_rtt: BTreeMap::new(),
    };
    let env = rda_proto::signaling::Envelope::new("m1", 0, None, Message::Register(forged));
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        String::from_utf8(env.to_vec().unwrap()).unwrap(),
    ))
    .await
    .unwrap();

    let reply = ws.next().await.unwrap().unwrap().into_text().unwrap();
    let env = rda_proto::signaling::Envelope::from_slice(reply.as_bytes()).unwrap();
    match env.msg {
        Message::Error(e) => {
            assert_eq!(
                e.code,
                rda_proto::signaling::error_code::BAD_SIGNATURE,
                "impersonating another device id must be refused"
            );
        }
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test]
async fn session_messages_are_refused_before_registration() {
    let (url, _server) = start_server().await;

    use futures_util::{SinkExt, StreamExt};
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let _challenge = ws.next().await.unwrap().unwrap();

    let env = rda_proto::signaling::Envelope::new(
        "m1",
        0,
        Some("sess_fake".into()),
        Message::Offer(SdpPayload::plain("v=0")),
    );
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        String::from_utf8(env.to_vec().unwrap()).unwrap(),
    ))
    .await
    .unwrap();

    let reply = ws.next().await.unwrap().unwrap().into_text().unwrap();
    let env = rda_proto::signaling::Envelope::from_slice(reply.as_bytes()).unwrap();
    match env.msg {
        Message::Error(e) => assert_eq!(e.code, rda_proto::signaling::error_code::NOT_REGISTERED),
        other => panic!("expected NOT_REGISTERED, got {other:?}"),
    }
}
