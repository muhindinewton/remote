//! WebSocket connection handling: the signaling state machine.
//!
//! One task per connection reads frames; a second task drains that peer's outbound queue. Splitting
//! them means a slow or stalled client cannot block the routing path for anyone else — on this
//! corridor a peer that stops reading is a normal event, not an exceptional one.

use crate::auth::{AuthError, Challenge};
use crate::registry::{Peer, RouteError};
use crate::relay;
use crate::{now_ms, AppState, RateLimiter};
use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use rda_proto::ids::DeviceId;
use rda_proto::signaling::{
    error_code, ConnectResponse, ConnectStatus, Envelope, ErrorPayload, Message, PeerGone,
    RegisterAck, Role, SignalingError,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Axum handler for `GET /ws`.
pub async fn handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.max_message_size(rda_proto::MAX_SIGNALING_MESSAGE)
        .on_upgrade(move |socket| connection(socket, state))
}

/// Per-connection state.
struct Conn {
    state: Arc<AppState>,
    tx: mpsc::UnboundedSender<Envelope>,
    challenge: Challenge,
    limiter: RateLimiter,
    identity: Option<DeviceId>,
    conn_id: u64,
    msg_counter: u64,
}

impl Conn {
    fn next_id(&mut self) -> String {
        self.msg_counter += 1;
        ulid::Ulid::new().to_string()
    }

    fn send(&mut self, sid: Option<String>, msg: Message) {
        let id = self.next_id();
        let _ = self.tx.send(Envelope::new(id, now_ms(), sid, msg));
    }

    fn send_error(&mut self, code: u16, message: &str, in_reply_to: Option<String>) {
        self.send(
            None,
            Message::Error(ErrorPayload {
                code,
                message: message.to_string(),
                in_reply_to,
                retry_after_s: (code == error_code::RATE_LIMITED).then_some(10),
            }),
        );
    }
}

async fn connection(socket: WebSocket, state: Arc<AppState>) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Envelope>();

    // Outbound pump. Kept separate so routing never blocks on a slow reader.
    let writer = tokio::spawn(async move {
        while let Some(env) = rx.recv().await {
            let Ok(bytes) = env.to_vec() else { continue };
            let Ok(text) = String::from_utf8(bytes) else {
                continue;
            };
            if sink.send(WsMessage::Text(text.into())).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    let conn_id = state.registry.next_conn_id();
    let mut conn = Conn {
        challenge: Challenge::issue(now_ms()),
        limiter: RateLimiter::new(state.config.rate_limit, state.config.rate_window_ms),
        tx: tx.clone(),
        state: state.clone(),
        identity: None,
        conn_id,
        msg_counter: 0,
    };

    // The challenge goes out before anything is accepted, so registration is always bound to a
    // nonce this server issued to this specific socket.
    let challenge_msg = Message::Challenge(rda_proto::signaling::Challenge {
        nonce: conn.challenge.nonce_b64(),
        server_time: now_ms(),
        min_client_version: None,
    });
    conn.send(None, challenge_msg);

    while let Some(Ok(frame)) = stream.next().await {
        let text = match frame {
            WsMessage::Text(t) => t,
            WsMessage::Binary(_) => {
                conn.send_error(
                    error_code::BAD_REQUEST,
                    "signaling frames must be text",
                    None,
                );
                continue;
            }
            WsMessage::Close(_) => break,
            // axum answers Ping automatically; Pong needs no action.
            WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
        };

        if !conn.limiter.allow(now_ms()) {
            warn!(conn_id, "rate limit exceeded, closing connection");
            conn.send_error(error_code::RATE_LIMITED, "too many messages", None);
            break;
        }

        match Envelope::from_slice(text.as_bytes()) {
            Ok(env) => {
                if !handle(&mut conn, env).await {
                    break;
                }
            }
            Err(e) => {
                let code = match e {
                    SignalingError::TooLarge(_) => error_code::MESSAGE_TOO_LARGE,
                    SignalingError::BadVersion(_) => error_code::UNSUPPORTED_VERSION,
                    SignalingError::Json(_) => error_code::BAD_REQUEST,
                };
                debug!(conn_id, error = %e, "rejected signaling message");
                conn.send_error(code, &e.to_string(), None);
            }
        }
    }

    teardown(&conn);
    drop(tx);
    let _ = writer.await;
}

/// Handles one message. Returns `false` to close the connection.
async fn handle(conn: &mut Conn, env: Envelope) -> bool {
    let reply_to = Some(env.id.clone());
    let sid = env.sid.clone();

    // Before registration the only thing that may be sent is a registration.
    let Some(identity) = conn.identity.clone() else {
        return match env.msg {
            Message::Register(reg) => register(conn, reg, reply_to),
            _ => {
                conn.send_error(error_code::NOT_REGISTERED, "register first", reply_to);
                true
            }
        };
    };

    match env.msg {
        Message::Register(_) => {
            conn.send_error(error_code::BAD_REQUEST, "already registered", reply_to);
        }
        Message::Heartbeat => conn.send(None, Message::HeartbeatAck),

        Message::ConnectRequest(req) => connect_request(conn, &identity, req, sid, reply_to),

        Message::ConnectResponse(resp) => connect_response(conn, &identity, resp, reply_to),

        // SDP, ICE and restarts are pure session-scoped forwards. The registry refuses to route
        // them unless the sender is genuinely a participant.
        Message::Offer(_)
        | Message::Answer(_)
        | Message::IceCandidate(_)
        | Message::IceRestart
        | Message::PeerGone(_) => {
            forward(conn, &identity, sid, env.msg, reply_to);
        }

        // Server-originated messages have no meaning inbound. Ignored rather than fatal, per the
        // forward-compatibility rule.
        Message::Challenge(_)
        | Message::RegisterAck(_)
        | Message::HeartbeatAck
        | Message::RelayCredentials(_)
        | Message::Error(_) => {
            debug!(
                conn_id = conn.conn_id,
                "ignoring server-originated message from client"
            );
        }
    }
    true
}

fn register(
    conn: &mut Conn,
    reg: rda_proto::signaling::Register,
    reply_to: Option<String>,
) -> bool {
    let device_id = reg.device_id.clone();
    let pubkey = match conn.challenge.verify(&reg, now_ms()) {
        Ok(pk) => pk,
        Err(e) => {
            let code = match e {
                AuthError::BadNonce => error_code::BAD_NONCE,
                _ => error_code::BAD_SIGNATURE,
            };
            warn!(%device_id, error = %e, "registration rejected");
            conn.send_error(code, &e.to_string(), reply_to);
            // A failed registration burns the nonce, so there is nothing left to retry on this
            // socket. Closing prevents an attacker holding sockets open to probe.
            return false;
        }
    };

    let peer = Peer {
        device_id: device_id.clone(),
        pubkey,
        role: reg.role,
        caps: reg.caps,
        agent: reg.agent,
        pop_rtt: reg.pop_rtt,
        tx: conn.tx.clone(),
        conn_id: conn.conn_id,
    };

    if let Some(displaced) = conn.state.registry.register(peer) {
        let id = ulid::Ulid::new().to_string();
        let _ = displaced.tx.send(Envelope::new(
            id,
            now_ms(),
            None,
            Message::PeerGone(PeerGone {
                reason: "replaced".into(),
            }),
        ));
    }

    conn.identity = Some(device_id.clone());
    info!(%device_id, role = ?reg.role, conn_id = conn.conn_id, "device registered");

    conn.send(
        None,
        Message::RegisterAck(RegisterAck {
            device_id,
            heartbeat_interval_s: conn.state.config.heartbeat_interval_s,
            session_ttl_s: conn.state.config.session_ttl_s,
        }),
    );
    true
}

fn connect_request(
    conn: &mut Conn,
    from: &DeviceId,
    req: rda_proto::signaling::ConnectRequest,
    _sid: Option<String>,
    reply_to: Option<String>,
) {
    let target = req.target.clone();
    let host = match conn.state.registry.resolve_target(&target) {
        Ok(peer) => peer,
        Err(e) => {
            debug!(%from, %target, error = %e, "connect_request could not be routed");
            // Offline and not-dialable are reported identically. Distinguishing them would turn
            // the ID space into an enumeration oracle (`docs/PROTOCOL.md` §3.3).
            conn.send(
                None,
                Message::ConnectResponse(ConnectResponse::refuse(ConnectStatus::Offline, None)),
            );
            let _ = reply_to;
            return;
        }
    };

    let session_id = format!("sess_{}", ulid::Ulid::new());
    let session = conn.state.registry.create_session(
        session_id.clone(),
        from.clone(),
        target.clone(),
        now_ms(),
    );

    // Relay selection uses both peers' measured latency vectors, so it can only happen here —
    // neither peer knows the other's numbers.
    let controller_rtt = conn
        .state
        .registry
        .get(from)
        .map(|p| p.pop_rtt)
        .unwrap_or_default();
    let ranked = relay::rank_pops(&conn.state.pops, &controller_rtt, &host.pop_rtt);
    let creds = relay::build_relay_credentials(
        &conn.state.pops,
        &ranked,
        &conn.state.config.turn_secret,
        &session.id,
        now_ms() / 1000,
        conn.state.config.relay_ttl_s,
    );

    info!(%from, %target, session = %session.id, best_pop = ?ranked.first(), "session created");

    let id = ulid::Ulid::new().to_string();
    let _ = host.tx.send(Envelope::new(
        id,
        now_ms(),
        Some(session.id.clone()),
        Message::ConnectRequest(req),
    ));

    conn.send(
        Some(session.id.clone()),
        Message::RelayCredentials(creds.clone()),
    );
    let id = ulid::Ulid::new().to_string();
    let _ = host.tx.send(Envelope::new(
        id,
        now_ms(),
        Some(session.id),
        Message::RelayCredentials(creds),
    ));
}

fn connect_response(
    conn: &mut Conn,
    from: &DeviceId,
    resp: ConnectResponse,
    reply_to: Option<String>,
) {
    let Some(session_id) = resp.session_id.clone() else {
        conn.send_error(
            error_code::BAD_REQUEST,
            "connect_response needs a session_id",
            reply_to,
        );
        return;
    };
    let accepted = resp.status == ConnectStatus::Accepted;
    let env = Envelope::new(
        ulid::Ulid::new().to_string(),
        now_ms(),
        Some(session_id.clone()),
        Message::ConnectResponse(resp),
    );
    if let Err(e) = conn
        .state
        .registry
        .forward_in_session(&session_id, from, env)
    {
        route_error(conn, e, reply_to);
        return;
    }
    if !accepted {
        // A refusal ends the session immediately; leaving it live would let the controller keep
        // pushing SDP at a host that already said no.
        conn.state.registry.end_session(&session_id);
    }
}

fn forward(
    conn: &mut Conn,
    from: &DeviceId,
    sid: Option<String>,
    msg: Message,
    reply_to: Option<String>,
) {
    let Some(session_id) = sid else {
        conn.send_error(
            error_code::BAD_REQUEST,
            "message requires a session id",
            reply_to,
        );
        return;
    };
    let env = Envelope::new(
        ulid::Ulid::new().to_string(),
        now_ms(),
        Some(session_id.clone()),
        msg,
    );
    if let Err(e) = conn
        .state
        .registry
        .forward_in_session(&session_id, from, env)
    {
        route_error(conn, e, reply_to);
    }
}

fn route_error(conn: &mut Conn, e: RouteError, reply_to: Option<String>) {
    let code = match e {
        RouteError::UnknownSession | RouteError::NotAParticipant => error_code::UNKNOWN_TARGET,
        RouteError::NotConnected | RouteError::QueueClosed => error_code::UNKNOWN_TARGET,
        RouteError::NotDialable => error_code::CAPABILITY_DENIED,
    };
    debug!(error = %e, "routing failed");
    conn.send_error(code, &e.to_string(), reply_to);
}

/// Cleans up when a connection ends: deregister, and tell every session peer the other end left.
fn teardown(conn: &Conn) {
    let Some(device_id) = conn.identity.clone() else {
        return;
    };

    // Guarded by conn_id so a slow teardown cannot deregister the reconnection that replaced it.
    if !conn.state.registry.unregister(&device_id, conn.conn_id) {
        debug!(%device_id, "connection superseded before teardown; leaving registry intact");
        return;
    }

    for session in conn.state.registry.sessions_for(&device_id) {
        if let Some(peer_id) = session.peer_of(&device_id) {
            let env = Envelope::new(
                ulid::Ulid::new().to_string(),
                now_ms(),
                Some(session.id.clone()),
                Message::PeerGone(PeerGone {
                    reason: "disconnected".into(),
                }),
            );
            let _ = conn.state.registry.send_to(peer_id, env);
        }
        conn.state.registry.end_session(&session.id);
    }
    info!(%device_id, conn_id = conn.conn_id, "device disconnected");
}

/// Roles that may be dialled, exposed for diagnostics.
#[must_use]
pub fn dialable_roles() -> [Role; 2] {
    [Role::Host, Role::Both]
}
