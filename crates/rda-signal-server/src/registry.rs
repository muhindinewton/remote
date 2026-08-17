//! Device registry, presence and session routing.
//!
//! Deliberately free of any network or axum dependency so the routing rules — which are where the
//! interesting mistakes live — can be unit-tested directly.
//!
//! The server is untrusted with session *content*, but it is fully trusted with *routing*. A bug
//! here delivers a session to the wrong device, so the invariants are enforced in one place.

use dashmap::DashMap;
use rda_proto::caps::Capabilities;
use rda_proto::ids::DeviceId;
use rda_proto::signaling::{Envelope, Role};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// A registered, connected device.
#[derive(Debug, Clone)]
pub struct Peer {
    /// Identifier, verified against `pubkey` at registration.
    pub device_id: DeviceId,
    /// Ed25519 identity public key.
    pub pubkey: [u8; 32],
    /// What the device registered as.
    pub role: Role,
    /// Advertised capabilities.
    pub caps: Capabilities,
    /// Free-form agent string.
    pub agent: Option<String>,
    /// PoP code → median RTT, from the device's own probes.
    pub pop_rtt: BTreeMap<String, u32>,
    /// Outbound queue to this device's WebSocket task.
    pub tx: mpsc::UnboundedSender<Envelope>,
    /// Monotonic connection identifier, so a stale task cannot evict its own replacement.
    pub conn_id: u64,
}

/// An in-progress session between a controller and a host.
#[derive(Debug, Clone)]
pub struct Session {
    /// Session identifier.
    pub id: String,
    /// The controlling device.
    pub controller: DeviceId,
    /// The host device.
    pub host: DeviceId,
    /// Creation time, Unix milliseconds.
    pub created_ms: u64,
}

impl Session {
    /// Returns the other end of the session, or `None` if `from` is not a participant.
    ///
    /// Returning `None` rather than guessing is the whole point: it is what stops a device that
    /// learned a session id from routing messages into a session it does not belong to.
    #[must_use]
    pub fn peer_of(&self, from: &DeviceId) -> Option<&DeviceId> {
        if from == &self.controller {
            Some(&self.host)
        } else if from == &self.host {
            Some(&self.controller)
        } else {
            None
        }
    }
}

/// Why a send to a peer failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RouteError {
    /// No such device is connected.
    #[error("target device is not connected")]
    NotConnected,
    /// The device exists but is not accepting connections in this role.
    #[error("target device is not dialable")]
    NotDialable,
    /// The sender is not a participant in the session it named.
    #[error("sender is not a participant in that session")]
    NotAParticipant,
    /// No such session.
    #[error("unknown session")]
    UnknownSession,
    /// The peer's outbound queue is closed; its socket is going away.
    #[error("peer queue closed")]
    QueueClosed,
}

/// Shared server state.
#[derive(Debug, Default)]
pub struct Registry {
    peers: DashMap<DeviceId, Peer>,
    sessions: DashMap<String, Session>,
    next_conn_id: AtomicU64,
}

impl Registry {
    /// A fresh, empty registry.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Allocates a connection identifier.
    pub fn next_conn_id(&self) -> u64 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Registers a device, replacing any previous connection for the same identity.
    ///
    /// Returns the displaced peer so the caller can tell it why it was evicted. Last-writer-wins is
    /// correct here: a device that reconnects after a network change must not be locked out by its
    /// own half-dead previous socket, which the server cannot distinguish from a live one until a
    /// heartbeat times out.
    pub fn register(&self, peer: Peer) -> Option<Peer> {
        self.peers.insert(peer.device_id.clone(), peer)
    }

    /// Removes a device, but only if it is still the connection identified by `conn_id`.
    ///
    /// The guard matters: without it, a slow teardown of an old socket deregisters the new one that
    /// has already replaced it, and the device silently vanishes from presence.
    pub fn unregister(&self, device_id: &DeviceId, conn_id: u64) -> bool {
        let should_remove = self
            .peers
            .get(device_id)
            .map(|p| p.conn_id == conn_id)
            .unwrap_or(false);
        if should_remove {
            self.peers.remove(device_id);
        }
        should_remove
    }

    /// Looks up a connected device.
    #[must_use]
    pub fn get(&self, device_id: &DeviceId) -> Option<Peer> {
        self.peers.get(device_id).map(|p| p.clone())
    }

    /// Number of connected devices.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Number of live sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Sends an envelope directly to a device.
    pub fn send_to(&self, device_id: &DeviceId, env: Envelope) -> Result<(), RouteError> {
        let peer = self.peers.get(device_id).ok_or(RouteError::NotConnected)?;
        peer.tx.send(env).map_err(|_| RouteError::QueueClosed)
    }

    /// Resolves a dial target, refusing devices that did not register as dialable.
    pub fn resolve_target(&self, target: &DeviceId) -> Result<Peer, RouteError> {
        let peer = self.peers.get(target).ok_or(RouteError::NotConnected)?;
        if !peer.role.is_dialable() {
            return Err(RouteError::NotDialable);
        }
        Ok(peer.clone())
    }

    /// Creates a session between two devices.
    pub fn create_session(
        &self,
        id: String,
        controller: DeviceId,
        host: DeviceId,
        now_ms: u64,
    ) -> Session {
        let session = Session {
            id: id.clone(),
            controller,
            host,
            created_ms: now_ms,
        };
        self.sessions.insert(id, session.clone());
        session
    }

    /// Looks up a session.
    #[must_use]
    pub fn session(&self, id: &str) -> Option<Session> {
        self.sessions.get(id).map(|s| s.clone())
    }

    /// Ends a session and returns it.
    pub fn end_session(&self, id: &str) -> Option<Session> {
        self.sessions.remove(id).map(|(_, s)| s)
    }

    /// Every session a device participates in.
    #[must_use]
    pub fn sessions_for(&self, device_id: &DeviceId) -> Vec<Session> {
        self.sessions
            .iter()
            .filter(|s| s.controller == *device_id || s.host == *device_id)
            .map(|s| s.clone())
            .collect()
    }

    /// Forwards a session-scoped message to the other participant.
    ///
    /// This is the one routing path that carries SDP and ICE, so it enforces the two invariants
    /// that matter: the session must exist, and the sender must actually be in it.
    pub fn forward_in_session(
        &self,
        session_id: &str,
        from: &DeviceId,
        env: Envelope,
    ) -> Result<DeviceId, RouteError> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or(RouteError::UnknownSession)?;
        let peer_id = session
            .peer_of(from)
            .ok_or(RouteError::NotAParticipant)?
            .clone();
        drop(session);
        self.send_to(&peer_id, env)?;
        Ok(peer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rda_proto::ids::device_id_from_pubkey;
    use rda_proto::signaling::Message;

    fn make_peer(seed: u8, role: Role, conn_id: u64) -> (Peer, mpsc::UnboundedReceiver<Envelope>) {
        let pubkey = [seed; 32];
        let (tx, rx) = mpsc::unbounded_channel();
        let peer = Peer {
            device_id: device_id_from_pubkey(&pubkey),
            pubkey,
            role,
            caps: Capabilities::new(),
            agent: None,
            pop_rtt: BTreeMap::new(),
            tx,
            conn_id,
        };
        (peer, rx)
    }

    fn envelope() -> Envelope {
        Envelope::new("m1", 0, None, Message::Heartbeat)
    }

    #[test]
    fn registration_and_lookup() {
        let reg = Registry::new();
        let (peer, _rx) = make_peer(1, Role::Host, 1);
        let id = peer.device_id.clone();
        assert!(reg.register(peer).is_none());
        assert_eq!(reg.peer_count(), 1);
        assert!(reg.get(&id).is_some());
    }

    #[test]
    fn reconnect_displaces_the_old_connection() {
        let reg = Registry::new();
        let (p1, _rx1) = make_peer(1, Role::Host, 1);
        let (p2, _rx2) = make_peer(1, Role::Host, 2);
        let id = p1.device_id.clone();
        reg.register(p1);
        let displaced = reg
            .register(p2)
            .expect("previous connection must be returned");
        assert_eq!(displaced.conn_id, 1);
        assert_eq!(reg.get(&id).unwrap().conn_id, 2);
    }

    #[test]
    fn a_stale_teardown_cannot_deregister_its_replacement() {
        // The bug this prevents: an old socket's cleanup runs after a reconnect and silently
        // removes the live connection, so the device disappears from presence until it retries.
        let reg = Registry::new();
        let (p1, _rx1) = make_peer(1, Role::Host, 1);
        let (p2, _rx2) = make_peer(1, Role::Host, 2);
        let id = p1.device_id.clone();
        reg.register(p1);
        reg.register(p2);

        assert!(
            !reg.unregister(&id, 1),
            "stale conn_id must not remove the current peer"
        );
        assert!(reg.get(&id).is_some());
        assert!(reg.unregister(&id, 2));
        assert!(reg.get(&id).is_none());
    }

    #[test]
    fn controllers_are_not_dialable() {
        let reg = Registry::new();
        let (peer, _rx) = make_peer(2, Role::Controller, 1);
        let id = peer.device_id.clone();
        reg.register(peer);
        assert_eq!(
            reg.resolve_target(&id).unwrap_err(),
            RouteError::NotDialable
        );
    }

    #[test]
    fn unknown_target_is_reported_as_not_connected() {
        let reg = Registry::new();
        let missing = device_id_from_pubkey(&[9u8; 32]);
        assert_eq!(
            reg.resolve_target(&missing).unwrap_err(),
            RouteError::NotConnected
        );
    }

    #[tokio::test]
    async fn session_forwarding_reaches_the_other_participant() {
        let reg = Registry::new();
        let (host, mut host_rx) = make_peer(1, Role::Host, 1);
        let (ctrl, mut ctrl_rx) = make_peer(2, Role::Controller, 2);
        let host_id = host.device_id.clone();
        let ctrl_id = ctrl.device_id.clone();
        reg.register(host);
        reg.register(ctrl);
        reg.create_session("sess_1".into(), ctrl_id.clone(), host_id.clone(), 0);

        let to = reg
            .forward_in_session("sess_1", &ctrl_id, envelope())
            .unwrap();
        assert_eq!(to, host_id);
        assert!(host_rx.recv().await.is_some());

        let to = reg
            .forward_in_session("sess_1", &host_id, envelope())
            .unwrap();
        assert_eq!(to, ctrl_id);
        assert!(ctrl_rx.recv().await.is_some());
    }

    #[test]
    fn an_outsider_cannot_inject_into_a_session() {
        // Knowing a session id must not be enough to inject SDP or ICE into it — otherwise a
        // leaked identifier becomes a session hijack.
        let reg = Registry::new();
        let (host, _h) = make_peer(1, Role::Host, 1);
        let (ctrl, _c) = make_peer(2, Role::Controller, 2);
        let (evil, _e) = make_peer(3, Role::Controller, 3);
        let (host_id, ctrl_id, evil_id) = (
            host.device_id.clone(),
            ctrl.device_id.clone(),
            evil.device_id.clone(),
        );
        reg.register(host);
        reg.register(ctrl);
        reg.register(evil);
        reg.create_session("sess_1".into(), ctrl_id, host_id, 0);

        assert_eq!(
            reg.forward_in_session("sess_1", &evil_id, envelope()),
            Err(RouteError::NotAParticipant)
        );
    }

    #[test]
    fn unknown_session_is_rejected() {
        let reg = Registry::new();
        let (ctrl, _c) = make_peer(2, Role::Controller, 1);
        let id = ctrl.device_id.clone();
        reg.register(ctrl);
        assert_eq!(
            reg.forward_in_session("nope", &id, envelope()),
            Err(RouteError::UnknownSession)
        );
    }

    #[test]
    fn sessions_for_finds_both_roles_and_end_removes() {
        let reg = Registry::new();
        let ctrl_id = device_id_from_pubkey(&[2u8; 32]);
        let host_id = device_id_from_pubkey(&[1u8; 32]);
        reg.create_session("s1".into(), ctrl_id.clone(), host_id.clone(), 0);
        reg.create_session("s2".into(), ctrl_id.clone(), host_id.clone(), 0);

        assert_eq!(reg.sessions_for(&ctrl_id).len(), 2);
        assert_eq!(reg.sessions_for(&host_id).len(), 2);
        assert!(reg.end_session("s1").is_some());
        assert_eq!(reg.session_count(), 1);
        assert!(reg.end_session("s1").is_none());
    }

    #[test]
    fn peer_of_rejects_non_participants() {
        let s = Session {
            id: "s".into(),
            controller: device_id_from_pubkey(&[2u8; 32]),
            host: device_id_from_pubkey(&[1u8; 32]),
            created_ms: 0,
        };
        assert_eq!(s.peer_of(&s.controller), Some(&s.host));
        assert_eq!(s.peer_of(&s.host), Some(&s.controller));
        assert_eq!(s.peer_of(&device_id_from_pubkey(&[7u8; 32])), None);
    }
}
