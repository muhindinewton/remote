//! ICE policy — `docs/ARCHITECTURE.md` §1.4.
//!
//! Two decisions here are corridor-specific and differ from WebRTC defaults:
//!
//! 1. **Relay candidates are capped at two PoPs.** Every relay candidate multiplies the
//!    connectivity-check matrix, and each check round costs an RTT. On a 220 ms path an
//!    over-generous candidate list turns a two-second connection into a ten-second one.
//! 2. **We prefer a direct path hard, then give up fast.** Waiting indefinitely for hole punching
//!    to succeed is worse than relaying: a user staring at a connecting spinner has no idea we are
//!    optimising for them.

use rda_proto::signaling::{IceServer, RelayCredentials, MAX_RELAY_POPS};
use std::time::Duration;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::policy::bundle_policy::RTCBundlePolicy;
use webrtc::peer_connection::policy::ice_transport_policy::RTCIceTransportPolicy;
use webrtc::peer_connection::policy::rtcp_mux_policy::RTCRtcpMuxPolicy;

/// How long to hold out for a peer-to-peer candidate pair before accepting a relayed one.
///
/// Three seconds is roughly a dozen check rounds at 220 ms RTT — enough for hole punching to work
/// where it is going to work, and short enough that a user does not conclude the product is broken.
pub const P2P_GRACE: Duration = Duration::from_secs(3);

/// Total time to establish any working candidate pair before the attempt fails.
pub const ICE_TIMEOUT: Duration = Duration::from_secs(15);

/// How the session should route media.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RoutingPreference {
    /// Try direct first, fall back to relay. The default.
    #[default]
    PreferDirect,
    /// Never expose peer IP addresses to the other side; always relay.
    ///
    /// Costs 20–40 ms and some relay bandwidth. Offered because a successful P2P connection reveals
    /// each peer's IP to the other, which users are rarely expecting
    /// (`docs/ARCHITECTURE.md` §5.6).
    ForceRelay,
}

impl RoutingPreference {
    fn policy(self) -> RTCIceTransportPolicy {
        match self {
            RoutingPreference::PreferDirect => RTCIceTransportPolicy::All,
            RoutingPreference::ForceRelay => RTCIceTransportPolicy::Relay,
        }
    }
}

/// Builds the peer connection configuration from server-supplied relay credentials.
///
/// Truncates the TURN entries to [`MAX_RELAY_POPS`] even if the server sent more, so a
/// misconfigured or hostile server cannot inflate our candidate list and slow every connection down.
#[must_use]
pub fn build_configuration(
    creds: &RelayCredentials,
    preference: RoutingPreference,
) -> RTCConfiguration {
    let mut ice_servers = Vec::new();
    let mut relay_count = 0usize;

    for server in &creds.ice_servers {
        let is_relay = server.username.is_some();
        if is_relay {
            if relay_count >= MAX_RELAY_POPS {
                continue;
            }
            relay_count += 1;
        }
        ice_servers.push(to_rtc_ice_server(server));
    }

    RTCConfiguration {
        ice_servers,
        ice_transport_policy: preference.policy(),
        // BUNDLE everything onto one transport: one ICE handshake, one DTLS handshake, one NAT
        // binding to keep alive. Separate transports would multiply the setup cost by the number
        // of media lines.
        bundle_policy: RTCBundlePolicy::MaxBundle,
        rtcp_mux_policy: RTCRtcpMuxPolicy::Require,
        ..Default::default()
    }
}

fn to_rtc_ice_server(server: &IceServer) -> RTCIceServer {
    RTCIceServer {
        urls: server.urls.clone(),
        username: server.username.clone().unwrap_or_default(),
        credential: server.credential.clone().unwrap_or_default(),
    }
}

/// Classification of a negotiated candidate pair, for telemetry and UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// Both peers on the same network.
    HostToHost,
    /// UDP hole punching succeeded. The good case.
    ServerReflexive,
    /// Traffic is going through a TURN relay.
    Relayed,
    /// Not yet determined.
    Unknown,
}

impl PathKind {
    /// Classifies a pair from the ICE candidate type strings.
    #[must_use]
    pub fn classify(local: &str, remote: &str) -> Self {
        if local == "relay" || remote == "relay" {
            PathKind::Relayed
        } else if local == "host" && remote == "host" {
            PathKind::HostToHost
        } else if matches!(local, "srflx" | "prflx" | "host")
            && matches!(remote, "srflx" | "prflx" | "host")
        {
            PathKind::ServerReflexive
        } else {
            PathKind::Unknown
        }
    }

    /// Returns `true` if media is traversing a relay.
    #[must_use]
    pub fn is_relayed(self) -> bool {
        matches!(self, PathKind::Relayed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(relay_pops: usize) -> RelayCredentials {
        let mut ice_servers = vec![IceServer {
            urls: vec!["stun:stun.example.net:3478".into()],
            username: None,
            credential: None,
        }];
        for i in 0..relay_pops {
            ice_servers.push(IceServer {
                urls: vec![format!("turn:turn{i}.example.net:3478?transport=udp")],
                username: Some("user".into()),
                credential: Some("pass".into()),
            });
        }
        RelayCredentials {
            ice_servers,
            ttl_s: 3600,
            preferred_order: vec![],
        }
    }

    #[test]
    fn relay_candidates_are_capped_even_if_the_server_sends_more() {
        // A server that hands out eight relays would multiply the ICE check matrix and add seconds
        // to every connection on this corridor.
        let cfg = build_configuration(&creds(8), RoutingPreference::PreferDirect);
        let relays = cfg
            .ice_servers
            .iter()
            .filter(|s| !s.username.is_empty())
            .count();
        assert_eq!(relays, MAX_RELAY_POPS);
    }

    #[test]
    fn stun_servers_are_never_capped() {
        let cfg = build_configuration(&creds(0), RoutingPreference::PreferDirect);
        assert_eq!(cfg.ice_servers.len(), 1);
    }

    #[test]
    fn force_relay_sets_the_relay_only_policy() {
        let cfg = build_configuration(&creds(2), RoutingPreference::ForceRelay);
        assert_eq!(cfg.ice_transport_policy, RTCIceTransportPolicy::Relay);
        let cfg = build_configuration(&creds(2), RoutingPreference::PreferDirect);
        assert_eq!(cfg.ice_transport_policy, RTCIceTransportPolicy::All);
    }

    #[test]
    fn bundling_and_rtcp_mux_are_required() {
        // Both save round trips and NAT bindings; neither is the webrtc-rs default in every path.
        let cfg = build_configuration(&creds(1), RoutingPreference::PreferDirect);
        assert_eq!(cfg.bundle_policy, RTCBundlePolicy::MaxBundle);
        assert_eq!(cfg.rtcp_mux_policy, RTCRtcpMuxPolicy::Require);
    }

    #[test]
    fn path_classification_flags_relayed_traffic() {
        assert_eq!(PathKind::classify("host", "host"), PathKind::HostToHost);
        assert_eq!(
            PathKind::classify("srflx", "srflx"),
            PathKind::ServerReflexive
        );
        assert_eq!(
            PathKind::classify("host", "srflx"),
            PathKind::ServerReflexive
        );
        // One relayed end is enough to make the whole path relayed.
        assert!(PathKind::classify("relay", "srflx").is_relayed());
        assert!(PathKind::classify("srflx", "relay").is_relayed());
        assert!(!PathKind::classify("srflx", "prflx").is_relayed());
    }

    #[test]
    fn grace_period_allows_several_check_rounds_at_corridor_rtt() {
        // The 3 s budget must be worth at least ~10 checks at 250 ms, or hole punching never gets
        // a fair chance before we fall back to a relay.
        let rounds = P2P_GRACE.as_millis() / 250;
        assert!(
            rounds >= 10,
            "only {rounds} check rounds fit in the grace period"
        );
        assert!(ICE_TIMEOUT > P2P_GRACE);
    }
}
