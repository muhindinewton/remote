//! Rendezvous and signaling server — `docs/PROTOCOL.md` §3.
//!
//! What this server is trusted with, and what it is not, is the load-bearing distinction:
//!
//! - **Trusted with routing.** It decides which socket a message reaches. A bug here delivers a
//!   session to the wrong device, so [`registry`] enforces participation on every forward.
//! - **Not trusted with content.** It can read the SDP, and therefore the DTLS fingerprints — but
//!   substituting one gains it nothing, because the peers bind their fingerprints to their identity
//!   keys by signature and verify that binding peer-to-peer (`docs/PROTOCOL.md` §4.3).
//!
//! Operators should assume the server is compromised and design accordingly. That assumption is
//! what makes it acceptable to run relays and rendezvous in jurisdictions you do not control.

#![forbid(unsafe_code)]

pub mod auth;
pub mod registry;
pub mod relay;
pub mod ws;

use axum::routing::{get, MethodRouter};
use axum::Router;
use registry::Registry;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Server configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Base domain used to construct PoP STUN/TURN URLs.
    pub domain: String,
    /// Shared secret for TURN REST credential minting. Must match the relays' `static-auth-secret`.
    pub turn_secret: Vec<u8>,
    /// How often clients must heartbeat, in seconds.
    pub heartbeat_interval_s: u32,
    /// How long a registration survives without a heartbeat, in seconds.
    pub session_ttl_s: u32,
    /// TURN credential lifetime, in seconds. Capped at one hour.
    pub relay_ttl_s: u32,
    /// Maximum signaling messages per connection per [`Config::rate_window_ms`].
    pub rate_limit: u32,
    /// Rate limiting window, in milliseconds.
    pub rate_window_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            domain: "example.net".to_string(),
            turn_secret: b"CHANGE-ME-IN-PRODUCTION".to_vec(),
            // 30 s is ample at 220 ms RTT, and a shorter interval only costs mobile battery.
            heartbeat_interval_s: 30,
            session_ttl_s: 86_400,
            relay_ttl_s: 3600,
            // Generous for honest clients: registration, one connect, an SDP exchange and ~20
            // trickled candidates is well under 60 messages in 10 s.
            rate_limit: 60,
            rate_window_ms: 10_000,
        }
    }
}

impl Config {
    /// Loads configuration from the environment, falling back to defaults.
    #[must_use]
    pub fn from_env() -> Self {
        let mut cfg = Config::default();
        if let Ok(d) = std::env::var("RDA_DOMAIN") {
            cfg.domain = d;
        }
        if let Ok(s) = std::env::var("RDA_TURN_SECRET") {
            cfg.turn_secret = s.into_bytes();
        }
        cfg
    }

    /// Returns `true` if the TURN secret is still the built-in placeholder.
    #[must_use]
    pub fn has_default_turn_secret(&self) -> bool {
        self.turn_secret == b"CHANGE-ME-IN-PRODUCTION"
    }
}

/// Shared application state.
#[derive(Debug)]
pub struct AppState {
    /// Device registry and session routing.
    pub registry: Arc<Registry>,
    /// Server configuration.
    pub config: Config,
    /// The PoP fleet offered to clients.
    pub pops: Vec<relay::Pop>,
}

impl AppState {
    /// Builds state from a configuration.
    #[must_use]
    pub fn new(config: Config) -> Arc<Self> {
        let pops = relay::default_pops(&config.domain);
        Arc::new(Self {
            registry: Registry::new(),
            config,
            pops,
        })
    }
}

/// Builds the HTTP router.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/ws", get(ws::handler))
        .route("/healthz", health_route())
        .with_state(state)
}

fn health_route() -> MethodRouter<Arc<AppState>> {
    get(
        |axum::extract::State(state): axum::extract::State<Arc<AppState>>| async move {
            axum::Json(serde_json::json!({
                "status": "ok",
                "peers": state.registry.peer_count(),
                "sessions": state.registry.session_count(),
            }))
        },
    )
}

/// Current Unix time in milliseconds.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A fixed-window rate limiter.
///
/// Deliberately per connection rather than per IP: the pre-authentication surface is what needs
/// bounding, and a shared-NAT IP (extremely common on Kenyan mobile networks) must not let one
/// user's traffic throttle another's.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    limit: u32,
    window_ms: u64,
    window_start: u64,
    count: u32,
}

impl RateLimiter {
    /// Builds a limiter permitting `limit` events per `window_ms`.
    #[must_use]
    pub fn new(limit: u32, window_ms: u64) -> Self {
        Self {
            limit,
            window_ms,
            window_start: 0,
            count: 0,
        }
    }

    /// Records an event. Returns `false` if the caller has exceeded its budget.
    pub fn allow(&mut self, now_ms: u64) -> bool {
        if now_ms.saturating_sub(self.window_start) > self.window_ms {
            self.window_start = now_ms;
            self.count = 0;
        }
        self.count += 1;
        self.count <= self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_permits_then_blocks_then_resets() {
        let mut r = RateLimiter::new(3, 1000);
        assert!(r.allow(0));
        assert!(r.allow(100));
        assert!(r.allow(200));
        assert!(!r.allow(300), "fourth event in the window must be refused");
        assert!(r.allow(2000), "a new window restores the budget");
    }

    #[test]
    fn default_turn_secret_is_detectable() {
        assert!(Config::default().has_default_turn_secret());
        let cfg = Config {
            turn_secret: b"real".to_vec(),
            ..Config::default()
        };
        assert!(!cfg.has_default_turn_secret());
    }
}
