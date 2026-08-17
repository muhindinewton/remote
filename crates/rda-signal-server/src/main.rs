//! Signaling server binary.
//!
//! TLS is deliberately **not** terminated here. Run this behind a reverse proxy that owns the
//! certificate; `docs/PROTOCOL.md` §3.1 requires `wss://` in production, and putting certificate
//! handling in the same process as the routing logic buys nothing and complicates rotation.

use anyhow::Context;
use rda_signal_server::{router, AppState, Config};
use std::net::SocketAddr;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// Probes the local health endpoint and exits 0 or 1.
///
/// Implemented in the binary rather than shelling out to `curl` so the runtime image needs no HTTP
/// client — one less package, one less thing to keep patched, and a smaller image to pull onto
/// every PoP.
fn health_check(addr: &str) -> anyhow::Result<()> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let mut stream =
        TcpStream::connect(addr).with_context(|| format!("could not connect to {addr}"))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    if response.starts_with("HTTP/1.1 200") {
        Ok(())
    } else {
        anyhow::bail!(
            "health endpoint returned: {}",
            response.lines().next().unwrap_or("<empty>")
        )
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("RDA_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let bind = std::env::var("RDA_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    // Docker's HEALTHCHECK runs the same binary with this flag, so there is no second image layer
    // and no drift between what is deployed and what is probed.
    if std::env::args().any(|a| a == "--health-check") {
        let probe = bind.replace("0.0.0.0", "127.0.0.1");
        return health_check(&probe);
    }

    let config = Config::from_env();
    if config.has_default_turn_secret() {
        warn!(
            "RDA_TURN_SECRET is unset — using the built-in placeholder. \
             TURN credentials minted with it are forgeable by anyone reading this source. \
             Set it before exposing this server."
        );
    }

    let addr: SocketAddr = bind
        .parse()
        .context("RDA_BIND must be a socket address such as 0.0.0.0:8080")?;

    let state = AppState::new(config);
    info!(
        %addr,
        domain = %state.config.domain,
        pops = state.pops.len(),
        "signaling server starting"
    );

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;

    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    info!("signaling server stopped");
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("shutdown signal received");
}
