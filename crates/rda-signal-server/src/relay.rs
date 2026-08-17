//! PoP configuration, relay selection and TURN credential minting.
//!
//! Implements the relay-selection algorithm in `docs/ARCHITECTURE.md` §1.4. The selection is a pure
//! function of measured latency vectors, so it is testable without deploying anything.

use base64::Engine as _;
use hmac::{Hmac, Mac};
use rda_proto::signaling::{IceServer, RelayCredentials, MAX_RELAY_POPS};
use sha1::Sha1;
use std::collections::BTreeMap;

type HmacSha1 = Hmac<Sha1>;

/// One point of presence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pop {
    /// Short code, e.g. `mrs`. Clients report probe results keyed by this.
    pub code: String,
    /// Human-readable location.
    pub location: String,
    /// STUN URL.
    pub stun_url: String,
    /// TURN URLs, UDP first then a TLS fallback for restrictive networks.
    pub turn_urls: Vec<String>,
}

/// The default PoP fleet for the US ↔ Kenya corridor — `docs/ARCHITECTURE.md` §1.4.
///
/// Marseille rather than Johannesburg is the primary midpoint: PEACE and SEACOM both run
/// Mombasa → Suez → Mediterranean → France, so European PoPs sit on the path traffic already
/// takes. A Johannesburg relay is only justified once measurement proves a direct Nairobi
/// path, which is carrier-dependent.
/// An empty domain means no relay fleet, not a fleet with malformed URLs. That is a real
/// deployment — a LAN, or a self-hoster who has not stood up TURN yet — and it matters that it
/// produces zero ICE servers: peers spend real time resolving and probing every URL they are
/// given, so handing out unreachable ones is worse than handing out none.
#[must_use]
pub fn default_pops(domain: &str) -> Vec<Pop> {
    if domain.is_empty() {
        return Vec::new();
    }
    ["iad", "mrs", "lhr", "nbo"]
        .into_iter()
        .zip(["US-East Ashburn", "Marseille", "London", "Nairobi"])
        .map(|(code, location)| Pop {
            code: code.to_string(),
            location: location.to_string(),
            stun_url: format!("stun:stun.{code}.{domain}:3478"),
            turn_urls: vec![
                format!("turn:turn.{code}.{domain}:3478?transport=udp"),
                format!("turns:turn.{code}.{domain}:5349?transport=tcp"),
            ],
        })
        .collect()
}

/// Ranks PoPs for one pair of peers, best first.
///
/// Scores each PoP by `rtt_controller_to_pop + rtt_pop_to_host`, which is the actual cost of
/// relaying through it. A PoP neither peer has measured is ranked last rather than dropped, so a
/// client that failed to probe still gets a usable list.
#[must_use]
pub fn rank_pops(
    pops: &[Pop],
    controller_rtt: &BTreeMap<String, u32>,
    host_rtt: &BTreeMap<String, u32>,
) -> Vec<String> {
    const UNMEASURED: u32 = 10_000;
    let mut scored: Vec<(u32, &str)> = pops
        .iter()
        .map(|p| {
            let c = controller_rtt.get(&p.code).copied().unwrap_or(UNMEASURED);
            let h = host_rtt.get(&p.code).copied().unwrap_or(UNMEASURED);
            (c.saturating_add(h), p.code.as_str())
        })
        .collect();
    // Ties broken by code so the ordering is deterministic across restarts; a relay list that
    // reshuffles on every reconnect makes latency regressions impossible to attribute.
    scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
    scored
        .into_iter()
        .map(|(_, code)| code.to_string())
        .collect()
}

/// Mints time-limited TURN credentials using the standard REST mechanism.
///
/// `username = "<unix_expiry>:<session_id>"`, `credential = base64(HMAC-SHA1(secret, username))`.
/// This is coturn's `use-auth-secret` scheme, so the shared secret never leaves the server and the
/// relay needs no per-user database.
#[must_use]
pub fn mint_turn_credential(secret: &[u8], session_id: &str, expiry_unix: u64) -> (String, String) {
    let username = format!("{expiry_unix}:{session_id}");
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(username.as_bytes());
    let credential = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    (username, credential)
}

/// Builds the ICE server list for one session.
///
/// Only the top [`MAX_RELAY_POPS`] entries get TURN credentials. Every extra relay candidate
/// multiplies the ICE connectivity-check matrix, and on a 220 ms path each check round costs a
/// fifth of a second — so the cap is a latency decision, not a cost decision. STUN is offered from
/// every PoP because server-reflexive gathering is cheap and improves the odds of a direct path.
#[must_use]
pub fn build_relay_credentials(
    pops: &[Pop],
    ranked: &[String],
    secret: &[u8],
    session_id: &str,
    now_unix: u64,
    ttl_s: u32,
) -> RelayCredentials {
    let ttl_s = ttl_s.min(3600); // §3.3: credentials never live longer than an hour.
    let expiry = now_unix + u64::from(ttl_s);
    let (username, credential) = mint_turn_credential(secret, session_id, expiry);

    let by_code: BTreeMap<&str, &Pop> = pops.iter().map(|p| (p.code.as_str(), p)).collect();
    let mut servers = Vec::new();

    servers.push(IceServer {
        urls: pops.iter().map(|p| p.stun_url.clone()).collect(),
        username: None,
        credential: None,
    });

    for code in ranked.iter().take(MAX_RELAY_POPS) {
        if let Some(pop) = by_code.get(code.as_str()) {
            servers.push(IceServer {
                urls: pop.turn_urls.clone(),
                username: Some(username.clone()),
                credential: Some(credential.clone()),
            });
        }
    }

    RelayCredentials {
        ice_servers: servers,
        ttl_s,
        preferred_order: ranked.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rtt(pairs: &[(&str, u32)]) -> BTreeMap<String, u32> {
        pairs.iter().map(|(k, v)| ((*k).to_string(), *v)).collect()
    }

    #[test]
    fn ranking_picks_the_true_midpoint_not_the_map_midpoint() {
        let pops = default_pops("example.net");
        // A realistic US-East controller and a Nairobi host.
        let controller = rtt(&[("iad", 8), ("mrs", 95), ("lhr", 78), ("nbo", 235)]);
        let host = rtt(&[("iad", 240), ("mrs", 100), ("lhr", 118), ("nbo", 6)]);

        let ranked = rank_pops(&pops, &controller, &host);
        // mrs = 195, lhr = 196, iad = 248, nbo = 241.
        assert_eq!(
            ranked[0], "mrs",
            "Marseille sits on the path the traffic already takes"
        );
        assert_eq!(ranked[1], "lhr");
    }

    #[test]
    fn unmeasured_pops_rank_last_but_are_still_offered() {
        let pops = default_pops("example.net");
        let controller = rtt(&[("iad", 10)]);
        let host = rtt(&[("iad", 240)]);
        let ranked = rank_pops(&pops, &controller, &host);
        assert_eq!(ranked[0], "iad");
        assert_eq!(
            ranked.len(),
            pops.len(),
            "a failed probe must not shrink the fallback list"
        );
    }

    #[test]
    fn ranking_is_deterministic_under_ties() {
        let pops = default_pops("example.net");
        let flat = rtt(&[("iad", 50), ("mrs", 50), ("lhr", 50), ("nbo", 50)]);
        assert_eq!(
            rank_pops(&pops, &flat, &flat),
            rank_pops(&pops, &flat, &flat)
        );
    }

    #[test]
    fn only_two_relay_pops_get_credentials() {
        let pops = default_pops("example.net");
        let ranked: Vec<String> = pops.iter().map(|p| p.code.clone()).collect();
        let creds = build_relay_credentials(&pops, &ranked, b"secret", "sess_1", 1000, 3600);

        let turn_entries = creds
            .ice_servers
            .iter()
            .filter(|s| s.username.is_some())
            .count();
        assert_eq!(
            turn_entries, MAX_RELAY_POPS,
            "extra relay candidates cost ICE round trips"
        );
        // ...but every PoP still contributes STUN, which is free and improves P2P odds.
        assert_eq!(creds.ice_servers[0].urls.len(), pops.len());
        assert_eq!(creds.preferred_order.len(), pops.len());
    }

    #[test]
    fn turn_credentials_follow_the_coturn_rest_scheme() {
        let (user, cred) = mint_turn_credential(b"shared-secret", "sess_abc", 1_755_248_400);
        assert_eq!(user, "1755248400:sess_abc");
        // Deterministic for a given secret and username, which is what lets coturn verify it
        // without any shared state.
        let (_, again) = mint_turn_credential(b"shared-secret", "sess_abc", 1_755_248_400);
        assert_eq!(cred, again);
        let (_, other) = mint_turn_credential(b"different", "sess_abc", 1_755_248_400);
        assert_ne!(cred, other);
    }

    #[test]
    fn credential_ttl_is_capped_at_an_hour() {
        let pops = default_pops("example.net");
        let creds = build_relay_credentials(&pops, &[], b"s", "sess", 0, 999_999);
        assert_eq!(creds.ttl_s, 3600);
    }
}
