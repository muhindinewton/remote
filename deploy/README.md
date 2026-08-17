# Deployment

One compose stack per point of presence: a signaling server and a TURN relay. The PoPs are
identical; what differs is where they sit, and that is the entire point — this corridor is won by
placement, not by configuration.

> **Not validated by running.** Docker is not installed in the environment these manifests were
> written in. The YAML is syntax-checked, the Dockerfile is written against the workspace layout,
> and the container's `HEALTHCHECK` invokes a `--health-check` flag that **is** implemented and
> verified (exit 0 when the server is up, exit 1 when it is not). No image has been built.

## Where to put them

From `docs/ARCHITECTURE.md` §1.4. The reasoning matters more than the list, because the obvious
choice is wrong:

| PoP | Location | Role | Why |
|---|---|---|---|
| `IAD` | US-East (Ashburn) | Signaling, STUN, TURN | Controller-side ingress; cheap and densely peered |
| `MRS` | Marseille | Signaling, STUN, TURN | **The real midpoint.** SEACOM and PEACE both run Mombasa → Red Sea → Suez → Mediterranean → France |
| `LHR`/`AMS` | London / Amsterdam | Signaling, STUN, TURN | Secondary European path, peering depth |
| `NBO` | Nairobi (iColo or Africa Data Centres, peered at KIXP) | STUN, TURN | In-country. Fixes the KE ↔ KE trombone as much as the US corridor |
| `JNB` | Johannesburg | TURN, **optional** | Only if measurement proves a direct Nairobi path exists |

**Johannesburg is the expensive mistake.** It is intuitive on a map and frequently wrong on the
network: Nairobi → Johannesburg has historically routed *via Europe* on many carriers, so a JNB
relay can add a full Europe round trip rather than remove one. It stays measurement-gated.

For in-country presence today, use carrier-neutral colocation peered at KIXP. AWS announced a
Nairobi region in September 2025 targeting late 2026 — it is not generally available, so do not
architect as though it is.

## Setup

Each PoP needs a `.env` beside the compose file:

```sh
# Must match coturn's static-auth-secret exactly. The signaling server mints credentials the relay
# verifies, with no shared state beyond this string, so a mismatch produces allocations that
# authenticate against nothing and fail in a way that looks like a NAT problem.
RDA_TURN_SECRET=<64+ random bytes, base64>

RDA_DOMAIN=example.net

# The address clients can actually reach. On a cloud host behind one-to-one NAT this is the public
# address, and getting it wrong is the single most common TURN misconfiguration: allocations succeed
# and then carry nothing.
RDA_EXTERNAL_IP=203.0.113.10

RDA_LOG=info
```

Generate the secret with something that is actually random:

```sh
head -c 48 /dev/urandom | base64
```

Then:

```sh
docker compose --env-file .env up -d
docker compose ps
docker compose logs -f signal
```

## Firewall

The relay is useless behind a closed port range, and the failure is silent — allocations succeed and
carry no media.

| Port | Protocol | Purpose |
|---|---|---|
| 3478 | UDP **and** TCP | STUN/TURN. UDP is the one that matters |
| 5349 | TCP | TURN over TLS, for networks that block UDP outright |
| 49152–65535 | UDP | Relay allocation range. Must match `min-port`/`max-port` in `coturn/turnserver.conf` |
| 443 | TCP | The reverse proxy in front of signaling |

Signaling itself binds `127.0.0.1:8080` and is reached only through the proxy: TLS is terminated
there, not in the server (`docs/PROTOCOL.md` §3.1).

## TLS

Two separate certificates, for two separate reasons:

- **The reverse proxy** terminates `wss://` for signaling. Any ACME client will do.
- **coturn** terminates TURN/TLS on 5349 itself, because that is a protocol concern rather than an
  HTTP one. Mount the certificate into the `turn-certs` volume at `fullchain.pem` and `privkey.pem`.

## Verifying a PoP

```sh
# Signaling is alive and reports its load.
curl -s https://signal.mrs.example.net/healthz
# {"peers":0,"sessions":0,"status":"ok"}

# The relay allocates. Credentials come from the signaling server, so this exercises the shared
# secret end to end rather than just checking a port is open.
turnutils_uclient -T -u "$(date -d '+1 hour' +%s):test" -w "<hmac>" turn.mrs.example.net
```

Then work through [`../scripts/CHECKLIST.md`](../scripts/CHECKLIST.md).

## Operational notes

**Rotating the TURN secret invalidates every outstanding credential.** That is the intended
behaviour in an incident, and it means a rotation is a brief outage for sessions mid-negotiation
rather than a transparent change. Roll it deliberately.

**The relay sees ciphertext only.** DTLS keys never leave the peers, and the fingerprint binding in
`docs/PROTOCOL.md` §4.3 means a compromised relay cannot MITM a session. That is what makes it
acceptable to run PoPs in jurisdictions you do not control — which is the whole reason a
geo-distributed fleet is affordable.

**What the relay does learn is metadata**: who talked to whom, when, and how much. `docs/ARCHITECTURE.md`
§5.6 says not to retain it, and the coturn config keeps logging minimal for exactly that reason.

**Do not skip the peer denials** in `coturn/turnserver.conf`. A TURN server with no peer
restrictions is an open proxy into whatever private network it sits in, and the cloud metadata
endpoint at `169.254.169.254` is a credential-theft primitive on every major provider.
