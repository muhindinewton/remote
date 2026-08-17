# Long-distance verification checklist

The corridor this system targets cannot be reached from a developer's desk, so it has to be
manufactured. This is the sequence for convincing yourself a build actually works over 250 ms and
10 % loss, ordered so each step is cheap and the expensive ones only run once the cheap ones pass.

Three levels, in increasing cost and increasing truth:

| Level | Cost | What it proves |
|---|---|---|
| **A — Simulated** | milliseconds, no privileges | The policies behave correctly under modelled impairment |
| **B — Local impairment** | one machine, root | The real stack behaves over real sockets under real delay |
| **C — Real corridor** | two machines, two continents | Everything else was right about the actual path |

Level A runs in CI on every commit. Level B is the pre-release gate. Level C is what you do before
telling anyone the numbers.

---

## Level A — simulated, in CI

```sh
cargo test -p rda-netsim
cargo test -p rda-netsim --test corridor_e2e -- --nocapture
```

- [ ] All `rda-netsim` unit tests pass.
- [ ] `corridor_e2e` passes on every profile.
- [ ] The sweep output shows playout delay **rising with link quality falling**. A buffer that stays
      at its 15 ms floor on the congested profile means it is not adapting, and the session will
      stutter on a real link.
- [ ] Achieved bitrate on `us-kenya-congested` sits **below** 800 kbps. Over-sending is what turns a
      bandwidth problem into a latency problem.

Reference output on a healthy build:

```
                 lan  rtt   2ms  encoded   61  played   61 (100%)   7009 kbps  buf  15ms
     us-kenya-direct  rtt 220ms  encoded   61  played   61 (100%)   5378 kbps  buf  24ms
    us-kenya-relayed  rtt 260ms  encoded   61  played   61 (100%)   1998 kbps  buf  51ms
  us-kenya-congested  rtt 250ms  encoded   61  played   53 ( 87%)    695 kbps  buf 120ms
             hostile  rtt 250ms  encoded   61  played   21 ( 34%)    318 kbps  buf 185ms
```

The play rate falling on the worse profiles is expected — this harness sends **without FEC**, and a
single lost fragment costs the whole frame. What must not happen is the stream stopping.

---

## Level B — local impairment

Apply real delay and loss to a real interface, then run a real session across it.

```sh
# Linux
sudo ./scripts/impair.sh apply congested eth0

# macOS
sudo ./scripts/impair-macos.sh apply congested en0
```

- [ ] `ping` shows the expected round trip (~250 ms for `congested`) and visible loss.
- [ ] A session establishes at all. If ICE fails, check the relay before blaming the impairment —
      3 s of hole-punching at 250 ms RTT is only about a dozen check rounds.
- [ ] `rda-host --encode` still reports a plausible bitrate rather than collapsing to nothing.
- [ ] The telemetry line in the viewer shows RTT within ~20 % of what `ping` reports. A large
      disagreement means the transport is measuring something other than the path.
- [ ] Typing feels laggy but **predictable**. Users tolerate consistent latency far better than
      variable latency; jitter that makes the cursor stutter is a worse failure than the delay.
- [ ] The picture degrades — softer, lower frame rate — rather than freezing.
- [ ] **Recovery**: clear the impairment and confirm quality climbs back within ~15 s. The
      degradation ladder promotes deliberately slowly (10 s of sustained headroom), so anything
      faster means the hysteresis is not working and anything much slower means it is stuck.

```sh
sudo ./scripts/impair.sh clear eth0
```

- [ ] Impairment actually cleared. `tc qdisc show` / `dnctl list` reports nothing.

### Loss-specific work

Use **Linux** for anything where the loss result matters. macOS dummynet's `plr` is independent
per-packet loss with no correlation parameter, and independent loss flatters forward error
correction badly — a code that recovers one loss per protected set handles scattered loss trivially
and burst loss not at all.

---

## Level C — the real corridor

Two machines: one in US-East, one in Nairobi. Nothing below can be inferred from levels A and B.

- [ ] **Measure the actual RTT** from a Kenyan vantage point to each PoP — `IAD`, `MRS`, `LHR`,
      `NBO`. Record them. The numbers in `docs/ARCHITECTURE.md` §1.4 are labelled estimates and this
      is the step that replaces them.
- [ ] **Confirm Marseille beats Johannesburg**, or find out it does not. The architecture predicts
      European PoPs win because SEACOM and PEACE both run Mombasa → Suez → Mediterranean → France,
      and that Nairobi ↔ Johannesburg frequently routes via Europe anyway. It is a prediction, not a
      measurement, and JNB is explicitly measurement-gated.
- [ ] **Check the KE ↔ KE case.** Two Kenyan endpoints on non-peering ISPs may route to each other
      via London. If they do, the Nairobi PoP is earning its cost on more than the US corridor.
- [ ] Record what fraction of sessions get a **direct P2P path** versus falling back to a relay. The
      overlay relay mesh (§1.5) is justified by the relayed tail, not the median, and this number is
      what decides whether to build it.
- [ ] Measure **glass-to-glass** latency with a physical clock in frame, not a software timer. The
      budget in §2.1 predicts ~172 ms typical; anything far above it points at a specific row.
- [ ] Run a session at **evening peak** in Nairobi, not at 03:00 UTC. Residential congestion is the
      condition the whole design exists for and it is invisible off-peak.

---

## What none of this covers

Stated plainly, because a checklist that implies completeness is worse than one that admits gaps:

- **Cross traffic that reacts to us.** The simulator's bandwidth ceiling is a fixed pipe. Real
  bottlenecks are shared with TCP flows that back off when we push, and the interaction between
  our congestion control and theirs is not modelled anywhere here.
- **Middlebox behaviour.** Carrier-grade NAT, deep packet inspection and UDP throttling on mobile
  networks are all real on this corridor and none of them appear in any level below C.
- **Sustained multi-hour sessions.** Everything above runs for seconds. Memory growth, sequence
  number wrap and clock drift need a soak test.
- **Concurrent load.** One session on an idle PoP says nothing about a hundred.
