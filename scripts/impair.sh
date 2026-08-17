#!/usr/bin/env bash
# Apply US <-> Kenya link conditions to a Linux interface using tc/netem.
#
# The corridor this project targets cannot be reached from a developer's desk, so it has to be
# manufactured. This script reproduces the profiles in `crates/rda-netsim/src/profile.rs` on a real
# interface, so the same conditions the simulator asserts against can be verified end to end with
# real sockets, a real encoder and a real WebRTC stack.
#
# Run on the HOST side, or on a router between the two machines. Applying it to loopback also works
# and is the easiest way to test two processes on one box.
#
#   sudo ./scripts/impair.sh apply congested eth0
#   sudo ./scripts/impair.sh status eth0
#   sudo ./scripts/impair.sh clear eth0
#
# Requires: iproute2 (tc), and the sch_netem kernel module.

set -euo pipefail

usage() {
  cat <<'USAGE'
usage: impair.sh <command> [profile] [interface]

commands:
  apply <profile> [iface]   apply a profile (default iface: eth0)
  clear [iface]             remove all impairment
  status [iface]            show what is currently applied
  list                      list available profiles

profiles (matching crates/rda-netsim/src/profile.rs):
  direct       220 ms RTT,  0.5% loss, 12 ms jitter,  8 Mbps
  relayed      260 ms RTT,    2% loss, 20 ms jitter,  4 Mbps
  congested    250 ms RTT,   10% loss, 45 ms jitter, 800 kbps
  hostile      250 ms RTT,   20% loss, 60 ms jitter, 400 kbps

Delay is applied per direction. Applying 125 ms here produces a 250 ms round trip, because the
packet crosses the impaired interface twice.
USAGE
}

# profile -> "one-way-delay jitter loss% reorder% rate"
profile_params() {
  case "$1" in
    direct)    echo "110ms 12ms 0.5 0.1 8mbit" ;;
    relayed)   echo "130ms 20ms 2   0.2 4mbit" ;;
    congested) echo "125ms 45ms 10  1   800kbit" ;;
    hostile)   echo "125ms 60ms 20  2   400kbit" ;;
    *)         return 1 ;;
  esac
}

require_root() {
  if [[ ${EUID} -ne 0 ]]; then
    echo "error: must run as root (tc modifies kernel queueing discipline)" >&2
    exit 1
  fi
}

require_tc() {
  if ! command -v tc >/dev/null 2>&1; then
    echo "error: tc not found; install iproute2" >&2
    exit 1
  fi
}

clear_impairment() {
  local iface="$1"
  # `|| true` because deleting a qdisc that is not there is an error, and "clear" should be
  # idempotent — it is the first thing anyone runs when something looks wrong.
  tc qdisc del dev "${iface}" root 2>/dev/null || true
  echo "cleared impairment on ${iface}"
}

apply_impairment() {
  local profile="$1" iface="$2"
  local params
  if ! params=$(profile_params "${profile}"); then
    echo "error: unknown profile '${profile}'" >&2
    usage >&2
    exit 2
  fi
  read -r delay jitter loss reorder rate <<<"${params}"

  clear_impairment "${iface}"

  # Two layers: a token bucket for the bandwidth ceiling, and netem underneath it for delay, jitter
  # and loss. Order matters — netem must sit below the shaper, or the shaper's queue absorbs the
  # jitter and the delay distribution never reaches the wire.
  tc qdisc add dev "${iface}" root handle 1: tbf \
      rate "${rate}" burst 32kbit latency 400ms

  # `loss ... 25%` is netem's Gilbert model correlation: it makes losses cluster instead of being
  # independent. Real loss arrives in runs, and independent loss makes FEC look far better than it
  # is (see the module docs in crates/rda-netsim/src/profile.rs).
  tc qdisc add dev "${iface}" parent 1:1 handle 10: netem \
      delay "${delay}" "${jitter}" distribution normal \
      loss "${loss}%" 25% \
      reorder "${reorder}%" 50% \
      limit 2000

  echo "applied '${profile}' to ${iface}:"
  echo "  one-way delay : ${delay} +/- ${jitter}  (round trip ~$(( ${delay%ms} * 2 )) ms)"
  echo "  loss          : ${loss}%, correlated (bursty)"
  echo "  reorder       : ${reorder}%"
  echo "  rate ceiling  : ${rate}"
  echo
  echo "verify with: ping -c 10 <peer>   # expect ~$(( ${delay%ms} * 2 )) ms and some loss"
}

show_status() {
  local iface="$1"
  echo "qdisc on ${iface}:"
  tc -s qdisc show dev "${iface}"
}

main() {
  local cmd="${1:-}"
  case "${cmd}" in
    apply)
      require_root; require_tc
      apply_impairment "${2:?profile required}" "${3:-eth0}"
      ;;
    clear)
      require_root; require_tc
      clear_impairment "${2:-eth0}"
      ;;
    status)
      require_tc
      show_status "${2:-eth0}"
      ;;
    list)
      for p in direct relayed congested hostile; do
        printf '  %-10s %s\n' "${p}" "$(profile_params "${p}")"
      done
      ;;
    ""|-h|--help|help)
      usage
      ;;
    *)
      echo "error: unknown command '${cmd}'" >&2
      usage >&2
      exit 2
      ;;
  esac
}

main "$@"
