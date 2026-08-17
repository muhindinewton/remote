#!/usr/bin/env bash
# The macOS equivalent of impair.sh, using dummynet through pfctl.
#
# `tc` is Linux-only, and the host side of this project is developed on macOS, so without this the
# impairment story stops at "get a Linux box". macOS has dummynet built in — it is just buried
# behind pfctl and undocumented enough that most people assume it is absent.
#
#   sudo ./scripts/impair-macos.sh apply congested
#   sudo ./scripts/impair-macos.sh clear
#
# Two caveats worth knowing before trusting a measurement taken this way:
#
#   * dummynet's `plr` is independent per-packet loss, with no correlation parameter. Real loss is
#     bursty, and independent loss flatters FEC badly (see crates/rda-netsim/src/profile.rs). Use
#     this for latency and bandwidth work; use Linux netem, or the simulator, for loss work.
#   * Loopback traffic on macOS does not traverse pf in all configurations. Impair a real interface
#     between two machines for anything you intend to quote.

set -euo pipefail

ANCHOR="rda-impair"
PIPE_OUT=1
PIPE_IN=2

usage() {
  cat <<'USAGE'
usage: impair-macos.sh <command> [profile] [interface]

commands:
  apply <profile> [iface]   apply a profile (default iface: en0)
  clear                     remove all impairment
  status                    show configured pipes
  list                      list available profiles

profiles (matching crates/rda-netsim/src/profile.rs):
  direct       220 ms RTT,  0.5% loss,  8 Mbps
  relayed      260 ms RTT,    2% loss,  4 Mbps
  congested    250 ms RTT,   10% loss, 800 kbps
  hostile      250 ms RTT,   20% loss, 400 kbps

Delay is per direction, so a 110 ms setting yields a ~220 ms round trip.
USAGE
}

# profile -> "one-way-delay-ms loss-fraction bandwidth queue-slots"
profile_params() {
  case "$1" in
    direct)    echo "110 0.005 8Mbit/s 100" ;;
    relayed)   echo "130 0.02  4Mbit/s 80"  ;;
    congested) echo "125 0.10  800Kbit/s 50" ;;
    hostile)   echo "125 0.20  400Kbit/s 30" ;;
    *)         return 1 ;;
  esac
}

require_root() {
  if [[ ${EUID} -ne 0 ]]; then
    echo "error: must run as root (pfctl and dnctl need it)" >&2
    exit 1
  fi
}

clear_impairment() {
  # Every step is tolerant of already being absent: "clear" is what people run when confused, and
  # it must never itself fail.
  dnctl -q flush 2>/dev/null || true
  pfctl -a "${ANCHOR}" -F all 2>/dev/null || true
  # Leave pf enabled or disabled as it was found; disabling it wholesale could drop a firewall the
  # machine relies on.
  echo "cleared impairment (dummynet pipes flushed, anchor ${ANCHOR} emptied)"
}

apply_impairment() {
  local profile="$1" iface="$2"
  local params
  if ! params=$(profile_params "${profile}"); then
    echo "error: unknown profile '${profile}'" >&2
    usage >&2
    exit 2
  fi
  read -r delay loss bandwidth queue <<<"${params}"

  clear_impairment

  # Separate pipes per direction, so an asymmetric profile is expressible later without rework.
  dnctl pipe ${PIPE_OUT} config delay "${delay}" plr "${loss}" bw "${bandwidth}" queue "${queue}"
  dnctl pipe ${PIPE_IN} config delay "${delay}" plr "${loss}" bw "${bandwidth}" queue "${queue}"

  # pf rules go through an anchor so this cannot clobber an existing ruleset.
  cat <<PF | pfctl -a "${ANCHOR}" -f -
dummynet out on ${iface} all pipe ${PIPE_OUT}
dummynet in  on ${iface} all pipe ${PIPE_IN}
PF

  pfctl -E 2>/dev/null || true

  echo "applied '${profile}' to ${iface}:"
  echo "  one-way delay : ${delay} ms  (round trip ~$(( delay * 2 )) ms)"
  echo "  loss          : ${loss} (independent, NOT bursty — see the note at the top)"
  echo "  rate ceiling  : ${bandwidth}"
  echo
  echo "verify with: ping -c 10 <peer>   # expect ~$(( delay * 2 )) ms"
}

show_status() {
  echo "dummynet pipes:"
  dnctl -q list 2>/dev/null || echo "  (none)"
  echo
  echo "anchor ${ANCHOR}:"
  pfctl -a "${ANCHOR}" -s rules 2>/dev/null || echo "  (empty)"
}

main() {
  local cmd="${1:-}"
  case "${cmd}" in
    apply)
      require_root
      apply_impairment "${2:?profile required}" "${3:-en0}"
      ;;
    clear)
      require_root
      clear_impairment
      ;;
    status)
      show_status
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
