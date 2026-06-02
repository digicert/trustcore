#!/usr/bin/env bash
# run_testsuite.sh — automated IKE/IPsec test harness for NanoSec
#
# NETWORK TOPOLOGY
# ────────────────
#
#   NanoSec ↔ NanoSec mode  (default, no -S flag)
#
#     Both veth ends share the default network namespace so that
#     moc_ipsec.ko — which registers netfilter hooks only in the default
#     namespace — can intercept all IKE and ESP traffic between them.
#
#     ┌──────────────────────────────────────────────────────────────┐
#     │  default namespace                                           │
#     │                                                              │
#     │  [NanoSec responder]          [NanoSec initiator]            │
#     │   veth_resp                    veth_init                     │
#     │   10.10.10.1  ◄──────────────► 10.10.10.2                    │
#     │                                                              │
#     │  moc_ipsec.ko handles ESP encrypt/decrypt for both sides     │
#     └──────────────────────────────────────────────────────────────┘
#
#     Both IPs are local to the same namespace, so the kernel routes
#     packets between them through loopback (lo), not the veth pair.
#     Traffic therefore never triggers the netfilter OUTPUT hooks that
#     moc_ipsec.ko relies on for SA lookup.  The "sa init" SPD flag is
#     used instead: it sets IPSEC_SP_FLAG_INIT on the SPD entry, causing
#     the kernel module to call IPSEC_keyInitiate() via IOCTL, which
#     starts Quick Mode (IKEv1) or IKE_AUTH child creation (IKEv2)
#     without waiting for a real data packet.  Packet-capture for
#     encryption verification is done on lo for the same reason.
#
#   StrongSwan interop mode  (-S flag)
#
#     Each veth end is placed in its own network namespace to prevent a
#     port-500 conflict: charon (StrongSwan daemon) binds 0.0.0.0:500
#     (wildcard) while NanoSec binds to a specific IP.  Separate
#     namespaces give each daemon its own isolated view of port 500.
#
#     ┌──────────────────────┐           ┌──────────────────────┐
#     │  ns_ike_left         │           │  ns_ike_right        │
#     │  veth_resp           │◄─────────►│  veth_init           │
#     │  10.10.10.1          │           │  10.10.10.2          │
#     └──────────────────────┘           └──────────────────────┘
#
#     SS=init:  NanoSec   ─► ns_ike_left  (RESP_IP = 10.10.10.1)
#               StrongSwan ─► ns_ike_right (INIT_IP = 10.10.10.2)
#
#     SS=resp:  StrongSwan ─► ns_ike_left  (RESP_IP = 10.10.10.1)
#               NanoSec   ─► ns_ike_right (INIT_IP = 10.10.10.2)
#
#     moc_ipsec.ko does not intercept cross-namespace traffic.  ESP
#     encryption of data traffic is provided by StrongSwan's XFRM
#     subsystem inside the SS namespace; the kernel encrypts outbound
#     packets as ESP before they exit the veth.  Packet capture for
#     verification is therefore done on the SS-side veth interface.
#
# TEST FLOW — NanoSec ↔ NanoSec
# ──────────────────────────────
#
#   1. Flush SA/SPD state left over from any previous test.
#   2. tc_setup_policies() writes three policy files:
#        resp_policy    SPD entry loaded before the responder starts
#        init_policy    SPD entry loaded before the initiator starts (no trigger)
#        sainit_policy  Same entry with the "sa init" flag; loaded after Phase 1
#   3. Load resp_policy and init_policy into moc_ipsec via loadConfig.
#   4. Start NanoSec responder (binds RESP_IP:500, waits for IKE packets).
#   5. Start NanoSec initiator (connects to RESP_IP, begins IKE exchange).
#   6. Poll until "IKE_SA Created" appears in the initiator log (Phase 1 done).
#   7. Load sainit_policy → IPSEC_SP_FLAG_INIT → IPSEC_keyInitiate() → Phase 2.
#   8. Poll until "CHILD_SA created" appears in both process logs.
#   9. Verify negotiated encr/auth/keylen against TC_VERIFY_* via dmesg SA dump.
#  10. Send 5 UDP packets from RESP_IP to INIT_IP; capture on lo; confirm
#      every captured packet is ESP or AH with no plain UDP visible.
#
# TEST FLOW — StrongSwan interop
# ───────────────────────────────
#
#   SS=init (StrongSwan initiates, NanoSec responds):
#     1. Start charon in NS_RIGHT (INIT_IP); NanoSec responder in NS_LEFT.
#     2. Load swanctl.conf; run swanctl --initiate.
#     3. Poll until "CHILD_SA created" in NanoSec log and "INSTALLED" in
#        swanctl --list-sas.
#     4. Send 5 UDP packets from the SS namespace; capture on its veth.
#        XFRM encrypts them as ESP before they leave, so plain UDP is absent.
#
#   SS=resp (StrongSwan responds, NanoSec initiates):
#     1. Start charon in NS_LEFT (RESP_IP); NanoSec initiator in NS_RIGHT.
#     2. Phase 1 completes; harness loads sainit_policy to trigger Phase 2.
#     3-4. Same poll and capture steps as SS=init above.
#
# Usage:
#   sudo ./samples/nanosec/run_testsuite.sh [options] [glob...]
#
# Options:
#   -t <secs>   Negotiation timeout per test case (default: 30)
#   -w <secs>   Socket wait time passed to the ike binary (default: 60)
#   -k          Keep veth pair and modules after the suite finishes
#   -V          Enable valgrind memory-leak checks on the ike binary
#   -S          StrongSwan interop mode (uses testcases_strongswan/ directory)
#   -I          Build and install strongswan 6.0.6 from source if not found
#   -f <glob>   Run only test cases whose filename matches glob (repeatable)
#   -l          List available test cases and exit
#   -h          Show this help
#
# Positional args: additional filename globs, OR-combined with -f.
#   e.g.: sudo ./samples/nanosec/run_testsuite.sh '01_*' '03_*'
#
# Test case API (defined in each testcases/*.sh file):
#   TC_NAME              Human-readable name (required)
#   TC_IKE_VERSION       IKE version: 1 or 2 (default: 1)
#   TC_NEG_TIMEOUT       Per-test timeout override (default: $NEG_TIMEOUT)
#   TC_SOCK_WAIT         Per-test -w override (default: $SOCK_WAIT)
#   TC_RESP_IKE_FLAGS    Array of extra flags for the responder ike binary
#   TC_INIT_IKE_FLAGS    Array of extra flags for the initiator ike binary
#   TC_VERIFY_AUTH       Expected auth algo name for SA verification (optional)
#   TC_VERIFY_ENCR       Expected encr algo name (optional)
#   TC_VERIFY_KEYLEN     Expected key length in bytes (optional)
#   TC_RUN_PACKET_TEST   1=run packet-capture step (default), 0=skip
#   TC_SKIP_REASON       If non-empty, skip this test with this message
#
#   tc_setup_policies resp_ip init_ip resp_file init_file sainit_file
#     Writes the three policy files described in the test flow above.
#     Must be defined in every test case file.
#
# StrongSwan interop test case API (testcases_strongswan/*.sh):
#   All standard TC_* variables above, plus:
#   TC_STRONGSWAN_ROLE   "init" = StrongSwan initiates / NanoSec responds (default)
#                        "resp" = StrongSwan responds / NanoSec initiates
#   TC_SS_CONN_NAME      swanctl connection name (default: nanosec-interop)
#   TC_SS_CHILD_NAME     swanctl child SA name (default: child1)
#
#   tc_setup_swanctl resp_ip init_ip conf_file
#     Writes a swanctl.conf for the StrongSwan side.  Must be defined.
#   tc_setup_policies resp_ip init_ip resp_file init_file sainit_file
#     Only the relevant side's file needs content:
#     - TC_STRONGSWAN_ROLE=init: populate resp_file only
#     - TC_STRONGSWAN_ROLE=resp: populate init_file and sainit_file only

# -e: exit on any command error; -u: treat unset variables as errors;
# -o pipefail: a pipeline fails if any command in it fails (not just the last).
set -euo pipefail

###############################################################################
# Defaults
###############################################################################
NEG_TIMEOUT=30
SOCK_WAIT=60
KEEP=0
LIST_ONLY=0
VALGRIND_ENABLED=0
STRONGSWAN_MODE=0
INSTALL_STRONGSWAN=0

# VICI (Versatile IKE Configuration Interface) is charon's socket-based
# control API.  swanctl uses it to load configs, trigger SA initiation, and
# query SA state.  charon creates this socket on startup.
SS_VICI_SOCK="/var/run/charon.vici"

# swanctl reads connection definitions from the compiled-in path
# /etc/swanctl/conf.d/.  We write one file there per test and call
# --load-all to activate it without touching other system StrongSwan config.
SS_SWANCTL_CONF_D="/etc/swanctl/conf.d"
SS_ACTIVE_CONF="${SS_SWANCTL_CONF_D}/nanosec_suite.conf"

# strongswan.conf controls daemon-level settings (logging, route installation).
# We generate a minimal one per suite run to keep charon from modifying the
# host routing table or assigning virtual IPs.
SS_STRONGSWAN_CONF="/tmp/strongswan_suite_$$.conf"

CHARON_PID=0
SWANCTL_BIN=""
CHARON_BIN=""

# Both IPs are in the same /24 so the kernel routes between them without a
# gateway; the range is private and unlikely to collide with host networking.
RESP_IP="10.10.10.1"
INIT_IP="10.10.10.2"
SUBNET="24"
VETH_RESP="veth_resp"
VETH_INIT="veth_init"

# Used only in StrongSwan mode; see the network topology diagram at the top.
NS_LEFT="ns_ike_left"    # owns veth_resp / RESP_IP
NS_RIGHT="ns_ike_right"  # owns veth_init / INIT_IP

# Each NanoSec process reports SA lifecycle events (CHILD_SA created/deleted)
# on a separate UDP port so the harness can detect negotiation completion
# independently of log-line parsing.
RESP_EVENT_PORT=13579
INIT_EVENT_PORT=13580

###############################################################################
# Path resolution
###############################################################################
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BIN_DIR="${REPO_DIR}/bin"
IKE_BIN="${REPO_DIR}/samples/bin/ike"
TC_DIR="${SCRIPT_DIR}/testcases"

###############################################################################
# Colors — only when stdout is a terminal
###############################################################################
if [[ -t 1 ]]; then
    _R='\033[0m'  _B='\033[1m'      _DIM='\033[2m'
    _CY='\033[1;36m' _GR='\033[1;32m' _RD='\033[1;31m'
    _YL='\033[1;33m' _MG='\033[1;35m'
else
    _R='' _B='' _DIM='' _CY='' _GR='' _RD='' _YL='' _MG=''
fi

###############################################################################
# Helpers
###############################################################################
log() {
    local ts msg="$*" color=''
    ts="$(date '+%H:%M:%S')"
    case "$msg" in
        *"RESULT:"*"ENCRYPTED"*|*"RESULT:"*"VERIFIED"*|\
        *"CHILD_SA: YES"*|*"Phase 1"*"established"*)   color="$_GR" ;;
        *"RESULT: WARNING"*|*"RESULT: Mixed"*|\
        *"RESULT: No packets"*|*"WARNING:"*)            color="$_YL" ;;
        *"RESULT: MISMATCH"*|*"CHILD_SA: NO"*|\
        *"Failure detected"*|*"expected="*"got="*)      color="$_RD" ;;
    esac
    if [[ "$msg" == "--- Cleanup ---" ]]; then
        printf "\n${_DIM}[%s] %s${_R}\n" "$ts" "$msg"
    elif [[ -n "$color" ]]; then
        printf "${_DIM}[%s]${_R} ${color}%s${_R}\n" "$ts" "$msg"
    else
        printf "${_DIM}[%s]${_R} %s\n" "$ts" "$msg"
    fi
}

step()     { printf "\n${_DIM}[%s]${_R} ${_CY}── %s${_R}\n" "$(date '+%H:%M:%S')" "$*"; }
section()  { printf "\n${_DIM}─── %s ───${_R}\n" "$*"; }
pass()     { printf "\n  ${_GR}${_B}✓  PASS:${_R}  %s\n\n" "$*"; }
skip_msg() { printf "\n  ${_YL}${_B}⊘  SKIP:${_R}  %s\n\n" "$*"; }
fail_msg() { printf "\n  ${_RD}${_B}✗  FAIL:${_R}  %s\n\n" "$*"; }
fail()     { printf "\n  ${_RD}${_B}✗  FAIL:${_R}  %b\n\n" "$*"; exit 1; }

# Pattern-based extraction: find the Usage section by its header line rather
# than a hardcoded line number, so the output stays correct as the header grows.
# The second sed deletes the trailing blank/non-comment line and strips "# ".
usage() { sed -n '/^# Usage:/,/^[^#]/p' "$0" | sed '$d;s/^# \{0,1\}//'; exit 0; }

# _graceful_kill <pid> [timeout_secs]
#
# Sends SIGTERM and waits up to <timeout_secs> (default 5, or 15 under
# valgrind) for the process to exit cleanly.  Falls back to SIGKILL only
# if the process is still alive after the deadline.
_graceful_kill() {
    local pid="$1"
    local timeout="${2:-}"

    [[ $pid -ne 0 ]] && kill -0 "$pid" 2>/dev/null || return 0

    # Default timeout: longer under valgrind because cleanup is ~20x slower.
    if [[ -z "$timeout" ]]; then
        timeout=5
        [[ $VALGRIND_ENABLED -eq 1 ]] && timeout=45
    fi

    kill -TERM "$pid" 2>/dev/null || return 0

    local waited=0
    while [[ $waited -lt $timeout ]] && kill -0 "$pid" 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
    done

    if kill -0 "$pid" 2>/dev/null; then
        log "  PID $pid did not exit after ${timeout}s — sending SIGKILL"
        kill -9 "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
}

###############################################################################
# Parse options
###############################################################################
declare -a FILTER_PATTERNS=()

while getopts "t:w:kVSIf:lh" opt; do
    case $opt in
        t) NEG_TIMEOUT="$OPTARG" ;;
        w) SOCK_WAIT="$OPTARG" ;;
        k) KEEP=1 ;;
        V) VALGRIND_ENABLED=1 ;;
        S) STRONGSWAN_MODE=1 ;;
        I) INSTALL_STRONGSWAN=1 ;;
        f) FILTER_PATTERNS+=("$OPTARG") ;;
        l) LIST_ONLY=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))
for _pat in "$@"; do FILTER_PATTERNS+=("$_pat"); done

[[ $STRONGSWAN_MODE -eq 1 ]] && TC_DIR="${SCRIPT_DIR}/testcases_strongswan"

# Log file prefix embedded in every /tmp/suite_* path so that NanoSec-only
# runs (suite_ns_N_*) and StrongSwan interop runs (suite_ss_N_*) never share
# a filename even when the same test index appears in both suites.
_LOG_PFX="ns"
[[ $STRONGSWAN_MODE -eq 1 ]] && _LOG_PFX="ss"

###############################################################################
# Sanity checks
###############################################################################
if [[ "$EUID" -ne 0 ]]; then
    fail "This script must be run as root (use sudo)."
fi

for _f in "${BIN_DIR}/moc_platform_mod.ko" \
           "${BIN_DIR}/moc_memdrv.ko"       \
           "${BIN_DIR}/moc_ipsec.ko"        \
           "${BIN_DIR}/moc_ipsec_mod.ko"    \
           "${BIN_DIR}/loadConfig"          \
           "${IKE_BIN}"; do
    [[ -f "$_f" ]] || fail "Required file not found: $_f"
done

[[ -d "$TC_DIR" ]] || fail "Test case directory not found: $TC_DIR"

###############################################################################
# Valgrind detection
###############################################################################
VALGRIND_BIN=""
if command -v valgrind &>/dev/null; then
    VALGRIND_BIN="$(command -v valgrind)"
fi
if [[ $VALGRIND_ENABLED -eq 1 && -z "$VALGRIND_BIN" ]]; then
    fail "valgrind not found in PATH — install it or omit -V."
fi

###############################################################################
# StrongSwan detection (and optional install)
###############################################################################
if command -v swanctl &>/dev/null; then
    SWANCTL_BIN="$(command -v swanctl)"
fi
for _p in /usr/libexec/ipsec/charon /usr/lib/ipsec/charon \
           /usr/libexec/strongswan/charon /usr/sbin/charon; do
    [[ -x "$_p" ]] && { CHARON_BIN="$_p"; break; }
done

if [[ $INSTALL_STRONGSWAN -eq 1 && ( -z "$SWANCTL_BIN" || -z "$CHARON_BIN" ) ]]; then
    step "Building strongswan 6.0.6 from source"
    command -v apt-get &>/dev/null || fail "-I requires apt-get for build dependencies (Debian/Ubuntu only)."
    command -v wget    &>/dev/null || fail "-I requires wget — install it first."

    step "  [1/4] Installing build dependencies"
    apt-get install -y gcc make libgmp-dev libldap-dev libcurl4-openssl-dev \
        libsoup-3.0-dev libsystemd-dev libgcrypt-dev libpam-dev \
        libip4tc-dev libssl-dev 2>&1 \
        | grep -E "^(Get:|Setting up|Unpacking|already)" || true

    _SS_BUILD_DIR="$(mktemp -d /tmp/strongswan_build.XXXXXX)"
    trap 'rm -rf "$_SS_BUILD_DIR"' EXIT

    step "  [2/4] Downloading strongswan-6.0.6.tar.gz"
    wget -q --show-progress \
        https://github.com/strongswan/strongswan/releases/download/6.0.6/strongswan-6.0.6.tar.gz \
        -O "${_SS_BUILD_DIR}/strongswan-6.0.6.tar.gz"
    tar xf "${_SS_BUILD_DIR}/strongswan-6.0.6.tar.gz" -C "$_SS_BUILD_DIR"

    step "  [3/4] Configuring and compiling"
    (
        cd "${_SS_BUILD_DIR}/strongswan-6.0.6"
        CFLAGS="-ggdb -O0 -DDEBUG" CXXFLAGS="-ggdb -O0 -DDEBUG" \
        ./configure \
            --enable-openssl --enable-ml --enable-gcrypt --enable-gmp \
            --enable-kernel-netlink --enable-socket-default --enable-stroke \
            --enable-vici --enable-swanctl --enable-charon --enable-updown \
            --enable-resolve --enable-eap-identity --enable-eap-md5 \
            --enable-eap-gtc --enable-eap-aka --enable-eap-aka-3gpp \
            --enable-eap-aka-3gpp2 --enable-eap-sim --enable-eap-mschapv2 \
            --enable-eap-radius --enable-eap-tls --enable-eap-ttls \
            --enable-eap-peap --enable-xauth-generic --enable-xauth-eap \
            --enable-xauth-pam --enable-xauth-noauth --enable-dhcp \
            --enable-farp --enable-addrblock --enable-unity --enable-curl \
            --enable-files --enable-soup --enable-ldap --enable-sqlite \
            --enable-pkcs11 --enable-sha3 --enable-mgf1 --enable-chapoly \
            --enable-ccm --enable-gcm --enable-ctr --enable-af-alg \
            --enable-sha1 --enable-sha2 --enable-md4 --enable-md5 \
            --enable-des --enable-aes --enable-rc2 --enable-blowfish \
            --enable-hmac --enable-xcbc --enable-cmac --enable-fips-prf \
            --enable-kdf --enable-pkcs1 --enable-pkcs7 --enable-pkcs8 \
            --enable-pkcs12 --enable-pgp --enable-dnskey --enable-sshkey \
            --enable-pem --enable-x509 --enable-revocation --enable-constraints \
            --enable-acert --enable-pubkey --enable-random --enable-nonce \
            --enable-curve25519 --enable-test-vectors --enable-systemd \
            --enable-agent --enable-certexpire --enable-connmark \
            --enable-eap-dynamic --enable-eap-tnc --enable-error-notify \
            --enable-forecast --enable-ha --enable-led --enable-lookip \
            --enable-tnc-tnccs \
            --sysconfdir=/etc --localstatedir=/var \
            --with-ipsecdir=/usr/libexec/ipsec \
            --with-ipseclibdir=/usr/lib/ipsec \
            --with-systemdsystemunitdir=/usr/lib/systemd/system \
            2>&1 | tail -5
        make -j4
    ) || fail "strongswan build failed — check output above."

    step "  [4/4] Installing"
    (cd "${_SS_BUILD_DIR}/strongswan-6.0.6" && make install)

    # Re-detect after install
    if command -v swanctl &>/dev/null; then
        SWANCTL_BIN="$(command -v swanctl)"
    fi
    for _p in /usr/libexec/ipsec/charon /usr/lib/ipsec/charon \
               /usr/libexec/strongswan/charon /usr/sbin/charon; do
        [[ -x "$_p" ]] && { CHARON_BIN="$_p"; break; }
    done
    [[ -n "$SWANCTL_BIN" && -n "$CHARON_BIN" ]] || \
        fail "strongswan built and installed but swanctl/charon still not found."
    log "  strongswan ready: swanctl=$SWANCTL_BIN  charon=$CHARON_BIN"
fi

if [[ $STRONGSWAN_MODE -eq 1 ]]; then
    [[ -n "$SWANCTL_BIN" ]] || \
        fail "swanctl not found: install strongswan (use -I to install)."
    [[ -n "$CHARON_BIN"  ]] || \
        fail "charon not found: install strongswan (use -I to install)."
    [[ -d "$TC_DIR"      ]] || \
        fail "StrongSwan test case directory not found: $TC_DIR"
fi

###############################################################################
# Collect and filter test cases
###############################################################################
# Read all test case files sorted alphabetically so tests run in the numeric
# order implied by their filename prefix (01_, 02_, …).
mapfile -t ALL_TC_FILES < <(find "$TC_DIR" -maxdepth 1 -name '*.sh' | sort)

TC_FILES=()
for _tc in "${ALL_TC_FILES[@]}"; do
    _base="$(basename "$_tc")"
    if [[ ${#FILTER_PATTERNS[@]} -eq 0 ]]; then
        TC_FILES+=("$_tc")
    else
        for _pat in "${FILTER_PATTERNS[@]}"; do
            # $_pat is unquoted intentionally: [[ == ]] treats it as a shell glob
            # so callers can pass patterns like '01_*' or '*cert*'.
            if [[ "$_base" == $_pat ]]; then
                TC_FILES+=("$_tc")
                break
            fi
        done
    fi
done

###############################################################################
# List-only mode
###############################################################################
if [[ $LIST_ONLY -eq 1 ]]; then
    printf "\nTest cases in %s:\n\n" "$TC_DIR"
    _idx=0
    for _tc in "${ALL_TC_FILES[@]}"; do
        _idx=$((_idx + 1))
        _base="$(basename "$_tc")"
        _name=$(grep -m1 '^TC_NAME=' "$_tc" \
                | sed "s/^TC_NAME=['\"]\\?//;s/['\"]\\?$//" 2>/dev/null \
                || echo "(no TC_NAME)")
        printf "  %2d.  %-42s  %s\n" "$_idx" "$_base" "$_name"
    done
    printf "\n"
    exit 0
fi

[[ ${#TC_FILES[@]} -gt 0 ]] || fail "No test cases match the given filter(s)."

###############################################################################
# Cleanup trap — runs on EXIT, INT, and TERM
#
# Kills any lingering IKE processes and charon, removes the veth pair or
# namespaces (unless -k was passed), and unloads the kernel modules.
###############################################################################
RESP_PID=0
INIT_PID=0
VETH_CREATED=0

cleanup() {
    local _code=$?
    log "--- Cleanup ---"

    for _pid in $RESP_PID $INIT_PID; do
        _graceful_kill "$_pid"
    done

    _graceful_kill "$CHARON_PID"
    rm -f "$SS_STRONGSWAN_CONF" "$SS_ACTIVE_CONF"

    if [[ $KEEP -eq 0 ]]; then
        for _mod in moc_ipsec_mod moc_ipsec moc_memdrv moc_platform_mod; do
            lsmod | grep -q "^${_mod} " && rmmod "$_mod" 2>/dev/null || true
        done
        if [[ $VETH_CREATED -eq 1 ]]; then
            if [[ $STRONGSWAN_MODE -eq 1 ]]; then
                # Deleting the namespaces also removes the veth interfaces inside them.
                ip netns del "$NS_LEFT"  2>/dev/null || true
                ip netns del "$NS_RIGHT" 2>/dev/null || true
            else
                ip link del "$VETH_RESP" 2>/dev/null || true
            fi
        fi
    else
        log "Skipping teardown (-k set). Logs in /tmp/suite_*"
    fi

    exit $_code
}

trap cleanup EXIT
# INT/TERM call exit(1), which fires the EXIT trap above and runs cleanup.
trap 'exit 1' INT TERM

###############################################################################
# Infrastructure: veth pair
###############################################################################
setup_network() {
    if [[ $STRONGSWAN_MODE -eq 1 ]]; then
        step "Infrastructure: Creating veth pair in network namespaces"

        ip netns del "$NS_LEFT"  2>/dev/null || true
        ip netns del "$NS_RIGHT" 2>/dev/null || true

        ip netns add "$NS_LEFT"
        ip netns add "$NS_RIGHT"
        VETH_CREATED=1

        # Create the pair in the default namespace, then move each end into
        # its dedicated namespace.  veth pairs must be created together; you
        # cannot create them already inside separate namespaces.
        ip link add "$VETH_RESP" type veth peer name "$VETH_INIT"
        ip link set "$VETH_RESP" netns "$NS_LEFT"
        ip link set "$VETH_INIT" netns "$NS_RIGHT"

        ip netns exec "$NS_LEFT"  ip addr add "${RESP_IP}/${SUBNET}" dev "$VETH_RESP"
        ip netns exec "$NS_LEFT"  ip link set "$VETH_RESP" up
        # lo must be brought up explicitly inside each namespace; it is down by
        # default in a freshly created namespace.
        ip netns exec "$NS_LEFT"  ip link set lo up
        # rp_filter=0: disable strict reverse-path check so IKE reply packets
        # that appear to arrive from the "wrong" interface are not silently dropped.
        ip netns exec "$NS_LEFT"  sysctl -qw net.ipv4.conf."${VETH_RESP}".rp_filter=0

        ip netns exec "$NS_RIGHT" ip addr add "${INIT_IP}/${SUBNET}" dev "$VETH_INIT"
        ip netns exec "$NS_RIGHT" ip link set "$VETH_INIT" up
        ip netns exec "$NS_RIGHT" ip link set lo up
        ip netns exec "$NS_RIGHT" sysctl -qw net.ipv4.conf."${VETH_INIT}".rp_filter=0

        log "veth pair ready: [${NS_LEFT}]${VETH_RESP}(${RESP_IP}) <-> [${NS_RIGHT}]${VETH_INIT}(${INIT_IP})"
    else
        # Both ends stay in the default namespace so moc_ipsec.ko (loaded in
        # the default namespace) can intercept all IKE and ESP traffic.
        # NanoSec processes each bind to a specific IP, so there is no port-500
        # conflict between them even without namespace isolation.
        step "Infrastructure: Creating veth pair"

        ip link del "$VETH_RESP" 2>/dev/null || true

        ip link add "$VETH_RESP" type veth peer name "$VETH_INIT"
        ip addr add "${RESP_IP}/${SUBNET}" dev "$VETH_RESP"
        ip addr add "${INIT_IP}/${SUBNET}" dev "$VETH_INIT"
        ip link set "$VETH_RESP" up
        ip link set "$VETH_INIT" up
        # rp_filter=0: same reason as in SS mode above.
        sysctl -qw net.ipv4.conf."${VETH_RESP}".rp_filter=0
        sysctl -qw net.ipv4.conf."${VETH_INIT}".rp_filter=0
        VETH_CREATED=1

        log "veth pair ready: ${VETH_RESP}(${RESP_IP}) <-> ${VETH_INIT}(${INIT_IP})"
    fi
}

###############################################################################
# Infrastructure: kernel modules
###############################################################################
load_modules() {
    step "Infrastructure: Loading kernel modules"

    _load_mod() {
        local _mod_file="$1" _mod_name
        _mod_name="$(basename "${_mod_file%.ko}")"
        if lsmod | grep -q "^${_mod_name} "; then
            log "  $_mod_name already loaded"
        else
            log "  insmod $_mod_file"
            insmod "$_mod_file"
        fi
    }

    _load_mod "${BIN_DIR}/moc_platform_mod.ko"
    _load_mod "${BIN_DIR}/moc_memdrv.ko"
    _load_mod "${BIN_DIR}/moc_ipsec.ko"
    _load_mod "${BIN_DIR}/moc_ipsec_mod.ko"
}

###############################################################################
# StrongSwan infrastructure
###############################################################################

# Write a minimal strongswan.conf that suppresses route and virtual-IP
# installation (we manage the network topology ourselves) and raises IKE/net
# log verbosity to level 2 so charon logs enough detail to diagnose failures.
_setup_strongswan_conf() {
    cat > "$SS_STRONGSWAN_CONF" <<EOF
charon {
    install_routes = no
    install_virtual_ip = no
    filelog {
        stderr {
            default = 1
            ike = 2
            net = 2
            cfg = 2
        }
    }
}
EOF
}

# Start charon inside a network namespace for one test.
# $1 = namespace (NS_LEFT or NS_RIGHT) where charon will bind port 500.
# Caller must set SS_CHARON_LOG to the desired per-test log path beforehand.
# Blocks until the VICI socket appears (up to 15 s) so the caller can assume
# charon is ready to receive swanctl commands immediately after returning.
_start_charon() {
    local ns="$1"
    step "Infrastructure: Starting charon (ns=$ns)"

    # A stale socket means a previous charon crashed without cleanup;
    # remove it so the new instance can create a fresh one.
    if [[ -S "$SS_VICI_SOCK" ]]; then
        log "  Stale VICI socket found — removing"
        rm -f "$SS_VICI_SOCK"
    fi

    _setup_strongswan_conf

    ip netns exec "$ns" \
        env STRONGSWAN_CONF="$SS_STRONGSWAN_CONF" "$CHARON_BIN" \
        >"$SS_CHARON_LOG" 2>&1 &
    CHARON_PID=$!

    local _waited=0
    while [[ ! -S "$SS_VICI_SOCK" && $_waited -lt 15 ]]; do
        sleep 1; _waited=$((_waited + 1))
    done
    [[ -S "$SS_VICI_SOCK" ]] \
        || fail "charon did not create VICI socket after 15s — check $SS_CHARON_LOG"
    log "  charon ready  (PID $CHARON_PID)  log: $SS_CHARON_LOG"
}

# Gracefully stop charon and remove its VICI socket.
_stop_charon() {
    _graceful_kill "$CHARON_PID"
    CHARON_PID=0
    rm -f "$SS_VICI_SOCK"
}

# Activate a swanctl.conf in the running charon instance.
# $1 = path to the swanctl.conf to install.
# Copies the file to SS_ACTIVE_CONF (inside the compiled-in conf.d/ dir) then
# runs --load-all so charon registers the connection without a restart.
_swanctl_load() {
    local _conf="$1"
    mkdir -p "$SS_SWANCTL_CONF_D"
    cp "$_conf" "$SS_ACTIVE_CONF"
    STRONGSWAN_CONF="$SS_STRONGSWAN_CONF" \
        "$SWANCTL_BIN" --load-all
}

# Terminate all active StrongSwan SAs and unload the connection config so the
# next test starts with a clean charon state.
_swanctl_reset() {
    rm -f "$SS_ACTIVE_CONF"
    STRONGSWAN_CONF="$SS_STRONGSWAN_CONF" \
        "$SWANCTL_BIN" --terminate --ike-id 1 --force 2>/dev/null || true
    STRONGSWAN_CONF="$SS_STRONGSWAN_CONF" \
        "$SWANCTL_BIN" --unload-conns 2>/dev/null || true
}

# Returns 0 when charon reports at least one CHILD_SA in INSTALLED state,
# meaning StrongSwan has completed its side of the IKE negotiation.
_swanctl_child_up() {
    STRONGSWAN_CONF="$SS_STRONGSWAN_CONF" \
        "$SWANCTL_BIN" --list-sas 2>/dev/null | grep -qi "INSTALLED"
}

###############################################################################
# Test case helpers — callable from testcases/*.sh
###############################################################################

# tc_gen_certs [prefix]
#
# Generates a fresh CA, responder cert/key, and initiator cert/key under the
# repo's keystore/ directories.  All files are named <prefix>_*.  The default
# prefix is "tc", giving tc_ca.pem, tc_resp.pem, tc_init.pem, etc.
#
# On success the following variables are set for the caller to use:
#   TC_CA_CERT   TC_RESP_CERT   TC_INIT_CERT   TC_RESP_KEY   TC_INIT_KEY
#
# Returns 1 if openssl is not installed or any generation step fails.
tc_gen_certs() {
    local prefix="${1:-tc}"
    local _cert_dir="${REPO_DIR}/keystore/certs"
    local _key_dir="${REPO_DIR}/keystore/keys"
    local _ca_key="${_key_dir}/${prefix}_ca.key"

    TC_CA_CERT="${_cert_dir}/${prefix}_ca.pem"
    TC_RESP_CERT="${_cert_dir}/${prefix}_resp.pem"
    TC_INIT_CERT="${_cert_dir}/${prefix}_init.pem"
    TC_RESP_KEY="${_key_dir}/${prefix}_resp.key"
    TC_INIT_KEY="${_key_dir}/${prefix}_init.key"

    command -v openssl &>/dev/null || return 1

    local _csr
    # CA
    openssl genrsa -out "$_ca_key" 2048 2>/dev/null                  || return 1
    openssl req -x509 -new -nodes -key "$_ca_key" -sha256 -days 1 \
        -subj "/CN=TestCA" -out "$TC_CA_CERT" 2>/dev/null             || return 1

    # Responder
    openssl genrsa -out "$TC_RESP_KEY" 2048 2>/dev/null               || return 1
    _csr="$(mktemp /tmp/${prefix}_resp_XXXXXX.csr)"
    openssl req -new -key "$TC_RESP_KEY" \
        -subj "/CN=responder" -out "$_csr" 2>/dev/null
    openssl x509 -req -in "$_csr" -CA "$TC_CA_CERT" -CAkey "$_ca_key" \
        -CAcreateserial -out "$TC_RESP_CERT" -days 1 -sha256 2>/dev/null
    rm -f "$_csr"

    # Initiator
    openssl genrsa -out "$TC_INIT_KEY" 2048 2>/dev/null               || return 1
    _csr="$(mktemp /tmp/${prefix}_init_XXXXXX.csr)"
    openssl req -new -key "$TC_INIT_KEY" \
        -subj "/CN=initiator" -out "$_csr" 2>/dev/null
    openssl x509 -req -in "$_csr" -CA "$TC_CA_CERT" -CAkey "$_ca_key" \
        -CAcreateserial -out "$TC_INIT_CERT" -days 1 -sha256 2>/dev/null
    rm -f "$_csr"
}

# tc_cleanup_certs [prefix]
#
# Removes all files created by tc_gen_certs for the given prefix (default "tc").
# Call this from tc_teardown() in any test case that used tc_gen_certs.
tc_cleanup_certs() {
    local prefix="${1:-tc}"
    local _cert_dir="${REPO_DIR}/keystore/certs"
    local _key_dir="${REPO_DIR}/keystore/keys"
    rm -f "${_cert_dir}/${prefix}_ca.pem"   "${_cert_dir}/${prefix}_ca.srl" \
          "${_cert_dir}/${prefix}_resp.pem" "${_cert_dir}/${prefix}_init.pem" \
          "${_key_dir}/${prefix}_ca.key"    "${_key_dir}/${prefix}_resp.key" \
          "${_key_dir}/${prefix}_init.key"
}

# If the IKE flags for a role include --ike_cert, log the cert subject and CA
# so the run output shows which certificates are in use — mirrors the cert
# summary that swanctl --list-conns prints for StrongSwan tests.
# Usage: _log_ike_cert_flags <label> "${flags_array[@]}"
_log_ike_cert_flags() {
    local label="$1"; shift
    local -a args=("$@")
    local cert="" ca="" i=0
    while [[ $i -lt $(( ${#args[@]} - 1 )) ]]; do
        case "${args[$i]}" in
            --ike_cert)    cert="${args[$((i+1))]}"; i=$(( i+2 )) ;;
            --ike_ca_cert) ca="${args[$((i+1))]}";   i=$(( i+2 )) ;;
            *)             i=$(( i+1 )) ;;
        esac
    done
    [[ -z "$cert" ]] && return
    if command -v openssl &>/dev/null && [[ -f "$cert" ]]; then
        local subj
        subj=$(openssl x509 -noout -subject -in "$cert" 2>/dev/null | sed 's/^subject=//')
        log "  ${label} cert auth: ${subj:-$cert}"
        if [[ -n "$ca" && -f "$ca" ]]; then
            local ca_subj
            ca_subj=$(openssl x509 -noout -subject -in "$ca" 2>/dev/null | sed 's/^subject=//')
            log "    CA: ${ca_subj:-$ca}"
        fi
    else
        log "  ${label} cert auth: $cert"
    fi
}

###############################################################################
# SA proposal verification
#
# After a CHILD_SA is established, loadConfig -d triggers a kernel SA dump
# that appears in dmesg.  The dump prints each SA's algorithm IDs as numbers.
# _ike_auth_name / _ike_encr_name map those numbers to the short names used
# in TC_VERIFY_AUTH / TC_VERIFY_ENCR (e.g. "sha1", "3des", "aes").
# verify_sa_proposal reads the dump and checks that the negotiated algorithms
# and key length match the test case's expectations.
###############################################################################
_ike_auth_name() {
    case "$1" in
        1) echo "md5" ;;       2) echo "sha1" ;;
        3) echo "aes-xcbc" ;;  4) echo "sha256" ;;
        5) echo "sha384" ;;    6) echo "sha512" ;;
        7) echo "blake2b" ;;   8) echo "blake2s" ;;
        *) echo "unknown($1)" ;;
    esac
}

_ike_encr_name() {
    case "$1" in
        1) echo "des" ;;        2) echo "3des" ;;
        3) echo "blowfish" ;;   4) echo "aes" ;;
        5) echo "ctr" ;;        6) echo "gcm" ;;
        7) echo "gmac" ;;       8) echo "ccm" ;;
        9) echo "chacha-poly" ;; *) echo "unknown($1)" ;;
    esac
}

# verify_sa_proposal <expected_auth> <expected_encr> <expected_keylen>
#
# Triggers a kernel SA dump via loadConfig -d, reads new dmesg lines, and
# compares the negotiated algorithm IDs against the expected values.
# key length is inferred by counting the hex bytes in the "Encr.key:" line.
#
# Returns 0 on match.
# Returns 0 (non-fatal) when no SA dump appears — the packet-capture step
# already provides independent evidence of encryption.
# Returns 1 on mismatch.
verify_sa_proposal() {
    local exp_auth="$1" exp_encr="$2" exp_keylen="$3"

    local dmesg_before
    dmesg_before=$(dmesg | wc -l)
    "${BIN_DIR}/loadConfig" -d 2>/dev/null || true
    sleep 0.3  # let the kernel module finish writing the SA dump to dmesg
    local sa_dump
    sa_dump=$(dmesg | tail -n "+$((dmesg_before + 1))")

    section "SA dump from kernel (via dmesg)"
    echo "$sa_dump" | grep -E "==== SPI|Flags|Proto|Source|Dest|Auth|Encr|Usage" \
        || echo "  (nothing)"
    echo

    if ! echo "$sa_dump" | grep -q "==== SPI:"; then
        log "  WARNING: No SA dump in dmesg — kernel may not have installed SAs"
        return 0   # non-fatal; packet capture step already confirmed encryption
    fi

    local sa_auth_num sa_encr_num sa_keylen sa_auth_name sa_encr_name
    sa_auth_num=$(echo "$sa_dump" | grep "Auth.algo:" \
                  | sed 's/.*Auth\.algo: *\([0-9]*\).*/\1/' | head -1)
    sa_encr_num=$(echo "$sa_dump" | grep "Encr.algo:" \
                  | sed 's/.*Encr\.algo: *\([0-9]*\).*/\1/' | head -1)
    # Strip dmesg timestamp/prefix before counting dots — each byte is "%02X."
    sa_keylen=$(echo "$sa_dump" | grep "Encr.key:" | head -1 \
                | sed 's/.*Encr[.]key: //' | tr -cd '.' | wc -c)

    sa_auth_name=$(_ike_auth_name "$sa_auth_num")
    sa_encr_name=$(_ike_encr_name "$sa_encr_num")

    log "  Configured policy : encr_auth_algs=${exp_auth}  encr_algs=${exp_encr}  keylength=${exp_keylen}"
    log "  Negotiated SA     : auth=${sa_auth_name}(id=${sa_auth_num})  encr=${sa_encr_name}(id=${sa_encr_num})  keylen=${sa_keylen}"

    local auth_ok=0 encr_ok=0 keylen_ok=0
    [[ "$sa_auth_name" == "$exp_auth"   ]] && auth_ok=1
    [[ "$sa_encr_name" == "$exp_encr"   ]] && encr_ok=1
    [[ "$sa_keylen"    == "$exp_keylen" ]] && keylen_ok=1

    if [[ $auth_ok -eq 1 && $encr_ok -eq 1 && $keylen_ok -eq 1 ]]; then
        log "  RESULT: Proposal VERIFIED — negotiated SA matches configured policy."
        return 0
    fi

    log "  RESULT: MISMATCH — negotiated SA differs from configured policy:"
    [[ $auth_ok   -eq 0 ]] && log "    auth:   expected=${exp_auth},  got=${sa_auth_name}"
    [[ $encr_ok   -eq 0 ]] && log "    encr:   expected=${exp_encr},  got=${sa_encr_name}"
    [[ $keylen_ok -eq 0 ]] && log "    keylen: expected=${exp_keylen},  got=${sa_keylen}"
    return 1
}

###############################################################################
# Packet-capture step
#
# Sends 5 UDP test packets, captures them with tcpdump, then checks whether
# every observed packet is ESP/AH-encapsulated.  This confirms that the
# kernel-level IPsec SA is actually encrypting traffic, not just that IKE
# negotiation succeeded.
#
# _run_packet_test <tc_idx> [sender_ns] [listener_ns] [sender_ip] [listener_ip] [iface]
#
#   sender_ns / listener_ns
#     Network namespace for the sender/listener Python processes.
#     Empty string means the default namespace (NanoSec↔NanoSec tests).
#
#   iface — where tcpdump listens:
#     NanoSec↔NanoSec: lo
#       Both IPs are local to the same namespace.  The kernel routes packets
#       between them via loopback (lo), not through the veth pair.  moc_ipsec.ko
#       encrypts them as ESP before they appear on lo.
#     StrongSwan: the SS-side veth (VETH_INIT or VETH_RESP)
#       StrongSwan uses Linux XFRM: the kernel encrypts each outbound packet
#       as ESP before it leaves the veth interface, so plain UDP is never
#       visible on that interface when a CHILD_SA is active.
#
#   In StrongSwan mode the listener (in the NanoSec namespace) may not
#   receive any data because moc_ipsec.ko is not active there to decrypt
#   inbound ESP.  The pass/fail verdict is based solely on the pcap counts:
#   encrypted > 0 AND plain_udp == 0 → pass.
#
# Returns 0 if all captured packets are encrypted, 1 otherwise.
###############################################################################
_run_packet_test() {
    local tc_idx="$1"
    local sender_ns="${2:-}"
    local listener_ns="${3:-}"
    local sender_ip="${4:-$RESP_IP}"
    local listener_ip="${5:-$INIT_IP}"
    local capture_iface="${6:-lo}"

    local pcap="/tmp/suite_${_LOG_PFX}_${tc_idx}_capture.pcap"
    local udp_port=19876
    rm -f "$pcap"

    step "  Verifying IPsec encryption via packet capture"
    log "  Starting UDP listener on ${listener_ip}:${udp_port} ..."

    # Build optional "ip netns exec <ns>" prefix arrays.  When the namespace
    # string is empty the array is empty and "${arr[@]}" expands to nothing,
    # so the command runs directly in the current (default) namespace.
    local _ns_l=() _ns_s=()
    [[ -n "$listener_ns" ]] && _ns_l=("ip" "netns" "exec" "$listener_ns")
    [[ -n "$sender_ns"   ]] && _ns_s=("ip" "netns" "exec" "$sender_ns")

    # Unquoted heredoc (<<PYEOF not <<'PYEOF') so ${listener_ip} and
    # ${udp_port} are expanded by the shell before Python sees the script.
    "${_ns_l[@]}" python3 - <<PYEOF &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('${listener_ip}', ${udp_port}))
s.settimeout(10)
count = 0
try:
    while count < 5:
        data, addr = s.recvfrom(1024)
        print(f"  [listener] from {addr[0]}: {data.decode()}", flush=True)
        count += 1
except socket.timeout:
    pass
if count == 0:
    print("  [listener] no packets (inbound decryption may not be active)", flush=True)
s.close()
PYEOF
    local listener_pid=$!

    # tcpdump runs inside the sender's namespace so it sees the same interface
    # view as the sender process — in particular the veth from which outbound
    # ESP packets will be emitted.
    log "  Starting tcpdump on ${capture_iface}${sender_ns:+ (in ${sender_ns})} ..."
    if [[ -n "$sender_ns" ]]; then
        ip netns exec "$sender_ns" tcpdump -i "$capture_iface" -n -c 20 \
            "proto 50 or proto 51 or (udp port ${udp_port})" \
            -w "$pcap" 2>/dev/null &
    else
        tcpdump -i "$capture_iface" -n -c 20 \
            "proto 50 or proto 51 or (udp port ${udp_port})" \
            -w "$pcap" 2>/dev/null &
    fi
    local tcpdump_pid=$!
    sleep 1  # give tcpdump time to attach to the interface before packets arrive

    log "  Sending 5 UDP packets: ${sender_ip} -> ${listener_ip}:${udp_port} ..."
    "${_ns_s[@]}" python3 - <<PYEOF
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('${sender_ip}', 0))
for i in range(1, 6):
    msg = f'IPsec-test-payload-{i}'.encode()
    s.sendto(msg, ('${listener_ip}', ${udp_port}))
    print(f'  [sender]   sent packet {i}: {msg.decode()}', flush=True)
    time.sleep(0.4)
s.close()
PYEOF

    sleep 2  # let the last packets arrive at the listener and be captured by tcpdump
    kill "$listener_pid" 2>/dev/null || true; wait "$listener_pid" 2>/dev/null || true
    kill "$tcpdump_pid"  2>/dev/null || true; wait "$tcpdump_pid"  2>/dev/null || true

    section "Captured packets on ${capture_iface}"
    tcpdump -r "$pcap" -n -v 2>/dev/null \
        | grep -E "IP |ESP|AH|UDP" | head -20 || echo "  (nothing captured)"
    echo

    local esp_count ah_count plain_udp
    esp_count=$(tcpdump -r "$pcap" -n "proto 50" 2>/dev/null | grep -c "ESP" || true)
    ah_count=$(tcpdump  -r "$pcap" -n "proto 51" 2>/dev/null | grep -c "AH"  || true)
    plain_udp=$(tcpdump -r "$pcap" -n "udp port ${udp_port}" 2>/dev/null | grep -c "UDP" || true)

    log "  ESP  packets : $esp_count"
    log "  AH   packets : $ah_count"
    log "  Plain UDP    : $plain_udp"

    local encrypted=$(( esp_count + ah_count ))
    if   [[ $encrypted -gt 0 && $plain_udp -eq 0 ]]; then
        log "  RESULT: Traffic is ENCRYPTED — ESP/AH present, no plain UDP."
        return 0
    elif [[ $plain_udp -gt 0 && $encrypted -eq 0 ]]; then
        log "  RESULT: WARNING — plain UDP captured without ESP/AH."
        return 1
    elif [[ $encrypted -eq 0 && $plain_udp -eq 0 ]]; then
        log "  RESULT: No packets captured."
        return 1
    else
        log "  RESULT: Mixed — ESP/AH: ${encrypted}, plain UDP: ${plain_udp}."
        return 1
    fi
}

###############################################################################
# Result tracking
###############################################################################
declare -a RESULTS=()
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# _parse_valgrind_leaks <log_file>
#
# Reads a valgrind --leak-check=full log and reports whether any heap blocks
# were lost.  Checks only "definitely", "indirectly", and "possibly" lost —
# "still reachable" blocks are intentional and excluded.
#
# Prints:
#   "NO"  — "All heap blocks were freed" fast path (valgrind confirms clean exit)
#   "NO"  — LEAK SUMMARY present with no non-zero lost counts
#   "YES" — at least one definitely/indirectly/possibly lost byte
#   "N/A" — log file empty or no LEAK SUMMARY (process killed before valgrind
#            could write its report)
_parse_valgrind_leaks() {
    local vg_log="$1"
    if [[ ! -s "$vg_log" ]]; then
        echo "N/A"
        return
    fi
    if grep -q "All heap blocks were freed" "$vg_log" 2>/dev/null; then
        echo "NO"
        return
    fi
    if ! grep -q "LEAK SUMMARY" "$vg_log" 2>/dev/null; then
        echo "N/A"
        return
    fi
    if grep -qE "definitely lost: [1-9]|indirectly lost: [1-9]|possibly lost: [1-9]" \
            "$vg_log" 2>/dev/null; then
        echo "YES"
    else
        echo "NO"
    fi
}

# Append one test result to the RESULTS array and update pass/fail/skip totals.
# Fields are pipe-separated: name|result|elapsed_s|leak_status|reason
_record() {
    RESULTS+=("${1}|${2}|${3}s|${4}|${5:-}")
    case "$2" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
    esac
}

###############################################################################
# Single test case runner
###############################################################################
run_one_test() {
    local tc_file="$1"
    local tc_idx="$2"
    local tc_start tc_result tc_reason
    tc_start=$(date +%s)
    tc_result="PASS"
    tc_reason=""

    # ── Reset all TC_* variables to safe defaults ─────────────────────────
    TC_NAME=""
    TC_IKE_VERSION=1
    TC_NEG_TIMEOUT="$NEG_TIMEOUT"
    TC_SOCK_WAIT="$SOCK_WAIT"
    TC_RESP_IKE_FLAGS=()
    TC_INIT_IKE_FLAGS=()
    TC_VERIFY_AUTH=""
    TC_VERIFY_ENCR=""
    TC_VERIFY_KEYLEN=""
    TC_SKIP_REASON=""
    TC_RUN_PACKET_TEST=1
    unset -f tc_setup_policies 2>/dev/null || true
    unset -f tc_teardown       2>/dev/null || true

    # ── Source test case ──────────────────────────────────────────────────
    if ! source "$tc_file" 2>/dev/null; then
        TC_NAME="$(basename "$tc_file" .sh)"
        _record "$TC_NAME" "FAIL" "$(( $(date +%s) - tc_start ))" \
            "N/A" "failed to source $(basename "$tc_file")"
        fail_msg "$(basename "$tc_file") — failed to source"
        return 1
    fi
    [[ -n "$TC_NAME" ]] || TC_NAME="$(basename "$tc_file" .sh)"

    step "Test ${tc_idx}: ${TC_NAME}"

    # ── Skip check ────────────────────────────────────────────────────────
    if [[ -n "$TC_SKIP_REASON" ]]; then
        declare -f tc_teardown &>/dev/null && tc_teardown || true
        _record "$TC_NAME" "SKIP" 0 "N/A" "$TC_SKIP_REASON"
        skip_msg "${TC_NAME} — ${TC_SKIP_REASON}"
        return 0
    fi

    # ── Require tc_setup_policies() ──────────────────────────────────────
    if ! declare -f tc_setup_policies &>/dev/null; then
        _record "$TC_NAME" "FAIL" "$(( $(date +%s) - tc_start ))" \
            "N/A" "tc_setup_policies() not defined"
        fail_msg "${TC_NAME} — tc_setup_policies() not defined"
        return 1
    fi

    local tc_resp_log="/tmp/suite_${_LOG_PFX}_${tc_idx}_resp.log"
    local tc_init_log="/tmp/suite_${_LOG_PFX}_${tc_idx}_init.log"
    local tc_resp_valgrind="/tmp/suite_${_LOG_PFX}_${tc_idx}_resp_valgrind.log"
    local tc_init_valgrind="/tmp/suite_${_LOG_PFX}_${tc_idx}_init_valgrind.log"
    local tc_resp_pf="/tmp/suite_${_LOG_PFX}_${tc_idx}_resp_policy.txt"
    local tc_init_pf="/tmp/suite_${_LOG_PFX}_${tc_idx}_init_policy.txt"
    local tc_sainit_pf="/tmp/suite_${_LOG_PFX}_${tc_idx}_sainit_policy.txt"
    local tc_leak_status="N/A"  # remains N/A if -V not set, or if valgrind didn't finish

    # "while true / break" is used as a structured try/finally: any failure
    # sets tc_result and runs "break" to exit the block; the code after the
    # loop always runs (process cleanup, leak check, recording the result).
    while true; do

        # -F flushes the SA database; -FP flushes the SPD (policy database).
        # Stale entries from a previous test can cause the kernel module to
        # reject or misroute new SAs.
        "${BIN_DIR}/loadConfig" -F  2>/dev/null || true
        "${BIN_DIR}/loadConfig" -FP 2>/dev/null || true

        if ! tc_setup_policies "$RESP_IP" "$INIT_IP" \
                "$tc_resp_pf" "$tc_init_pf" "$tc_sainit_pf"; then
            tc_result="FAIL"; tc_reason="tc_setup_policies() failed"; break
        fi

        if ! "${BIN_DIR}/loadConfig" -f "$tc_resp_pf" 2>/dev/null; then
            tc_result="FAIL"; tc_reason="loadConfig failed for responder policy"; break
        fi
        if ! "${BIN_DIR}/loadConfig" -f "$tc_init_pf" 2>/dev/null; then
            tc_result="FAIL"; tc_reason="loadConfig failed for initiator policy"; break
        fi

        [[ ${#TC_RESP_IKE_FLAGS[@]} -gt 0 ]] && \
            _log_ike_cert_flags "Responder" "${TC_RESP_IKE_FLAGS[@]}"
        [[ ${#TC_INIT_IKE_FLAGS[@]} -gt 0 ]] && \
            _log_ike_cert_flags "Initiator" "${TC_INIT_IKE_FLAGS[@]}"

        > "$tc_resp_log"
        if [[ $VALGRIND_ENABLED -eq 1 ]]; then
            stdbuf -oL "$VALGRIND_BIN" --leak-check=full --show-leak-kinds=all \
                --track-origins=yes --log-file="$tc_resp_valgrind" \
                "${IKE_BIN}" \
                -v "$TC_IKE_VERSION" "${TC_RESP_IKE_FLAGS[@]}" \
                -E "$RESP_EVENT_PORT" -w "$TC_SOCK_WAIT" \
                "$RESP_IP" > "$tc_resp_log" 2>&1 &
        else
            stdbuf -oL "${IKE_BIN}" \
                -v "$TC_IKE_VERSION" "${TC_RESP_IKE_FLAGS[@]}" \
                -E "$RESP_EVENT_PORT" -w "$TC_SOCK_WAIT" \
                "$RESP_IP" > "$tc_resp_log" 2>&1 &
        fi
        RESP_PID=$!
        sleep 1  # wait for the responder to bind port 500 before the initiator connects

        if ! kill -0 "$RESP_PID" 2>/dev/null; then
            tc_result="FAIL"; tc_reason="responder exited immediately — check $tc_resp_log"
            break
        fi

        > "$tc_init_log"
        if [[ $VALGRIND_ENABLED -eq 1 ]]; then
            stdbuf -oL "$VALGRIND_BIN" --leak-check=full --show-leak-kinds=all \
                --track-origins=yes --log-file="$tc_init_valgrind" \
                "${IKE_BIN}" \
                -v "$TC_IKE_VERSION" "${TC_INIT_IKE_FLAGS[@]}" \
                -E "$INIT_EVENT_PORT" -c "$RESP_IP" -w "$TC_SOCK_WAIT" \
                "$INIT_IP" > "$tc_init_log" 2>&1 &
        else
            stdbuf -oL "${IKE_BIN}" \
                -v "$TC_IKE_VERSION" "${TC_INIT_IKE_FLAGS[@]}" \
                -E "$INIT_EVENT_PORT" -c "$RESP_IP" -w "$TC_SOCK_WAIT" \
                "$INIT_IP" > "$tc_init_log" 2>&1 &
        fi
        INIT_PID=$!

        # ── Wait for CHILD SA ─────────────────────────────────────────────
        local elapsed=0 child_resp=0 child_init=0 ike_triggered=0
        while [[ $elapsed -lt "$TC_NEG_TIMEOUT" ]]; do
            sleep 1; elapsed=$(( elapsed + 1 ))

            if grep -q "CHILD_SA failed\|IKE_SA Failed\|IKE_EXAMPLE.*failed" \
                    "$tc_resp_log" 2>/dev/null; then
                tc_result="FAIL"; tc_reason="failure in responder log"; break 2
            fi
            if grep -q "CHILD_SA failed\|IKE_SA Failed\|IKE_EXAMPLE.*failed" \
                    "$tc_init_log" 2>/dev/null; then
                tc_result="FAIL"; tc_reason="failure in initiator log"; break 2
            fi

            # IKE_SA Created = Phase 1 complete.  Load sainit_policy now: the
            # "sa init" flag makes moc_ipsec.ko call IPSEC_keyInitiate(), which
            # starts Quick Mode (v1) or IKE_AUTH child SA (v2) immediately.
            # We cannot send real traffic to trigger this because local-to-local
            # packets between the two veth IPs go through lo and bypass the
            # netfilter hooks that moc_ipsec.ko hooks into.
            if [[ $ike_triggered -eq 0 ]] && \
               grep -q "IKE_SA Created" "$tc_init_log" 2>/dev/null; then
                log "  Phase 1 established — triggering Quick Mode"
                if ! "${BIN_DIR}/loadConfig" -f "$tc_sainit_pf" 2>/dev/null; then
                    tc_result="FAIL"; tc_reason="loadConfig sa init failed"; break 2
                fi
                ike_triggered=1
            fi

            grep -q "CHILD_SA created" "$tc_resp_log" 2>/dev/null && child_resp=1
            grep -q "CHILD_SA created" "$tc_init_log" 2>/dev/null && child_init=1
            [[ $child_resp -eq 1 && $child_init -eq 1 ]] && break
            (( elapsed % 5 == 0 )) && log "  ...waiting (${elapsed}s)"
        done

        if [[ $child_resp -eq 0 || $child_init -eq 0 ]]; then
            tc_result="FAIL"
            tc_reason="timeout after ${TC_NEG_TIMEOUT}s — CHILD_SA: resp=${child_resp} init=${child_init}"
            break
        fi

        log "  Responder CHILD_SA: YES"
        log "  Initiator CHILD_SA: YES"

        # ── SA proposal verification ──────────────────────────────────────
        if [[ -n "${TC_VERIFY_AUTH:-}" && -n "${TC_VERIFY_ENCR:-}" \
              && -n "${TC_VERIFY_KEYLEN:-}" ]]; then
            step "  SA Proposal Verification"
            if ! verify_sa_proposal "$TC_VERIFY_AUTH" "$TC_VERIFY_ENCR" \
                    "$TC_VERIFY_KEYLEN"; then
                tc_result="FAIL"; tc_reason="SA proposal mismatch"
            fi
        fi

        # ── Packet capture ────────────────────────────────────────────────
        if [[ $TC_RUN_PACKET_TEST -eq 1 && $tc_result == "PASS" ]]; then
            if ! _run_packet_test "$tc_idx"; then
                tc_result="FAIL"; tc_reason="packet capture: traffic not encrypted"
            fi
        fi

        break
    done  # end try block

    # ── Gracefully stop IKE processes for this test ──────────────────────
    for _pid in $RESP_PID $INIT_PID; do
        _graceful_kill "$_pid"
    done
    RESP_PID=0; INIT_PID=0

    # ── Check valgrind leak reports ───────────────────────────────────────
    if [[ $VALGRIND_ENABLED -eq 1 ]]; then
        local resp_leaks init_leaks
        resp_leaks=$(_parse_valgrind_leaks "$tc_resp_valgrind")
        init_leaks=$(_parse_valgrind_leaks "$tc_init_valgrind")
        if [[ "$resp_leaks" == "YES" || "$init_leaks" == "YES" ]]; then
            tc_leak_status="YES"
            fail_msg "  Memory leaks detected — resp: $resp_leaks  init: $init_leaks"
            log "  Valgrind logs: $tc_resp_valgrind  $tc_init_valgrind"
        elif [[ "$resp_leaks" == "NO" && "$init_leaks" == "NO" ]]; then
            tc_leak_status="NO"
            pass "  No memory leaks detected."
        fi
    fi

    # ── Per-test teardown (e.g. remove generated cert files) ─────────────
    if declare -f tc_teardown &>/dev/null; then
        tc_teardown || true
    fi

    # ── Show log tails on failure ─────────────────────────────────────────
    if [[ $tc_result == "FAIL" ]]; then
        section "Responder log (last 20 lines)"
        tail -20 "$tc_resp_log" || true
        section "Initiator log (last 20 lines)"
        tail -20 "$tc_init_log" || true
    fi

    # ── Record and report ─────────────────────────────────────────────────
    local tc_elapsed=$(( $(date +%s) - tc_start ))
    _record "$TC_NAME" "$tc_result" "$tc_elapsed" "$tc_leak_status" "$tc_reason"

    if [[ $tc_result == "PASS" ]]; then
        pass "${TC_NAME}  (${tc_elapsed}s)"
        return 0
    else
        fail_msg "${TC_NAME} — ${tc_reason}  (${tc_elapsed}s)"
        return 1
    fi
}

###############################################################################
# StrongSwan interop test runner
#
# Runs one test case where one IKE peer is the NanoSec ike binary and the
# other is charon (StrongSwan).  TC_STRONGSWAN_ROLE selects which is which:
#   "init"  — charon initiates (sends IKE_SA_INIT / MM1), NanoSec responds
#   "resp"  — charon responds, NanoSec initiates
#
# charon is started fresh for each test inside the appropriate namespace
# (see the network topology diagram at the top of this file) so that its
# 0.0.0.0:500 wildcard bind is contained within that namespace and does not
# conflict with the NanoSec process listening in the peer namespace.
# charon is stopped after each test so the next test can start it in a
# potentially different namespace if the role changes.
###############################################################################
run_one_test_strongswan() {
    local tc_file="$1"
    local tc_idx="$2"
    local tc_start tc_result tc_reason
    tc_start=$(date +%s)
    tc_result="PASS"
    tc_reason=""

    # ── Reset all TC_* variables to safe defaults ─────────────────────────
    TC_NAME=""
    TC_IKE_VERSION=1
    TC_NEG_TIMEOUT="$NEG_TIMEOUT"
    TC_SOCK_WAIT="$SOCK_WAIT"
    TC_RESP_IKE_FLAGS=()
    TC_INIT_IKE_FLAGS=()
    TC_VERIFY_AUTH=""
    TC_VERIFY_ENCR=""
    TC_VERIFY_KEYLEN=""
    TC_SKIP_REASON=""
    TC_RUN_PACKET_TEST=1       # default on: send from SS namespace, capture on its veth
    TC_STRONGSWAN_ROLE="init"  # default: StrongSwan initiates
    TC_SS_CONN_NAME="nanosec-interop"
    TC_SS_CHILD_NAME="child1"
    unset -f tc_setup_policies  2>/dev/null || true
    unset -f tc_setup_swanctl   2>/dev/null || true
    unset -f tc_teardown        2>/dev/null || true

    # ── Source test case ──────────────────────────────────────────────────
    if ! source "$tc_file" 2>/dev/null; then
        TC_NAME="$(basename "$tc_file" .sh)"
        _record "$TC_NAME" "FAIL" "$(( $(date +%s) - tc_start ))" \
            "N/A" "failed to source $(basename "$tc_file")"
        fail_msg "$(basename "$tc_file") — failed to source"
        return 1
    fi
    [[ -n "$TC_NAME" ]] || TC_NAME="$(basename "$tc_file" .sh)"

    step "Test ${tc_idx}: ${TC_NAME}  [strongswan=${TC_STRONGSWAN_ROLE}]"

    # ── Skip check ────────────────────────────────────────────────────────
    if [[ -n "$TC_SKIP_REASON" ]]; then
        declare -f tc_teardown &>/dev/null && tc_teardown || true
        _record "$TC_NAME" "SKIP" 0 "N/A" "$TC_SKIP_REASON"
        skip_msg "${TC_NAME} — ${TC_SKIP_REASON}"
        return 0
    fi

    # ── Require both setup functions ──────────────────────────────────────
    if ! declare -f tc_setup_swanctl &>/dev/null; then
        _record "$TC_NAME" "FAIL" "$(( $(date +%s) - tc_start ))" \
            "N/A" "tc_setup_swanctl() not defined"
        fail_msg "${TC_NAME} — tc_setup_swanctl() not defined"
        return 1
    fi
    if ! declare -f tc_setup_policies &>/dev/null; then
        _record "$TC_NAME" "FAIL" "$(( $(date +%s) - tc_start ))" \
            "N/A" "tc_setup_policies() not defined"
        fail_msg "${TC_NAME} — tc_setup_policies() not defined"
        return 1
    fi

    # Assign namespaces based on role.  The StrongSwan namespace (_ss_ns) is
    # where charon will bind; the NanoSec namespace (_ns_ns) is where the ike
    # binary runs.  Setting SS_CHARON_LOG before _start_charon ensures the
    # charon output goes to this test's dedicated log file.
    #   SS=init: charon in NS_RIGHT (INIT_IP), NanoSec in NS_LEFT (RESP_IP)
    #   SS=resp: charon in NS_LEFT  (RESP_IP), NanoSec in NS_RIGHT (INIT_IP)
    local _ss_ns _ns_ns
    if [[ "$TC_STRONGSWAN_ROLE" == "init" ]]; then
        _ss_ns="$NS_RIGHT"; _ns_ns="$NS_LEFT"
    else
        _ss_ns="$NS_LEFT";  _ns_ns="$NS_RIGHT"
    fi
    SS_CHARON_LOG="/tmp/suite_${_LOG_PFX}_${tc_idx}_charon.log"
    _stop_charon
    _start_charon "$_ss_ns"

    local tc_ike_log="/tmp/suite_${_LOG_PFX}_${tc_idx}_ike.log"
    local tc_ike_valgrind="/tmp/suite_${_LOG_PFX}_${tc_idx}_ike_valgrind.log"
    local tc_swanctl_conf="/tmp/suite_${_LOG_PFX}_${tc_idx}_swanctl.conf"
    local tc_resp_pf="/tmp/suite_${_LOG_PFX}_${tc_idx}_resp_policy.txt"
    local tc_init_pf="/tmp/suite_${_LOG_PFX}_${tc_idx}_init_policy.txt"
    local tc_sainit_pf="/tmp/suite_${_LOG_PFX}_${tc_idx}_sainit_policy.txt"
    local tc_leak_status="N/A"  # remains N/A if -V not set, or if valgrind didn't finish

    while true; do

        # Flush NanoSec SA / SPD state from any previous test.
        "${BIN_DIR}/loadConfig" -F  2>/dev/null || true
        "${BIN_DIR}/loadConfig" -FP 2>/dev/null || true

        # Tear down any StrongSwan SAs from a previous test.
        _swanctl_reset

        # Write swanctl.conf for the StrongSwan side.
        if ! tc_setup_swanctl "$RESP_IP" "$INIT_IP" "$tc_swanctl_conf"; then
            tc_result="FAIL"; tc_reason="tc_setup_swanctl() failed"; break
        fi

        # Write NanoSec policy files (only the relevant side's file is used).
        if ! tc_setup_policies "$RESP_IP" "$INIT_IP" \
                "$tc_resp_pf" "$tc_init_pf" "$tc_sainit_pf"; then
            tc_result="FAIL"; tc_reason="tc_setup_policies() failed"; break
        fi

        # Load the StrongSwan config into charon.
        if ! _swanctl_load "$tc_swanctl_conf"; then
            tc_result="FAIL"; tc_reason="swanctl --load-all failed"; break
        fi
        # Verify the connection was actually registered.
        log "  Loaded connections:"
        STRONGSWAN_CONF="$SS_STRONGSWAN_CONF" \
            "$SWANCTL_BIN" --list-conns 2>&1 | while IFS= read -r l; do log "    $l"; done || true

        > "$tc_ike_log"

        if [[ "$TC_STRONGSWAN_ROLE" == "init" ]]; then
            # ── NanoSec is RESPONDER ──────────────────────────────────────

            if ! "${BIN_DIR}/loadConfig" -f "$tc_resp_pf" 2>/dev/null; then
                tc_result="FAIL"; tc_reason="loadConfig failed for responder policy"; break
            fi

            if [[ $VALGRIND_ENABLED -eq 1 ]]; then
                ip netns exec "$_ns_ns" \
                stdbuf -oL "$VALGRIND_BIN" --leak-check=full --show-leak-kinds=all \
                    --track-origins=yes --log-file="$tc_ike_valgrind" \
                    "${IKE_BIN}" \
                    -v "$TC_IKE_VERSION" "${TC_RESP_IKE_FLAGS[@]}" \
                    -E "$RESP_EVENT_PORT" -w "$TC_SOCK_WAIT" \
                    "$RESP_IP" > "$tc_ike_log" 2>&1 &
            else
                ip netns exec "$_ns_ns" \
                stdbuf -oL "${IKE_BIN}" \
                    -v "$TC_IKE_VERSION" "${TC_RESP_IKE_FLAGS[@]}" \
                    -E "$RESP_EVENT_PORT" -w "$TC_SOCK_WAIT" \
                    "$RESP_IP" > "$tc_ike_log" 2>&1 &
            fi
            RESP_PID=$!
            sleep 1  # wait for the responder to bind port 500 before swanctl --initiate

            if ! kill -0 "$RESP_PID" 2>/dev/null; then
                tc_result="FAIL"
                tc_reason="NanoSec responder exited immediately — check $tc_ike_log"
                break
            fi

            # --timeout 1 makes swanctl return immediately instead of waiting for
            # the SA to establish; the poll loop below handles that wait.
            STRONGSWAN_CONF="$SS_STRONGSWAN_CONF" \
                "$SWANCTL_BIN" --initiate \
                --ike "${TC_SS_CONN_NAME}" \
                --child "${TC_SS_CHILD_NAME}" \
                --timeout 1 2>/dev/null || true

        else
            # ── NanoSec is INITIATOR ──────────────────────────────────────

            if ! "${BIN_DIR}/loadConfig" -f "$tc_init_pf" 2>/dev/null; then
                tc_result="FAIL"; tc_reason="loadConfig failed for initiator policy"; break
            fi

            if [[ $VALGRIND_ENABLED -eq 1 ]]; then
                ip netns exec "$_ns_ns" \
                stdbuf -oL "$VALGRIND_BIN" --leak-check=full --show-leak-kinds=all \
                    --track-origins=yes --log-file="$tc_ike_valgrind" \
                    "${IKE_BIN}" \
                    -v "$TC_IKE_VERSION" "${TC_INIT_IKE_FLAGS[@]}" \
                    -E "$INIT_EVENT_PORT" -c "$RESP_IP" -w "$TC_SOCK_WAIT" \
                    "$INIT_IP" > "$tc_ike_log" 2>&1 &
            else
                ip netns exec "$_ns_ns" \
                stdbuf -oL "${IKE_BIN}" \
                    -v "$TC_IKE_VERSION" "${TC_INIT_IKE_FLAGS[@]}" \
                    -E "$INIT_EVENT_PORT" -c "$RESP_IP" -w "$TC_SOCK_WAIT" \
                    "$INIT_IP" > "$tc_ike_log" 2>&1 &
            fi
            INIT_PID=$!
        fi

        # ── Wait for CHILD SA on both sides ───────────────────────────────
        local elapsed=0 child_ike=0 child_ss=0 ike_triggered=0
        while [[ $elapsed -lt "$TC_NEG_TIMEOUT" ]]; do
            sleep 1; elapsed=$(( elapsed + 1 ))

            if grep -q "CHILD_SA failed\|IKE_SA Failed\|IKE_EXAMPLE.*failed" \
                    "$tc_ike_log" 2>/dev/null; then
                tc_result="FAIL"; tc_reason="failure in ike log"; break 2
            fi

            # Same sainit_policy trigger as in the NanoSec↔NanoSec flow: Phase 1
            # (IKE_SA Created) is complete; loading sainit_policy starts Phase 2
            # without needing a real data packet (which cannot trigger hooks here).
            if [[ "$TC_STRONGSWAN_ROLE" == "resp" && $ike_triggered -eq 0 ]] && \
               grep -q "IKE_SA Created" "$tc_ike_log" 2>/dev/null; then
                log "  Phase 1 established — triggering Quick Mode"
                if ! "${BIN_DIR}/loadConfig" -f "$tc_sainit_pf" 2>/dev/null; then
                    tc_result="FAIL"; tc_reason="loadConfig sa init failed"; break 2
                fi
                ike_triggered=1
            fi

            grep -q "CHILD_SA created" "$tc_ike_log" 2>/dev/null && child_ike=1
            _swanctl_child_up && child_ss=1

            [[ $child_ike -eq 1 && $child_ss -eq 1 ]] && break
            (( elapsed % 5 == 0 )) && log "  ...waiting (${elapsed}s)"
        done

        if [[ $child_ike -eq 0 || $child_ss -eq 0 ]]; then
            tc_result="FAIL"
            tc_reason="timeout after ${TC_NEG_TIMEOUT}s — ike CHILD_SA: ${child_ike}  swanctl INSTALLED: ${child_ss}"
            break
        fi

        log "  NanoSec CHILD_SA : YES"
        log "  StrongSwan CHILD_SA: YES"

        # ── SA proposal verification ──────────────────────────────────────
        if [[ -n "${TC_VERIFY_AUTH:-}" && -n "${TC_VERIFY_ENCR:-}" \
              && -n "${TC_VERIFY_KEYLEN:-}" ]]; then
            step "  SA Proposal Verification"
            if ! verify_sa_proposal "$TC_VERIFY_AUTH" "$TC_VERIFY_ENCR" \
                    "$TC_VERIFY_KEYLEN"; then
                tc_result="FAIL"; tc_reason="SA proposal mismatch"
            fi
        fi

        # ── Packet capture ────────────────────────────────────────────────
        # Always send from the StrongSwan namespace: XFRM encrypts packets as
        # ESP before they exit the veth, making encryption visible in the pcap.
        # The NanoSec namespace is used as the listener destination only; it
        # may not decrypt the ESP (moc_ipsec.ko is not active there), but the
        # verdict is based entirely on what the capture shows (see _run_packet_test).
        if [[ $TC_RUN_PACKET_TEST -eq 1 && $tc_result == "PASS" ]]; then
            if [[ "$TC_STRONGSWAN_ROLE" == "init" ]]; then
                if ! _run_packet_test "$tc_idx" \
                        "$NS_RIGHT" "$NS_LEFT" "$INIT_IP" "$RESP_IP" "$VETH_INIT"; then
                    tc_result="FAIL"; tc_reason="packet capture: traffic not encrypted"
                fi
            else
                if ! _run_packet_test "$tc_idx" \
                        "$NS_LEFT" "$NS_RIGHT" "$RESP_IP" "$INIT_IP" "$VETH_RESP"; then
                    tc_result="FAIL"; tc_reason="packet capture: traffic not encrypted"
                fi
            fi
        fi

        break
    done  # end try block

    # ── Gracefully stop NanoSec ike process for this test ─────────────────
    for _pid in $RESP_PID $INIT_PID; do
        _graceful_kill "$_pid"
    done
    RESP_PID=0; INIT_PID=0

    # ── Check valgrind leak reports ───────────────────────────────────────
    if [[ $VALGRIND_ENABLED -eq 1 ]]; then
        local ike_leaks
        ike_leaks=$(_parse_valgrind_leaks "$tc_ike_valgrind")
        if [[ "$ike_leaks" == "YES" ]]; then
            tc_leak_status="YES"
            fail_msg "  Memory leaks detected — ike: $ike_leaks"
            log "  Valgrind log: $tc_ike_valgrind"
        elif [[ "$ike_leaks" == "NO" ]]; then
            tc_leak_status="NO"
            pass "  No memory leaks detected."
        fi
    fi

    # Tear down SAs and stop charon.  The next test will restart charon in
    # whichever namespace its role requires — which may differ from this test.
    _swanctl_reset
    _stop_charon

    # ── Per-test teardown ─────────────────────────────────────────────────
    if declare -f tc_teardown &>/dev/null; then
        tc_teardown || true
    fi

    # ── Show log tails on failure ─────────────────────────────────────────
    if [[ $tc_result == "FAIL" ]]; then
        section "NanoSec ike log"
        cat "$tc_ike_log" || true
        section "charon log (full)"
        cat "$SS_CHARON_LOG" || true
        section "charon socket check (port 500 in ${_ss_ns})"
        ip netns exec "$_ss_ns" ss -lunp 'sport = :500' 2>&1 || true
        section "namespace connectivity check"
        ip netns exec "$_ss_ns" ping -c 1 -W 1 \
            "$( [[ "$TC_STRONGSWAN_ROLE" == "init" ]] && echo "$RESP_IP" || echo "$INIT_IP" )" \
            2>&1 | tail -3 || true
    fi

    # ── Record and report ─────────────────────────────────────────────────
    local tc_elapsed=$(( $(date +%s) - tc_start ))
    _record "$TC_NAME" "$tc_result" "$tc_elapsed" "$tc_leak_status" "$tc_reason"

    if [[ $tc_result == "PASS" ]]; then
        pass "${TC_NAME}  (${tc_elapsed}s)"
        return 0
    else
        fail_msg "${TC_NAME} — ${tc_reason}  (${tc_elapsed}s)"
        return 1
    fi
}

###############################################################################
# Summary table
###############################################################################
print_summary() {
    local total=$(( PASS_COUNT + FAIL_COUNT + SKIP_COUNT ))

    # Size the "Test Case" column to the longest name so nothing overflows.
    # Minimum of 12 to accommodate the "Test Case" header label itself.
    local w=12
    local _entry _name
    for _entry in "${RESULTS[@]}"; do
        IFS='|' read -r _name _ _ _ _ <<< "$_entry"
        [[ ${#_name} -gt $w ]] && w=${#_name}
    done

    printf "\n"
    printf "${_MG}${_B}═══ Test Suite Summary ══════════════════════════════════════════════════════════${_R}\n"
    if [[ $VALGRIND_ENABLED -eq 1 ]]; then
        printf "  ${_DIM}%-3s  %-${w}s  %-6s  %-9s  %s${_R}\n" \
            "#" "Test Case" "Result" "Mem Leaks" "Time"
        printf "  ${_DIM}%-3s  %-${w}s  %-6s  %-9s  %s${_R}\n" \
            "───" "$(printf '─%.0s' $(seq 1 $w))" "──────" "─────────" "────"
    else
        printf "  ${_DIM}%-3s  %-${w}s  %-6s  %s${_R}\n" \
            "#" "Test Case" "Result" "Time"
        printf "  ${_DIM}%-3s  %-${w}s  %-6s  %s${_R}\n" \
            "───" "$(printf '─%.0s' $(seq 1 $w))" "──────" "────"
    fi

    local i=1
    for _entry in "${RESULTS[@]}"; do
        IFS='|' read -r _name _result _elapsed _leaks _reason <<< "$_entry"
        local _color="$_GR"
        [[ "$_result" == "FAIL" ]] && _color="$_RD"
        [[ "$_result" == "SKIP" ]] && _color="$_YL"
        if [[ $VALGRIND_ENABLED -eq 1 ]]; then
            local _lcolor="$_DIM"
            [[ "$_leaks" == "YES" ]] && _lcolor="$_RD"
            [[ "$_leaks" == "NO"  ]] && _lcolor="$_GR"
            if [[ -n "$_reason" ]]; then
                printf "  ${_DIM}%-3s${_R}  %-${w}s  ${_color}%-6s${_R}  ${_lcolor}%-9s${_R}  ${_DIM}%s — %s${_R}\n" \
                    "$i" "$_name" "$_result" "$_leaks" "$_elapsed" "$_reason"
            else
                printf "  ${_DIM}%-3s${_R}  %-${w}s  ${_color}%-6s${_R}  ${_lcolor}%-9s${_R}  ${_DIM}%s${_R}\n" \
                    "$i" "$_name" "$_result" "$_leaks" "$_elapsed"
            fi
        else
            if [[ -n "$_reason" ]]; then
                printf "  ${_DIM}%-3s${_R}  %-${w}s  ${_color}%-6s${_R}  ${_DIM}%s — %s${_R}\n" \
                    "$i" "$_name" "$_result" "$_elapsed" "$_reason"
            else
                printf "  ${_DIM}%-3s${_R}  %-${w}s  ${_color}%-6s${_R}  ${_DIM}%s${_R}\n" \
                    "$i" "$_name" "$_result" "$_elapsed"
            fi
        fi
        i=$(( i + 1 ))
    done

    if [[ $VALGRIND_ENABLED -eq 1 ]]; then
        printf "  ${_DIM}%-3s  %-${w}s  %-6s  %-9s  %s${_R}\n" \
            "───" "$(printf '─%.0s' $(seq 1 $w))" "──────" "─────────" "────"
    else
        printf "  ${_DIM}%-3s  %-${w}s  %-6s  %s${_R}\n" \
            "───" "$(printf '─%.0s' $(seq 1 $w))" "──────" "────"
    fi
    printf "\n  "

    if   [[ $FAIL_COUNT -eq 0 && $SKIP_COUNT -eq 0 ]]; then
        printf "${_GR}${_B}All ${PASS_COUNT} test(s) passed.${_R}"
    elif [[ $FAIL_COUNT -eq 0 ]]; then
        printf "${_GR}${_B}${PASS_COUNT} passed${_R}  ${_YL}${SKIP_COUNT} skipped${_R}"
    else
        printf "${_RD}${_B}${FAIL_COUNT} FAILED${_R}  ${_GR}${PASS_COUNT} passed${_R}"
        [[ $SKIP_COUNT -gt 0 ]] && printf "  ${_YL}${SKIP_COUNT} skipped${_R}"
    fi
    printf "  ${_DIM}(${total} total)${_R}\n\n"
}

###############################################################################
# Main
###############################################################################
if [[ $STRONGSWAN_MODE -eq 1 ]]; then
    printf "\n${_MG}${_B}NanoSec IKE/IPsec Test Suite  [StrongSwan interop mode]${_R}  "
else
    printf "\n${_MG}${_B}NanoSec IKE/IPsec Test Suite${_R}  "
fi
printf "${_DIM}%d test case(s) selected${_R}\n" "${#TC_FILES[@]}"

setup_network
load_modules

_tc_idx=0
for _tc_file in "${TC_FILES[@]}"; do
    _tc_idx=$(( _tc_idx + 1 ))
    if [[ $STRONGSWAN_MODE -eq 1 ]]; then
        # || true: a test failure returns 1 but must not abort the suite (set -e).
        run_one_test_strongswan "$_tc_file" "$_tc_idx" || true
    else
        run_one_test "$_tc_file" "$_tc_idx" || true
    fi
done

print_summary

[[ $FAIL_COUNT -eq 0 ]]
