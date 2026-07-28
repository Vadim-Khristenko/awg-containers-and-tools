#!/bin/bash
# Brings up an AmneziaWG interface — 1.0, 1.5, 2.0 or 3.0 — from a .conf file.
#
# Why not awg-quick: amneziawg-tools, on released tags *and* on master, parses
# only the AWG 2.0 keys. A config carrying HeaderProtectionKey,
# ContentPaddingAddition or the randomised timer ranges cannot be brought up
# with awg-quick at all — setconf never learns those words. amneziawg-go accepts
# every one of them on its UAPI socket, so this script translates the .conf into
# a UAPI `set=1` request and writes it to the socket itself.
#
# The same code path serves every protocol generation: only the keys actually
# present in the file are ever emitted, so a 1.0 config produces a 1.0 request.
#
# Along the way it writes an operational event log — starts, restarts, the
# interface coming up, peers installed — with no key material in it at all. See
# awg-log.sh for what is recorded and what is deliberately left out.
set -euo pipefail

IFACE="${AWG_IFACE:-awg0}"
export AWG_IFACE="$IFACE"
CONF="${AWG_CONF:-/etc/amnezia/awg/${IFACE}.conf}"
# amneziawg-go keeps its UAPI socket in /var/run/amneziawg, NOT the upstream
# wireguard-go /var/run/wireguard — see ipc/uapi_unix.go, same on every tag.
SOCKDIR="${AWG_SOCK_DIR:-/var/run/amneziawg}"
SOCK="${SOCKDIR}/${IFACE}.sock"
# auto: NAT when the config has a ListenPort (i.e. it is a server). on/off force.
NAT="${AWG_NAT:-auto}"
# Where the boot counter lives. Mount it to tell a restart from a first start;
# without a volume every container start looks like boot=1, which is true.
STATE_DIR="${AWG_STATE_DIR:-/var/lib/awg}"

# shellcheck source=awg-log.sh
. /usr/lib/awg/log.sh

log() { printf '>> %s\n' "$*" >&2; }
die() { printf '!! %s\n' "$*" >&2; exit 1; }

[ -r "$CONF" ] || die "no readable config at $CONF"

BOOT=1
if [ -r "$STATE_DIR/boots" ]; then
    BOOT=$(( $(cat "$STATE_DIR/boots" 2>/dev/null || echo 0) + 1 ))
fi
mkdir -p "$STATE_DIR" 2>/dev/null && printf '%s\n' "$BOOT" > "$STATE_DIR/boots" 2>/dev/null || true
awg_event start "boot=$BOOT" "daemon=$(amneziawg-go --version 2>/dev/null | awk 'NR==1{print $NF}')" \
    "protocol=${AWG_PROTOCOL:-unknown}"

trim() {
    local s=$1
    s=${s#"${s%%[![:space:]]*}"}
    s=${s%"${s##*[![:space:]]}"}
    printf '%s' "$s"
}

# base64 -> lowercase hex, which is what UAPI wants for every key.
#
# od(1) is POSIX and always present (busybox provides it); xxd is only there
# because Alpine happens to enable the applet, so it is not used. `-v` is not
# optional: without it od collapses repeated 16-byte runs to a bare "*", which
# silently truncates any key containing a repeated block — an all-zero preshared
# key being the obvious way to hit it.
b64hex() { printf '%s' "$1" | base64 -d | od -An -v -tx1 | tr -d ' \n'; }

# --- read the ini-ish config -------------------------------------------------
declare -A IF=()
declare -a PEERS=()
section=""
peer=""

flush_peer() {
    if [ -n "$peer" ]; then PEERS+=("$peer"); fi
    peer=""
}

while IFS= read -r line || [ -n "$line" ]; do
    line=${line%%#*}
    line=$(trim "$line")
    if [ -z "$line" ]; then continue; fi
    case "$line" in
        \[[Ii]nterface\]) flush_peer; section=if;    continue ;;
        \[[Pp]eer\])      flush_peer; section=peer;  continue ;;
        \[*\])            flush_peer; section=other; continue ;;
    esac
    # a line with no '=' is not a key/value pair
    if [ "$line" = "${line#*=}" ]; then continue; fi
    key=$(trim "${line%%=*}")
    val=$(trim "${line#*=}")
    case "$section" in
        if)   IF["$key"]=$val ;;
        peer) peer+="${key}=${val}"$'\n' ;;
    esac
done < "$CONF"
flush_peer

[ -n "${IF[PrivateKey]:-}" ] || die "config has no [Interface] PrivateKey"
[ -n "${IF[Address]:-}"    ] || die "config has no [Interface] Address"

# Default the mark and the routing table to the listen port rather than to a
# constant. In a container each instance has its own netns and a constant is
# harmless, but with `network_mode: host` several generations side by side would
# all write rules for table 51820 and quietly steal each other's default route.
# Deriving from the port makes the collision impossible for exactly the cases
# where it would have mattered.
FWMARK="${AWG_FWMARK:-${IF[ListenPort]:-51820}}"
RTABLE="${AWG_TABLE:-${IF[ListenPort]:-51820}}"

# --- start the daemon --------------------------------------------------------
mkdir -p "$SOCKDIR"
rm -f "$SOCK"
log "amneziawg-go $(amneziawg-go --version 2>/dev/null | head -1 || echo '(version unknown)')"
# -f keeps it in this process; without it the daemon re-execs itself detached
# and this script would either block forever or lose the child.
amneziawg-go -f "$IFACE" &
DAEMON=$!

for _ in $(seq 1 100); do
    if [ -S "$SOCK" ]; then break; fi
    if ! kill -0 "$DAEMON" 2>/dev/null; then die "amneziawg-go exited during startup"; fi
    sleep 0.1
done
[ -S "$SOCK" ] || die "UAPI socket $SOCK never appeared"

# busybox nc does not reliably do unix sockets, so socat is the transport.
uapi() { socat -t 15 - UNIX-CONNECT:"$SOCK"; }

# --- build the UAPI set request ---------------------------------------------
# Key names come from amneziawg-go device/uapi.go (identical across v0.2.x and
# v3.0.x for everything the older generations use).
declare -a REQ=("set=1")
addk() { if [ -n "${2:-}" ]; then REQ+=("$1=$2"); fi; }

addk private_key "$(b64hex "${IF[PrivateKey]}")"
addk listen_port "${IF[ListenPort]:-}"

for map in Jc:jc Jmin:jmin Jmax:jmax \
           S1:s1 S2:s2 S3:s3 S4:s4 \
           H1:h1 H2:h2 H3:h3 H4:h4 \
           I1:i1 I2:i2 I3:i3 I4:i4 I5:i5 Itime:itime \
           ContentPaddingAddition:content_padding_addition \
           RekeyAfterTime:rekey_after_time \
           RekeyTimeout:rekey_timeout \
           RejectAfterTime:reject_after_time \
           KeepaliveTimeout:keepalive_timeout \
           MaxHandshakeAttempts:max_handshake_attempts; do
    addk "${map#*:}" "${IF[${map%%:*}]:-}"
done

# 3.0 only, and base64 in the .conf but hex on the wire.
if [ -n "${IF[HeaderProtectionKey]:-}" ]; then
    addk header_protection_key "$(b64hex "${IF[HeaderProtectionKey]}")"
fi

# --- peers -------------------------------------------------------------------
# amneziawg-go's ParseEndpoint is netip.ParseAddrPort: an IP literal and a port,
# no resolver. Names have to be resolved here, the way `wg setconf` would.
resolve_endpoint() {
    local ep=$1 host port ip
    case "$ep" in
        \[*\]:*) host=${ep%]:*}; host=${host#[}; port=${ep##*:} ;;
        *:*)     host=${ep%:*};  port=${ep##*:} ;;
        *)       printf '%s' "$ep"; return 0 ;;
    esac
    ip=$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}') || true
    if [ -z "$ip" ]; then ip=$(getent hosts "$host" 2>/dev/null | awk 'NR==1{print $1}') || true; fi
    if [ -z "$ip" ]; then ip=$host; fi
    case "$ip" in
        *:*) printf '[%s]:%s' "$ip" "$port" ;;
        *)   printf '%s:%s'   "$ip" "$port" ;;
    esac
}

declare -a ALLOWED=()
# Public keys only, so the startup log can name the peers it installed without
# the peer loop ever holding a secret it might print.
declare -a PEER_PUBS=()
REQ+=("replace_peers=true")
for p in "${PEERS[@]}"; do
    declare -A P=()
    while IFS= read -r kv; do
        if [ -z "$kv" ]; then continue; fi
        P["${kv%%=*}"]=${kv#*=}
    done <<< "$p"

    # public_key opens a peer block in UAPI, so it must be emitted first.
    [ -n "${P[PublicKey]:-}" ] || die "peer without PublicKey in $CONF"
    REQ+=("public_key=$(b64hex "${P[PublicKey]}")")
    PEER_PUBS+=("${P[PublicKey]}")

    if [ -n "${P[PresharedKey]:-}" ]; then
        REQ+=("preshared_key=$(b64hex "${P[PresharedKey]}")")
    fi
    if [ -n "${P[Endpoint]:-}" ]; then
        REQ+=("endpoint=$(resolve_endpoint "${P[Endpoint]}")")
    fi
    if [ -n "${P[PersistentKeepalive]:-}" ]; then
        REQ+=("persistent_keepalive_interval=${P[PersistentKeepalive]}")
    fi
    if [ -n "${P[AllowedIPs]:-}" ]; then
        REQ+=("replace_allowed_ips=true")
        IFS=',' read -ra _ips <<< "${P[AllowedIPs]}"
        for cidr in "${_ips[@]}"; do
            cidr=$(trim "$cidr")
            if [ -z "$cidr" ]; then continue; fi
            REQ+=("allowed_ip=$cidr")
            ALLOWED+=("$cidr")
        done
    fi
    unset P
done

# A default route through the tunnel needs the fwmark trick, and the daemon has
# to know the mark before we install the rules.
FULL_TUNNEL=0
for cidr in ${ALLOWED[@]+"${ALLOWED[@]}"}; do
    case "$cidr" in 0.0.0.0/0|::/0) FULL_TUNNEL=1 ;; esac
done
if [ "$FULL_TUNNEL" = 1 ]; then REQ+=("fwmark=$FWMARK"); fi

# --- apply -------------------------------------------------------------------
if [ "${AWG_DUMP_REQUEST:-0}" = 1 ]; then
    # Contains the private key in clear, so it is opt-in and for debugging only.
    printf '%s\n' "${REQ[@]}" > /tmp/uapi-set.req
    log "wrote the outgoing request to /tmp/uapi-set.req (contains the private key)"
fi
if ! printf '%s\n' "${REQ[@]}" '' | uapi > /tmp/uapi-set.out 2>/tmp/uapi-set.err; then
    log "UAPI write failed"; cat /tmp/uapi-set.err >&2; exit 1
fi
if ! grep -q '^errno=0' /tmp/uapi-set.out; then
    log "daemon rejected the configuration:"
    cat /tmp/uapi-set.out >&2
    awg_event config-rejected "errno=$(sed -n 's/^errno=//p' /tmp/uapi-set.out | head -1)"
    exit 1
fi
log "configuration accepted by amneziawg-go (${#REQ[@]} UAPI lines, errno=0)"
# The line count, not the lines: the request carries the private key.
awg_event config-applied "errno=0" "uapi_lines=${#REQ[@]}" "peers=${#PEER_PUBS[@]}" \
    "port=${IF[ListenPort]:-none}"
for pub in ${PEER_PUBS[@]+"${PEER_PUBS[@]}"}; do
    awg_event peer-add "peer=$pub" "source=config"
done

# Peers created with `awg-peer add` live outside the mounted .conf, which is
# normally read-only. The request above carried replace_peers=true, so they have
# to be reinstalled here — otherwise every restart would silently revoke
# everyone the operator ever added, and the only sign of it would be clients
# that stop handshaking.
PEERS_DIR="${AWG_PEERS_DIR:-${STATE_DIR}/peers.d}"
for f in "$PEERS_DIR"/*.peer; do
    [ -e "$f" ] || continue
    p_pub=$(sed -n 's/^PublicKey=//p' "$f")
    p_psk=$(sed -n 's/^PresharedKey=//p' "$f")
    p_addr=$(sed -n 's/^Address=//p' "$f")
    p_label=$(sed -n 's/^Label=//p' "$f")
    if [ -z "$p_pub" ] || [ -z "$p_addr" ]; then
        log "skipping malformed peer record $f"
        continue
    fi
    declare -a PREQ=("set=1" "public_key=$(b64hex "$p_pub")")
    if [ -n "$p_psk" ]; then PREQ+=("preshared_key=$(b64hex "$p_psk")"); fi
    PREQ+=("replace_allowed_ips=true" "allowed_ip=$p_addr")
    if printf '%s\n' "${PREQ[@]}" '' | uapi | grep -q '^errno=0'; then
        awg_event peer-add "peer=$p_pub" "label=${p_label:-unlabelled}" "address=$p_addr" \
            "source=peers.d"
    else
        log "the daemon refused the stored peer ${p_label:-$p_pub}"
    fi
    unset PREQ
done

# --- network -----------------------------------------------------------------
ip link set mtu "${IF[MTU]:-1420}" dev "$IFACE"
IFS=',' read -ra _addrs <<< "${IF[Address]}"
for a in "${_addrs[@]}"; do
    a=$(trim "$a")
    if [ -n "$a" ]; then ip address add "$a" dev "$IFACE"; fi
done
ip link set up dev "$IFACE"

if [ "$FULL_TUNNEL" = 1 ]; then
    # awg-quick's routing, minus the parts that need the tools.
    ip route add default dev "$IFACE" table "$RTABLE"
    ip rule add not fwmark "$FWMARK" table "$RTABLE"
    ip rule add table main suppress_prefixlength 0
    sysctl -q -w net.ipv4.conf.all.src_valid_mark=1 2>/dev/null || true
else
    for cidr in ${ALLOWED[@]+"${ALLOWED[@]}"}; do
        ip route replace "$cidr" dev "$IFACE" 2>/dev/null || true
    done
fi

do_nat=0
case "$NAT" in
    on)   do_nat=1 ;;
    off)  do_nat=0 ;;
    auto) if [ -n "${IF[ListenPort]:-}" ]; then do_nat=1; fi ;;
esac
if [ "$do_nat" = 1 ]; then
    # /proc/sys is read-only in an unprivileged container, so the value has to be
    # handed in with `docker run --sysctl net.ipv4.ip_forward=1`. Only complain
    # if it is actually off.
    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != 1 ]; then
        sysctl -q -w net.ipv4.ip_forward=1 2>/dev/null \
            || log "ip_forward is off and cannot be set here — pass --sysctl net.ipv4.ip_forward=1"
    fi
    OUT_IF=$(ip route show default | awk 'NR==1{print $5}')
    iptables -A INPUT   -i "$IFACE" -j ACCEPT
    iptables -A FORWARD -i "$IFACE" -j ACCEPT
    iptables -A FORWARD -o "$IFACE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    for a in "${_addrs[@]}"; do
        a=$(trim "$a")
        case "$a" in
            *:*|"") continue ;;
        esac
        # `! -o $IFACE` rather than `-o $OUT_IF`: a node with a side network —
        # the DNS resolver's, say — has more than one way out, and pinning the
        # rule to the default route silently drops tunnel traffic aimed at any
        # of the others. The one thing that must not be masqueraded is traffic
        # going back into the tunnel.
        iptables -t nat -A POSTROUTING -s "$a" ! -o "$IFACE" -j MASQUERADE
    done
    log "NAT enabled, egress via ${OUT_IF:-?} (and any other non-tunnel link)"
fi

log "$IFACE is up"
awg_event iface-up "addr=${IF[Address]}" "mtu=${IF[MTU]:-1420}" "port=${IF[ListenPort]:-none}" \
    "nat=$do_nat" "full_tunnel=$FULL_TUNNEL"

shutdown() {
    trap - TERM INT EXIT
    awg_event stop
    if [ "$FULL_TUNNEL" = 1 ]; then
        ip rule del table main suppress_prefixlength 0 2>/dev/null || true
        ip rule del not fwmark "$FWMARK" table "$RTABLE" 2>/dev/null || true
    fi
    kill "$DAEMON" 2>/dev/null || true
    wait "$DAEMON" 2>/dev/null || true
    ip link del "$IFACE" 2>/dev/null || true
}
trap shutdown TERM INT EXIT

# Die with the daemon rather than lingering as a healthy-looking container.
wait "$DAEMON"
