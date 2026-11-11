#!/bin/bash
# Brings up an AmneziaWG interface — 1.0, 1.5, 2.0, 3.0 or 3.1 — from a .conf file.
#
# It translates the `.conf` into a UAPI `set=1` request and writes that to the
# daemon's socket rather than calling awg-quick: one code path serves every
# generation, and the keys reach the daemon whatever the tools in the image do
# or do not parse today. amneziawg-tools historically lagged behind 3.0 here,
# which is where this approach came from.
#
# Only the keys actually present in the file are ever emitted, so a 1.0 config
# produces a 1.0 request. Along the way it writes an operational event log —
# starts, restarts, the interface coming up, peers installed — with no key
# material in it at all.
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

# The 3.1 switches. Emitted only when the config carries them: a 3.0 device
# refuses both keys, and an off switch is not a parameter. The daemon parses
# them with boolf, so `1` is the value it wants — but `true`/`yes`/`on` are
# accepted here too, because people write them.
bool01() {
    case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes|on) printf '1' ;;
        *)             printf '0' ;;
    esac
}
for map in RandomTrailers:random_trailers DisableCookies:disable_cookies; do
    if [ -n "${IF[${map%%:*}]:-}" ]; then
        addk "${map#*:}" "$(bool01 "${IF[${map%%:*}]}")"
    fi
done

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
# Peer lines are collected apart from REQ: everything after the first
# public_key belongs to a peer, and the device keys that depend on the peers
# (fwmark) have to be written before it.
declare -a PREQ=()
for p in "${PEERS[@]}"; do
    declare -A P=()
    while IFS= read -r kv; do
        if [ -z "$kv" ]; then continue; fi
        P["${kv%%=*}"]=${kv#*=}
    done <<< "$p"

    # public_key opens a peer block in UAPI, so it must be emitted first.
    [ -n "${P[PublicKey]:-}" ] || die "peer without PublicKey in $CONF"
    PREQ+=("public_key=$(b64hex "${P[PublicKey]}")")
    PEER_PUBS+=("${P[PublicKey]}")

    if [ -n "${P[PresharedKey]:-}" ]; then
        PREQ+=("preshared_key=$(b64hex "${P[PresharedKey]}")")
    fi
    if [ -n "${P[Endpoint]:-}" ]; then
        PREQ+=("endpoint=$(resolve_endpoint "${P[Endpoint]}")")
    fi
    if [ -n "${P[PersistentKeepalive]:-}" ]; then
        PREQ+=("persistent_keepalive_interval=${P[PersistentKeepalive]}")
    fi
    if [ -n "${P[AllowedIPs]:-}" ]; then
        PREQ+=("replace_allowed_ips=true")
        IFS=',' read -ra _ips <<< "${P[AllowedIPs]}"
        for cidr in "${_ips[@]}"; do
            cidr=$(trim "$cidr")
            if [ -z "$cidr" ]; then continue; fi
            PREQ+=("allowed_ip=$cidr")
            ALLOWED+=("$cidr")
        done
    fi
    unset P
done

# A default route through the tunnel needs the fwmark trick, and the daemon has
# to know the mark before we install the rules. fwmark is a device key: after a
# peer's lines amneziawg-go reads it as a peer key and rejects the whole set
# with EINVAL, so it goes ahead of replace_peers.
FULL_TUNNEL=0
# The families with a default route, as `ip` flags: each needs its own table
# route and rules, or a ::/0 peer leaves IPv6 on eth0.
FULL_FAMILIES=()
for cidr in ${ALLOWED[@]+"${ALLOWED[@]}"}; do
    case "$cidr" in
        0.0.0.0/0) FULL_TUNNEL=1; FULL_FAMILIES+=(-4) ;;
        ::/0)      FULL_TUNNEL=1; FULL_FAMILIES+=(-6) ;;
    esac
done
if [ "$FULL_TUNNEL" = 1 ]; then REQ+=("fwmark=$FWMARK"); fi
REQ+=("replace_peers=true" ${PREQ[@]+"${PREQ[@]}"})

# AWG_EXCLUDE: CIDRs a full tunnel keeps off, checked before anything is
# applied, so a refusal leaves no peer behind. The tunnel's resolver must stay
# in the tunnel, or DNS leaves in the clear.
EXCLUDE=()
if [ -n "${AWG_EXCLUDE:-}" ]; then
    _without=$(awg-exclude "$AWG_EXCLUDE") || die "AWG_EXCLUDE: not a CIDR list"
    IFS=', ' read -ra EXCLUDE <<< "$AWG_EXCLUDE"
    IFS=', ' read -ra _dns <<< "${IF[DNS]:-}"
    for d in ${_dns[@]+"${_dns[@]}"}; do
        case "$d" in *[!0-9A-Fa-f.:]*|"") continue ;; esac
        if [ "$_without" = "$(awg-exclude "$AWG_EXCLUDE" "$d")" ]; then
            die "AWG_EXCLUDE covers the resolver $d: DNS would leave the tunnel"
        fi
    done
fi

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

# The resolver answers <label>.peer.vpn from a names file the node keeps on a
# volume of its own; rewrite it now, so peers issued before it existed have
# names too. Without that volume there is nothing to write.
AWG_PEERS_DIR="$PEERS_DIR" awg-peer names >/dev/null 2>&1 || true

# --- network -----------------------------------------------------------------
ip link set mtu "${IF[MTU]:-1420}" dev "$IFACE"
IFS=',' read -ra _addrs <<< "${IF[Address]}"
for a in "${_addrs[@]}"; do
    a=$(trim "$a")
    if [ -n "$a" ]; then ip address add "$a" dev "$IFACE"; fi
done
ip link set up dev "$IFACE"

RULED=() BYPASS=()
if [ "$FULL_TUNNEL" = 1 ]; then
    # awg-quick's routing, minus the parts that need the tools, per family.
    for fam in "${FULL_FAMILIES[@]}"; do
        # With IPv6 off in the container there is no IPv6 to leak, and no
        # route to add either.
        if [ "$fam" = -6 ] && [ "$(cat "/proc/sys/net/ipv6/conf/$IFACE/disable_ipv6" 2>/dev/null || echo 1)" != 0 ]; then
            log "::/0 in AllowedIPs, but IPv6 is off in this container: nothing to route"
            continue
        fi
        ip "$fam" route add default dev "$IFACE" table "$RTABLE"
        ip "$fam" rule add not fwmark "$FWMARK" table "$RTABLE"
        ip "$fam" rule add table main suppress_prefixlength 0
        RULED+=("$fam")
    done
    # A rule without a priority goes above the ones already there, so the
    # bypasses are read before the tunnel's own. A family without a tunnel
    # rule needs none.
    for cidr in ${EXCLUDE[@]+"${EXCLUDE[@]}"}; do
        fam=-4; case "$cidr" in *:*) fam=-6 ;; esac
        case " ${RULED[*]} " in *" $fam "*) : ;; *) continue ;; esac
        ip "$fam" rule add to "$cidr" table main || die "AWG_EXCLUDE: ip refused $cidr (host bits set?)"
        BYPASS+=("$fam" "$cidr")
    done
    if [ "${#EXCLUDE[@]}" -gt 0 ]; then log "kept off the tunnel: $AWG_EXCLUDE"; fi
    sysctl -q -w net.ipv4.conf.all.src_valid_mark=1 2>/dev/null || true
else
    for cidr in ${ALLOWED[@]+"${ALLOWED[@]}"}; do
        ip route replace "$cidr" dev "$IFACE" 2>/dev/null || true
    done
    if [ -n "${AWG_EXCLUDE:-}" ]; then
        log "AWG_EXCLUDE ignored: AllowedIPs has no default route to keep anything off"
    fi
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

    # TCP through the tunnel is held to segments that fit this side's MTU,
    # in both directions. A client that brings its interface up with an MTU of
    # its own instead of the config's (AmneziaVPN on Windows has used 1376 for
    # a 1280 config) otherwise gets connections that open and then stall on
    # the first large segment, TLS first among them. AWG_MSS=off leaves TCP
    # alone, a number sets the MSS outright.
    mtu=${IF[MTU]:-1420}
    case "${AWG_MSS:-auto}" in
        off)        mss= ;;
        auto|"")    mss=$((mtu - 40)) ;;
        *[!0-9]*)   log "AWG_MSS=$AWG_MSS is not off, auto or a number; using auto"; mss=$((mtu - 40)) ;;
        *)          mss=$AWG_MSS ;;
    esac
    if [ -n "$mss" ]; then
        clamped=1
        for dir in -i -o; do
            iptables -t mangle -A FORWARD "$dir" "$IFACE" -p tcp --tcp-flags SYN,RST SYN \
                -j TCPMSS --set-mss "$mss" 2>/dev/null || clamped=0
            # IPv6 headers are 20 bytes longer. No ip6tables, no IPv6 to clamp.
            ip6tables -t mangle -A FORWARD "$dir" "$IFACE" -p tcp --tcp-flags SYN,RST SYN \
                -j TCPMSS --set-mss "$((mss - 20))" 2>/dev/null || true
        done
        if [ "$clamped" = 1 ]; then
            log "TCP MSS through $IFACE held to $mss (AWG_MSS=off to leave it)"
        else
            log "could not clamp the TCP MSS (no TCPMSS target here?); large TCP segments rely on path MTU discovery"
        fi
    fi
fi

log "$IFACE is up"
# What node.vpn says about this node, next to the peer names: the protocol,
# the daemon, the MTU and when it came up. Nothing a client's own config
# does not already tell it.
NAMES_DIR=$(dirname "${AWG_NAMES_FILE:-/var/lib/awg-names/names.hosts}")
if [ -d "$NAMES_DIR" ] && [ -w "$NAMES_DIR" ]; then
    {
        echo "protocol=${AWG_PROTOCOL:-}"
        echo "daemon=$(amneziawg-go --version 2>/dev/null | awk 'NR==1{print $NF}')"
        echo "mtu=${IF[MTU]:-1420}"
        echo "started=$(date +%s)"
    } > "$NAMES_DIR/.node.txt.new" && chmod 644 "$NAMES_DIR/.node.txt.new" \
        && mv -f "$NAMES_DIR/.node.txt.new" "$NAMES_DIR/node.txt" || true
fi
awg_event iface-up "addr=${IF[Address]}" "mtu=${IF[MTU]:-1420}" "port=${IF[ListenPort]:-none}" \
    "nat=$do_nat" "full_tunnel=$FULL_TUNNEL"

# Peers that go quiet or come back, in the same log. AWG_WATCH=off leaves it
# out; it reads the UAPI socket once a minute and writes nothing else.
WATCH=
if [ "${AWG_WATCH:-on}" != off ]; then
    AWG_PEERS_DIR="$PEERS_DIR" awg-watch --loop &
    WATCH=$!
fi

shutdown() {
    trap - TERM INT EXIT
    awg_event stop
    if [ -n "$WATCH" ]; then kill "$WATCH" 2>/dev/null || true; fi
    set -- ${BYPASS[@]+"${BYPASS[@]}"}
    while [ "$#" -ge 2 ]; do
        ip "$1" rule del to "$2" table main 2>/dev/null || true
        shift 2
    done
    for fam in ${RULED[@]+"${RULED[@]}"}; do
        ip "$fam" rule del table main suppress_prefixlength 0 2>/dev/null || true
        ip "$fam" rule del not fwmark "$FWMARK" table "$RTABLE" 2>/dev/null || true
    done
    kill "$DAEMON" 2>/dev/null || true
    wait "$DAEMON" 2>/dev/null || true
    ip link del "$IFACE" 2>/dev/null || true
}
trap shutdown TERM INT EXIT

# Die with the daemon rather than lingering as a healthy-looking container.
wait "$DAEMON"
