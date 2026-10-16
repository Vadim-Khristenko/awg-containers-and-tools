#!/bin/sh
# The resolver container's entrypoint: build unbound's generated config out of
# whatever the operator mounted and set, start unbound, and keep it current
# without restarting it.
#
# Everything an operator changes lives in one directory, all of it optional:
#
#   /etc/awg-dns/blocklists.d/*.txt     names to block (plain, hosts-file or
#                                       adblock `||name^` lines)
#   /etc/awg-dns/blocklists.url         list URLs, one per line, refreshed
#   /etc/awg-dns/allowlist.d/*.txt      names never blocked, whatever a list says
#   /etc/awg-dns/records.d/*.records    your own records: `name TYPE value`
#   /etc/awg-dns/vpn.d/*.records        records in the tunnel's own .vpn zone
#   /etc/awg-dns/forward.d/*.conf       zones sent to resolvers you name:
#                                       `geek. 185.121.177.177 168.235.111.72`
#   /etc/awg-dns/chain.conf             resolvers asked in order, one per line,
#                                       `default` being this resolver's own
#                                       path; see "The chain" below
#
# and a few variables:
#
#   AWG_DNS_MODE        auto (default) | recursive | forward
#   AWG_DNS_FORWARD     DoT upstreams for forward mode, `ip@853#name` each
#   AWG_DNS_BLOCKLISTS  more list URLs, space separated
#   AWG_DNS_REFRESH     seconds between list refreshes (default 86400, 0 = once)
#   AWG_DNS_IPV6        1 to listen and resolve over IPv6 as well
#   AWG_DNS_NAMES       the node's names file, for <label>.peer.vpn
#   AWG_DNS_PUBLIC      where the counters dns.vpn shows are written
#                       (default /var/lib/awg-dns-public, skipped if absent)
#   AWG_DNS_CANARY      which encrypted-DNS bypasses to switch off: firefox
#                       (default), icloud, both space separated, or none
#   AWG_DNS_ZONES       more zones to forward: `geek=185.121.177.177,ip ...`
#   AWG_DNS_CHAIN       the chain when there is no chain.conf, space separated
#   AWG_DNS_CHAIN_SINKHOLES     more answers that mean "blocked" (ip or cidr)
#   AWG_DNS_CHAIN_KEEP          reasons to accept instead of moving on:
#                               nxdomain servfail refused sinkhole
#   AWG_DNS_CHAIN_TIMEOUT_MS    how long each resolver gets (default 1500)
#
# The chain. With one, unbound keeps the .vpn zone, the lists and the cache,
# and sends everything else to awg-dns-chain, which asks each resolver in turn
# and moves to the next one on no answer, SERVFAIL, REFUSED, NXDOMAIN or an
# answer that only points at 0.0.0.0, 127.0.0.0/8, :: or ::1. `default` in it
# is a second unbound inside this container doing what this one does without
# a chain (recursion or DoT, with DNSSEC), so
#
#   default
#   185.121.177.177
#
# resolves every name as before and asks OpenNIC only for what the real
# root says does not exist, such as .geek. Without a chain, or with `default`
# alone, nothing of this runs.
#
# The pre-0.5 blocklist directory, /etc/unbound/blacklist.d, is read too.
set -eu

CONF_DIR="${AWG_DNS_CONF_DIR:-/etc/awg-dns}"
LEGACY_BLOCK_DIR="${AWG_BLACKLIST_DIR:-/etc/unbound/blacklist.d}"
RUN="${AWG_DNS_RUN:-/run/awg-dns}"
OUT="$RUN/generated.conf"
MODE="${AWG_DNS_MODE:-auto}"
FORWARD="${AWG_DNS_FORWARD:-1.1.1.1@853#cloudflare-dns.com 9.9.9.9@853#dns.quad9.net}"
REFRESH="${AWG_DNS_REFRESH:-86400}"
IPV6="${AWG_DNS_IPV6:-0}"
CANARY="${AWG_DNS_CANARY:-firefox}"
NAMES="${AWG_DNS_NAMES:-/var/lib/awg-names/names.hosts}"
# Where `awg-tool dns block|allow` writes: a volume of its own, since the
# operator directory is usually mounted read-only.
MANAGED="${AWG_DNS_MANAGED:-/var/lib/awg-dns}"
# What the dns.vpn page may show: counts and counters, never a name anybody
# asked for or a name on a list.
PUBLIC="${AWG_DNS_PUBLIC:-/var/lib/awg-dns-public}"
CHAIN_PORT=5300
INNER_PORT=5301
CHAIN=
SELF="${AWG_DNS_ADDRESS:-172.29.172.254}"
STATUS="${AWG_DNS_STATUS_ADDRESS:-172.29.172.253}"
TTL=60
SAFE=0

mkdir -p "$RUN/lists"
say() { printf 'awg-dns: %s\n' "$*" >&2; }

# One name per line out of any of the list formats people publish: a bare
# name, `0.0.0.0 name` / `127.0.0.1 name`, or adblock's `||name^`. Comments,
# blanks and anything that is not a plausible name are dropped, lowercased,
# without a trailing dot. awk rather than a shell loop: lists run to hundreds
# of thousands of lines.
names_from() {
    only_files "$@" || return 0
    awk '
        { sub(/[#!].*/, ""); gsub(/\r/, "") }
        NF == 0 { next }
        $1 ~ /^\|\|/ { n = $1; sub(/^\|\|/, "", n); sub(/\^.*$/, "", n) }
        $1 !~ /^\|\|/ { n = (NF >= 2 && $1 ~ /^[0-9.:]+$/) ? $2 : $1 }
        { n = tolower(n); sub(/\.$/, "", n) }
        n ~ /^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/ && n != "localhost" { print n }
    ' $FILES
}

# Keep the arguments that are readable files, in $FILES. A glob that matched
# nothing arrives as its own pattern, and awk would stop on it. Returns
# non-zero when nothing is left. Names with spaces are not supported.
only_files() {
    FILES=
    for f in "$@"; do
        if [ -f "$f" ] && [ -r "$f" ]; then FILES="$FILES $f"; fi
    done
    [ -n "$FILES" ]
}

# Fetch every list URL into the cache. A list that fails to download keeps
# its last good copy: a flaky mirror must not unblock everything it listed.
fetch_lists() {
    urls=$( { [ -r "$CONF_DIR/blocklists.url" ] && cat "$CONF_DIR/blocklists.url"; \
              printf '%s\n' ${AWG_DNS_BLOCKLISTS:-}; } | sed 's/#.*//' | tr -s ' \t' '\n' | grep -E '^https?://' || true)
    [ -n "$urls" ] || return 0
    printf '%s\n' "$urls" | while IFS= read -r url; do
        key=$(printf '%s' "$url" | md5sum | cut -c1-16)
        if wget -q -T 30 -O "$RUN/lists/$key.tmp" "$url"; then
            mv -f "$RUN/lists/$key.tmp" "$RUN/lists/$key.txt"
            say "list $url: $(names_from "$RUN/lists/$key.txt" | wc -l) name(s)"
        else
            rm -f "$RUN/lists/$key.tmp"
            say "list $url: download failed, keeping the last copy if there is one"
        fi
    done
}

# `name TYPE value...` to unbound local-data. Only the record types a
# resolver for tunnel clients has a use for; anything else is reported.
records_from() {
    only_files "$@" || return 0
    awk -v ttl="$TTL" -v q="'" '
        { sub(/#.*/, "") }
        NF < 3 { next }
        {
            name = tolower($1); sub(/\.$/, "", name); type = toupper($2)
            if (name !~ /^[a-z0-9_*-]+(\.[a-z0-9_-]+)*$/ || type !~ /^(A|AAAA|CNAME|TXT|MX|SRV|PTR)$/) {
                printf "awg-dns: skipping record %s\n", $0 > "/dev/stderr"; next
            }
            value = $3; for (i = 4; i <= NF; i++) value = value " " $i
            # Single quotes around the whole record, so a TXT value can carry
            # its own double quotes; a value with a single quote cannot be
            # written safely and is skipped.
            if (index(value, q) > 0) { printf "awg-dns: skipping record %s\n", $0 > "/dev/stderr"; next }
            if (type == "TXT" && value !~ /^"/) value = "\"" value "\""
            printf "    local-data: %s%s. %d IN %s %s%s\n", q, name, ttl, type, value, q
        }
    ' $FILES
}

# An upstream as unbound and the chain both read it: an address, then
# optionally @port, then optionally #name for DoT. Nothing else gets through.
is_upstream() {
    printf '%s' "$1" | grep -Eq '^[0-9A-Fa-f:.]+(@[0-9]{1,5})?(#[A-Za-z0-9.-]+)?$'
}

# The chain as configured, `default` included, or nothing when it would only
# be `default`.
chain_list() {
    if [ -r "$CONF_DIR/chain.conf" ]; then
        sed 's/#.*//' "$CONF_DIR/chain.conf"
    else
        printf '%s\n' ${AWG_DNS_CHAIN:-}
    fi | awk 'NF { print $1 }' | while read -r u; do
        if [ "$u" = default ]; then echo default
        elif is_upstream "$u" && ! printf '%s' "$u" | grep -q '#'; then echo "$u"
        else say "chain: skipping $u (an address, @port optional; DoT goes in AWG_DNS_FORWARD)"
        fi
    done | awk '!seen[$0]++' | tr '\n' ' ' | awk '{ for (i = 1; i <= NF; i++) if ($i != "default") { print; exit } }'
}

# `zone server...`, one zone per line, from forward.d and AWG_DNS_ZONES.
zone_list() {
    {
        only_files "$CONF_DIR"/forward.d/*.conf && sed 's/#.*//' $FILES
        printf '%s\n' ${AWG_DNS_ZONES:-} | awk -F'=' 'NF == 2 { gsub(",", " ", $2); print $1, $2 }'
    } | awk 'NF >= 2' | while read -r zone servers; do
        zone=$(printf '%s' "$zone" | tr 'A-Z' 'a-z'); zone="${zone%.}."
        if ! printf '%s' "$zone" | grep -Eq '^([a-z0-9_-]+\.)+$'; then
            say "zones: skipping $zone (not a zone name)"; continue
        fi
        case "$zone" in
            vpn.|*.vpn.) say "zones: skipping $zone (.vpn is the tunnel's own)"; continue ;;
        esac
        good=
        for s in $servers; do
            if is_upstream "$s"; then good="$good $s"; else say "zones: skipping $s for $zone"; fi
        done
        [ -n "$good" ] && echo "$zone$good"
    done | awk '!seen[$1]++'
}

# The inner resolver the chain calls `default`: this container's own way of
# resolving (recursion or DoT, DNSSEC on), on loopback, with nothing local.
write_inner() {
    {
        echo "server:"
        echo "    interface: 127.0.0.1"
        echo "    port: $INNER_PORT"
        echo "    do-ip4: yes"
        echo "    do-ip6: $([ "$IPV6" = 1 ] && echo yes || echo no)"
        echo "    access-control: 127.0.0.0/8 allow"
        echo "    hide-identity: yes"
        echo "    hide-version: yes"
        echo "    use-syslog: no"
        echo "    qname-minimisation: yes"
        echo "    harden-glue: yes"
        echo "    harden-dnssec-stripped: yes"
        echo "    harden-below-nxdomain: yes"
        echo "    aggressive-nsec: yes"
        echo "    num-threads: 1"
        echo "    msg-cache-size: 4m"
        echo "    rrset-cache-size: 8m"
        echo "    prefetch: yes"
        echo "    serve-expired: yes"
        echo "    serve-expired-ttl: 3600"
        echo "    chroot: \"\""
        echo "    directory: \"/etc/unbound\""
        echo "    username: \"\""
        echo "    pidfile: \"\""
        echo "    trust-anchor-file: \"/usr/share/dnssec-root/trusted-key.key\""
        echo "    tls-cert-bundle: \"/etc/ssl/certs/ca-certificates.crt\""
        if [ "$MODE" = forward ]; then
            echo "forward-zone:"
            echo "    name: \".\""
            echo "    forward-tls-upstream: yes"
            for up in $FORWARD; do echo "    forward-addr: $up"; done
        fi
        echo "remote-control:"
        echo "    control-enable: no"
    } > "$RUN/inner.conf"
}

INNER_PID= CHAIN_PID= RUNNING_CHAIN=

start_inner() {
    /usr/sbin/unbound -d -p -c "$RUN/inner.conf" &
    INNER_PID=$!
}

start_chain() {
    set --
    for u in $CHAIN; do
        [ "$u" = default ] && u="127.0.0.1@$INNER_PORT"
        set -- "$@" --upstream "$u"
    done
    for s in ${AWG_DNS_CHAIN_SINKHOLES:-}; do set -- "$@" --sinkhole "$s"; done
    for k in ${AWG_DNS_CHAIN_KEEP:-}; do set -- "$@" --keep "$k"; done
    /usr/local/bin/awg-dns-chain --listen "127.0.0.1:$CHAIN_PORT" --stats "$RUN/chain.stats" \
        --timeout-ms "${AWG_DNS_CHAIN_TIMEOUT_MS:-1500}" "$@" &
    CHAIN_PID=$!
}

stop_chain() {
    for p in $CHAIN_PID $INNER_PID; do kill "$p" 2>/dev/null || true; done
    for p in $CHAIN_PID $INNER_PID; do wait "$p" 2>/dev/null || true; done
    INNER_PID= CHAIN_PID=
    rm -f "$RUN/chain.stats"
}

# Bring the running chain in line with the configured one, and start again
# whatever of it stopped.
sync_chain() {
    if [ "$CHAIN" != "$RUNNING_CHAIN" ]; then
        stop_chain
        RUNNING_CHAIN=$CHAIN
        if [ -n "$CHAIN" ]; then
            case " $CHAIN " in *" default "*)
                write_inner
                if ! problems=$(unbound-checkconf "$RUN/inner.conf" 2>&1); then
                    say "the inner resolver's config does not load: $problems"
                fi
                start_inner ;;
            esac
            start_chain
            say "chain: $CHAIN"
        fi
        return 0
    fi
    [ -n "$CHAIN" ] || return 0
    if [ -n "$INNER_PID" ] && ! kill -0 "$INNER_PID" 2>/dev/null; then
        say "the inner resolver stopped, starting it again"
        start_inner
    fi
    if [ -n "$CHAIN_PID" ] && ! kill -0 "$CHAIN_PID" 2>/dev/null; then
        say "the chain stopped, starting it again"
        start_chain
    fi
}

# The page's view of the resolver, in key=value lines.
#
# In a subshell, and never fatal: on a read-only container without the public
# volume the directory is there and looks writable, and a failed redirect
# under `set -e` would take the whole resolver down with it.
publish() {
    [ -d "$PUBLIC" ] || return 0
    ( publish_to "$PUBLIC/.dns.txt.new" && mv -f "$PUBLIC/.dns.txt.new" "$PUBLIC/dns.txt" ) 2>/dev/null || true
}

publish_to() {
    {
        echo "mode=$MODE"
        echo "blocked=$(grep -c 'always_nxdomain' "$OUT" 2>/dev/null || echo 0)"
        echo "allowed=$(wc -l < "$RUN/allowed.txt" 2>/dev/null | tr -d ' ' || echo 0)"
        echo "canary=$CANARY"
        echo "safe=$SAFE"
        echo "updated=$(date +%s)"
        if [ -r "$RUN/stats" ]; then
            grep -E '^(total\.num\.(queries|cachehits|cachemiss|expired)|num\.answer\.rcode\.(NOERROR|NXDOMAIN|SERVFAIL)|time\.up|total\.recursion\.time\.(avg|median))=' "$RUN/stats"
        fi
        echo "zones=$(wc -l < "$RUN/zones.txt" 2>/dev/null | tr -d ' ' || echo 0)"
        # The chain's counts; never its addresses, which are the operator's
        # business rather than every peer's.
        if [ -r "$RUN/chain.stats" ]; then
            grep -E '^chain\.(upstreams|queries|exhausted|[0-9]+\.(answered|timeout|servfail|refused|nxdomain|sinkhole))=' "$RUN/chain.stats"
        fi
    } > "$1"
}

generate() {
    tmp="$OUT.new"
    blocked="$RUN/blocked.txt"
    allowed="$RUN/allowed.txt"

    # Safe mode is the built-in zone and the mode alone: what the resolver
    # falls back to when the operator content would not load.
    if [ "$SAFE" = 1 ]; then
        : > "$blocked"
        : > "$allowed"
    else
        names_from "$CONF_DIR"/blocklists.d/* "$LEGACY_BLOCK_DIR"/* "$RUN"/lists/*.txt "$MANAGED"/block.txt | sort -u > "$blocked"
        names_from "$CONF_DIR"/allowlist.d/* "$MANAGED"/allow.txt | sort -u > "$allowed"
    fi
    # The names a network answers NXDOMAIN to tell software to keep to its
    # resolver: Firefox then does not switch to its own DoH provider, and iCloud
    # Private Relay stays off. Either would skip this resolver and its lists.
    # They join the blocklist, so the allowlist still overrides them.
    canaries=
    for c in $CANARY; do
        case "$c" in
            firefox) canaries="$canaries use-application-dns.net" ;;
            icloud)  canaries="$canaries mask.icloud.com mask-h2.icloud.com" ;;
            none)    ;;
            *)       say "AWG_DNS_CANARY: $c is not firefox, icloud or none, ignored" ;;
        esac
    done
    if [ -n "$canaries" ]; then
        printf '%s\n' $canaries | sort -u - "$blocked" > "$blocked.new"
        mv -f "$blocked.new" "$blocked"
    fi

    {
        echo "# generated by entrypoint-dns.sh at start and on every change; do not edit"
        echo "server:"

        if [ "$IPV6" = 1 ]; then
            echo "    interface: ::0"
            echo "    do-ip6: yes"
            echo "    access-control: fc00::/7 allow"
        fi

        # Blocking: every listed name and everything beneath it answers
        # NXDOMAIN from here, except what the allowlist names. An exact match
        # is simply dropped; a name under a blocked parent gets a zone of its
        # own, and the most specific zone wins in unbound.
        # The allowlist is read with getline, not as the first file: with an
        # empty allowlist `NR == FNR` would hold for the blocklist instead and
        # read every blocked name as allowed.
        awk -v allowfile="$allowed" '
            BEGIN { while ((getline a < allowfile) > 0) allow[a] = 1 }
            !($0 in allow) { printf "    local-zone: \"%s.\" always_nxdomain\n", $0 }
        ' "$blocked"
        awk -v blockfile="$blocked" '
            BEGIN { while ((getline b < blockfile) > 0) blk[b] = 1 }
            {
                n = $0
                while ((i = index(n, ".")) > 0) {
                    n = substr(n, i + 1)
                    if (n in blk) { printf "    local-zone: \"%s.\" transparent\n", $0; break }
                }
            }
        ' "$allowed"

        # The tunnel's own zone. Nothing outside the tunnel answers .vpn, so a
        # name here resolving at all says the query went through the tunnel.
        echo "    local-zone: \"vpn.\" static"
        echo "    local-data: \"vpn. 3600 IN SOA resolver.vpn. hostmaster.vpn. 1 3600 600 86400 60\""
        echo "    local-data: \"resolver.vpn. $TTL IN A $SELF\""
        for page in amiunder dns speed mtu node; do
            echo "    local-data: \"$page.vpn. $TTL IN A $STATUS\""
        done
        # Any <nonce>.leak.vpn answers too: the leak page asks for a fresh name
        # each time, so a cached answer from anywhere else cannot fake one.
        echo "    local-zone: \"leak.vpn.\" redirect"
        echo "    local-data: \"leak.vpn. $TTL IN A $STATUS\""
        [ "$SAFE" = 1 ] || records_from "$CONF_DIR"/vpn.d/*.records

        # The node's peers by name, with reverse records so a tunnel address
        # in a log reads as who it is.
        if [ "$SAFE" != 1 ] && [ -r "$NAMES" ]; then
            awk -v ttl="$TTL" '
                NF >= 2 && $2 ~ /^[A-Za-z0-9._-]+$/ && $1 ~ /^[0-9.]+$|:/ {
                    l = tolower($2)
                    printf "    local-data: \"%s.peer.vpn. %d IN %s %s\"\n", l, ttl, ($1 ~ /:/ ? "AAAA" : "A"), $1
                    printf "    local-data-ptr: \"%s %s.peer.vpn\"\n", $1, l
                }
            ' "$NAMES"
        fi

        [ "$SAFE" = 1 ] || records_from "$CONF_DIR"/records.d/*.records

        # Zones sent to resolvers the operator named, such as an alternative
        # root's TLDs. Nothing signs them under the ICANN root, so validation
        # stands aside for them alone.
        if [ "$SAFE" = 1 ]; then : > "$RUN/zones.txt"; else zone_list > "$RUN/zones.txt"; fi
        awk '{ printf "    domain-insecure: \"%s\"\n", $1 }' "$RUN/zones.txt"
        # unbound answers some zones itself (test., home.arpa., the private
        # reverse zones, RFC 6761 and 6303) before any forwarding happens; a
        # transparent zone of the same name lets a forwarded one through. A
        # zone the blocklist blocks stays blocked.
        awk -v blockfile="$blocked" '
            BEGIN { while ((getline b < blockfile) > 0) blk[b "."] = 1 }
            !($1 in blk) { printf "    local-zone: \"%s\" transparent\n", $1 }
        ' "$RUN/zones.txt"
        # With a chain the inner resolver validates the default path, and the
        # answers from the others could not pass a validator that trusts only
        # the ICANN root: this one only iterates.
        if [ -n "$CHAIN" ]; then
            echo "    module-config: \"iterator\""
            echo "    do-not-query-localhost: no"
        fi

        # Clauses last: every line after one belongs to it.
        awk '{
            printf "forward-zone:\n    name: \"%s\"\n", $1
            for (i = 2; i <= NF; i++) if (index($i, "#")) { print "    forward-tls-upstream: yes"; break }
            for (i = 2; i <= NF; i++) printf "    forward-addr: %s\n", $i
        }' "$RUN/zones.txt"
        if [ -n "$CHAIN" ]; then
            echo "forward-zone:"
            echo "    name: \".\""
            echo "    forward-addr: 127.0.0.1@$CHAIN_PORT"
        elif [ "$MODE" = forward ]; then
            echo "forward-zone:"
            echo "    name: \".\""
            echo "    forward-tls-upstream: yes"
            for up in $FORWARD; do echo "    forward-addr: $up"; done
        fi
    } > "$tmp"

    n_blocked=$(grep -c 'always_nxdomain' "$tmp" || true)
    if [ -f "$OUT" ] && cmp -s "$tmp" "$OUT"; then
        rm -f "$tmp"
        return 1
    fi
    # One bad line in a mounted file must not take the resolver down: the new
    # file is checked with the whole config before it is kept, and refused
    # back to the last good one, or at first start to the safe set.
    if [ -f "$OUT" ]; then cp -f "$OUT" "$OUT.prev"; fi
    mv -f "$tmp" "$OUT"
    if ! problems=$(unbound-checkconf /etc/unbound/unbound.conf 2>&1); then
        say "the generated config does not load, so it is not used:"
        printf '%s\n' "$problems" | sed 's/^/awg-dns:   /' >&2
        if [ -f "$OUT.prev" ]; then
            mv -f "$OUT.prev" "$OUT"
            say "kept the previous config"
        elif [ "$SAFE" != 1 ]; then
            SAFE=1
            generate || true
            SAFE=0
            say "running on the built-in .vpn zone alone until the files are fixed"
        fi
        return 1
    fi
    rm -f "$OUT.prev"
    say "mode $MODE, $n_blocked name(s) blocked, $(wc -l < "$allowed" | tr -d ' ') allowed"
    return 0
}

case "$MODE" in
    recursive|forward) ;;
    # Recursion keeps the query stream off any one provider, so it is the
    # first choice. Some networks drop plain DNS to the root on the way out;
    # there recursion would only time out, and DoT to the forwarders is the
    # resolver that still works. Asked once, at start.
    auto)
        if timeout 6 nslookup -type=NS . 198.41.0.4 >/dev/null 2>&1 \
            || timeout 6 nslookup -type=NS . 199.9.14.201 >/dev/null 2>&1; then
            MODE=recursive
            say "auto: the root servers answer, resolving recursively"
        else
            MODE=forward
            say "auto: the root servers do not answer from here, forwarding over DoT instead"
        fi ;;
    *) say "AWG_DNS_MODE=$MODE is not recursive, forward or auto"; exit 1 ;;
esac
echo "$MODE" > "$RUN/mode"

fetch_lists
CHAIN=$(chain_list)
generate || true
# The chain before the resolver in front of it, so the first query that is
# forwarded finds it listening.
sync_chain
publish

/usr/sbin/unbound -d -p -c /etc/unbound/unbound.conf &
pid=$!
trap 'stop_chain; kill -TERM "$pid" 2>/dev/null; wait "$pid"; exit 0' TERM INT

# Reload without a restart when something changed: the names file on every
# tick (a peer was just added), the lists on the refresh period.
#
# The cache is kept unless where names are sent changed: the chain or the
# forwarded zones. Then it goes, since it holds what the old path said, and an
# NXDOMAIN cached from the real root for a .geek name would outlive the chain
# that can answer it.
LAST_SHAPE=
shape() { printf '%s|%s' "$CHAIN" "$(cat "$RUN/zones.txt" 2>/dev/null)"; }
reload() {
    now=$(shape)
    if [ "$now" != "$LAST_SHAPE" ]; then
        LAST_SHAPE=$now
        unbound-control reload >/dev/null 2>&1 || true
        return
    fi
    unbound-control reload_keep_cache >/dev/null 2>&1 || unbound-control reload >/dev/null 2>&1 || true
}
# What the loop watches between refreshes: the peer names, the lists the
# tool manages, and the operator directory itself.
stamp() {
    find "$NAMES" "$MANAGED" "$CONF_DIR" -type f 2>/dev/null | sort | xargs -r stat -c '%n %Y %s' 2>/dev/null | md5sum
}
last_names=$(stamp)
LAST_SHAPE=$(shape)
since_fetch=0
# The first counters a few seconds in rather than a minute in.
since_stats=50
while kill -0 "$pid" 2>/dev/null; do
    sleep 5 &
    wait $! || true
    since_fetch=$((since_fetch + 5))
    since_stats=$((since_stats + 5))
    now_names=$(stamp)
    refetch=0
    if [ "$REFRESH" -gt 0 ] && [ "$since_fetch" -ge "$REFRESH" ]; then
        fetch_lists
        since_fetch=0
        refetch=1
    fi
    if [ "$now_names" != "$last_names" ] || [ "$refetch" = 1 ]; then
        last_names=$now_names
        CHAIN=$(chain_list)
        sync_chain
        if generate; then reload; fi
        publish
    else
        sync_chain
    fi
    if [ "$since_stats" -ge 60 ]; then
        unbound-control stats_noreset > "$RUN/stats.tmp" 2>/dev/null && mv -f "$RUN/stats.tmp" "$RUN/stats"
        publish
        since_stats=0
    fi
done
wait "$pid"
