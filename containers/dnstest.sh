#!/usr/bin/env bash
# Proves the DNS arrangement in both directions on a throwaway pair of networks.
#
#   ./dnstest.sh [1.0|1.5|2.0|3.0]     default 3.0
#
# The claim being tested is not "the resolver works". It is that the resolver is
# reachable *only* through the tunnel: the same query, to the same address, from
# a container that is not a tunnel client, must fail. A DNS setup that answers
# both ways is not leak-proof — it is just a resolver that happens to be nearby.
#
# Three vantage points, one query each:
#
#   1. tunnel client   -> 172.29.172.254   must ANSWER
#   2. bystander on the transport network (same bridge as the server, no tunnel)
#                      -> 172.29.172.254   must FAIL
#   3. bystander on the default docker bridge
#                      -> 172.29.172.254   must FAIL
set -uo pipefail

V=${1:-3.0}
PREFIX="${AWG_IMAGE_PREFIX:-vaiprog/}"
case "$V" in
    1.0) IMG=${PREFIX}amnezia-wg-1:latest  ;;
    1.5) IMG=${PREFIX}amnezia-wg-15:latest ;;
    2.0) IMG=${PREFIX}amnezia-wg-2:latest  ;;
    3.0) IMG=${PREFIX}amnezia-wg-3:latest  ;;
    3.1) IMG=${PREFIX}amnezia-wg-31:latest ;;
esac
DNSIMG=${PREFIX}amnezia-wg-dns:latest

NET=awgdnstest-transport
DNSNET=awgdnstest-resolver
SRV=awg-dnstest-server
CLI=awg-dnstest-client
DNS=awg-dnstest-dns
BY1=awg-dnstest-bystander-net
BY2=awg-dnstest-bystander-bridge
RESOLVER=172.29.172.254
QUERY=${AWG_DNS_QUERY:-example.com}
WORK=
AWG_TOOL=${AWG_TOOL:-$(dirname "$0")/../target/debug/awg-tool}
FAIL=0

hr()    { printf '\n===== %s =====\n' "$*"; }
check() { if [ "$1" = 0 ]; then echo "  PASS  $2"; else echo "  FAIL  $2"; FAIL=1; fi; }
cleanup() {
    docker rm -f "$SRV" "$CLI" "$DNS" "$BY1" "$BY2" >/dev/null 2>&1
    docker network rm "$NET" "$DNSNET" >/dev/null 2>&1
    if [ -n "$WORK" ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
cleanup
WORK=$(mktemp -d)

hr "setup — AWG $V tunnel + resolver at $RESOLVER"
"$AWG_TOOL" gen --version "$V" > "$WORK/params.conf" || exit 1

srv_priv=$(docker run --rm --entrypoint awg "$IMG" genkey)
srv_pub=$(printf '%s' "$srv_priv" | docker run --rm -i --entrypoint awg "$IMG" pubkey)
cli_priv=$(docker run --rm --entrypoint awg "$IMG" genkey)
cli_pub=$(printf '%s' "$cli_priv" | docker run --rm -i --entrypoint awg "$IMG" pubkey)
psk=$(docker run --rm --entrypoint awg "$IMG" genpsk)
params=$(cat "$WORK/params.conf")
srv_params=$params
if [ "$V" = 1.5 ]; then srv_params=$(grep -vE '^I[1-5] ' <<< "$params"); fi

cat > "$WORK/server.conf" <<EOF
[Interface]
PrivateKey = $srv_priv
Address = 10.98.0.1/24
ListenPort = 51820
MTU = 1280
$srv_params

[Peer]
PublicKey = $cli_pub
PresharedKey = $psk
AllowedIPs = 10.98.0.2/32
EOF

# The /32 for the resolver is what puts the query into the tunnel; without it
# the client would send it out of its own default route instead.
cat > "$WORK/client.conf" <<EOF
[Interface]
PrivateKey = $cli_priv
Address = 10.98.0.2/24
MTU = 1280
$params

[Peer]
PublicKey = $srv_pub
PresharedKey = $psk
AllowedIPs = 10.98.0.0/24, $RESOLVER/32
Endpoint = $SRV:51820
PersistentKeepalive = 15
EOF
chmod 644 "$WORK"/*.conf; chmod 755 "$WORK"

docker network create --subnet 172.31.98.0/24 "$NET"    >/dev/null || exit 1
docker network create --subnet 172.29.172.0/24 "$DNSNET" >/dev/null || exit 1

# The blacklist under test. example.net goes in as a bare domain, the second
# line in hosts-file style to prove that form is accepted too; example.com and
# example.org stay out of it, so the leak directions above keep their meaning.
cat > "$WORK/blocklist.txt" <<EOF
# dnstest blocklist — the resolver must sinkhole these
example.net
0.0.0.0 also-blocked.example
EOF

docker run -d --name "$DNS" --network "$DNSNET" --ip "$RESOLVER" \
    -v "$WORK/blocklist.txt:/etc/unbound/blacklist.d/test.txt:ro" "$DNSIMG" >/dev/null || exit 1
docker run -d --name "$SRV" --network "$NET" --ip 172.31.98.10 \
    --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 \
    -v "$WORK/server.conf:/etc/amnezia/awg/awg0.conf:ro" "$IMG" >/dev/null || exit 1
# The server is the only member of both networks — that is the whole mechanism.
docker network connect "$DNSNET" "$SRV" || exit 1
sleep 3
docker run -d --name "$CLI" --network "$NET" --ip 172.31.98.11 \
    --cap-add NET_ADMIN --device /dev/net/tun \
    -v "$WORK/client.conf:/etc/amnezia/awg/awg0.conf:ro" "$IMG" >/dev/null || exit 1

# Bystanders. Same host, same docker, same image — the only difference is that
# neither is a peer of the tunnel.
docker run -d --name "$BY1" --network "$NET"  --entrypoint sleep "$IMG" 600 >/dev/null || exit 1
docker run -d --name "$BY2" --network bridge  --entrypoint sleep "$IMG" 600 >/dev/null || exit 1
sleep 8

echo "resolver:   $(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$DNS")  on [$DNSNET]"
echo "server:     $(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$SRV")  on [$NET $DNSNET]"
echo "client:     $(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$CLI")  on [$NET] + tunnel"
echo "bystander1: $(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$BY1")  on [$NET], no tunnel"
echo "bystander2: $(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$BY2")  on [bridge], no tunnel"

hr "tunnel is up"
for _ in $(seq 1 15); do
    hs=$(docker exec "$SRV" awg-uapi get 2>/dev/null | grep -m1 '^last_handshake_time_sec=')
    [ -n "$hs" ] && [ "$hs" != "last_handshake_time_sec=0" ] && break
    sleep 2
done
echo "server: $hs"
[ -n "$hs" ] && [ "$hs" != "last_handshake_time_sec=0" ]; check $? "handshake completed"

# busybox nslookup, so no extra package is needed anywhere.
query() { docker exec "$1" timeout 8 nslookup "$QUERY" "$RESOLVER" 2>&1; }

hr "DIRECTION 1 — from inside the tunnel (must answer)"
out_in=$(query "$CLI"); rc_in=$?
echo "$out_in"
[ "$rc_in" = 0 ] && grep -qE '^(Address|Name):' <<< "$out_in"; check $? "tunnel client resolved $QUERY via $RESOLVER"

hr "DIRECTION 2 — same bridge as the server, no tunnel (must fail)"
out_by1=$(query "$BY1"); rc_by1=$?
echo "$out_by1"
echo "exit status: $rc_by1"
[ "$rc_by1" != 0 ]; check $? "bystander on $NET could NOT reach $RESOLVER"

hr "DIRECTION 3 — default docker bridge, no tunnel (must fail)"
out_by2=$(query "$BY2"); rc_by2=$?
echo "$out_by2"
echo "exit status: $rc_by2"
[ "$rc_by2" != 0 ]; check $? "bystander on the default bridge could NOT reach $RESOLVER"

hr "DIRECTION 2b — and it is not that the bystander has no network at all"
docker exec "$BY1" timeout 5 ping -c 2 172.31.98.10 2>&1 | tail -2
docker exec "$BY1" timeout 5 ping -c 2 172.31.98.10 >/dev/null 2>&1
check $? "the same bystander can still reach the server's transport address"

# The blacklist is answered by the resolver itself, so it is tested from the
# one vantage point that matters — the tunnel client. example.net is on the
# list, example.org deliberately is not: if both failed, the test would not
# know whether the blacklist ate the query or the resolver had died.
hr "DIRECTION 4 — the blacklist sinks its names, and only its names"
out_blk=$(docker exec "$CLI" timeout 8 nslookup example.net "$RESOLVER" 2>&1); rc_blk=$?
echo "$out_blk"
echo "exit status: $rc_blk"
[ "$rc_blk" != 0 ]; check $? "blacklisted example.net did not resolve"
out_sub=$(docker exec "$CLI" timeout 8 nslookup deep.sub.example.net "$RESOLVER" 2>&1); rc_sub=$?
[ "$rc_sub" != 0 ]; check $? "a name below a blacklisted zone did not resolve either"
out_ctl=$(docker exec "$CLI" timeout 8 nslookup example.org "$RESOLVER" 2>&1); rc_ctl=$?
echo "$out_ctl" | tail -3
[ "$rc_ctl" = 0 ]; check $? "non-blacklisted example.org still resolves"

hr "RESULT"
if [ "$FAIL" = 0 ]; then
    echo "AWG $V DNS: reachable through the tunnel, unreachable from outside it"
else
    echo "AWG $V DNS: FAILURES above"
fi
exit "$FAIL"
