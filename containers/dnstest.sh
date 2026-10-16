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
STATUSIMG=${PREFIX}amnezia-wg-status:latest

NET=awgdnstest-transport
DNSNET=awgdnstest-resolver
SRV=awg-dnstest-server
CLI=awg-dnstest-client
DNS=awg-dnstest-dns
STATUS=awg-dnstest-status
# The node writes peer names here and the resolver reads them.
NAMESVOL=awgdnstest-names
BY1=awg-dnstest-bystander-net
BY2=awg-dnstest-bystander-bridge
RESOLVER=172.29.172.254
# The slot unbound.conf answers amiunder.vpn with.
STATUS_IP=172.29.172.253
QUERY=${AWG_DNS_QUERY:-example.com}
WORK=
AWG_TOOL=${AWG_TOOL:-$(dirname "$0")/../target/debug/awg-tool}
FAIL=0

hr()    { printf '\n===== %s =====\n' "$*"; }
check() { if [ "$1" = 0 ]; then echo "  PASS  $2"; else echo "  FAIL  $2"; FAIL=1; fi; }
cleanup() {
    docker rm -f "$SRV" "$CLI" "$DNS" "$STATUS" "$BY1" "$BY2" >/dev/null 2>&1
    docker network rm "$NET" "$DNSNET" >/dev/null 2>&1
    docker volume rm "$NAMESVOL" >/dev/null 2>&1
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
AllowedIPs = 10.98.0.0/24, $RESOLVER/32, $STATUS_IP/32
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

# The operator surface: an allowlist punching a hole in a blocked zone, a
# record of their own, a name in the .vpn zone.
mkdir -p "$WORK/dns/allowlist.d" "$WORK/dns/records.d" "$WORK/dns/vpn.d"
printf 'www.example.net\n' > "$WORK/dns/allowlist.d/test.txt"
printf 'nas.home A 192.168.7.7\n' > "$WORK/dns/records.d/test.records"
printf 'files.vpn A 172.29.172.250\n' > "$WORK/dns/vpn.d/test.records"
chmod -R a+rX "$WORK/dns"
docker volume create "$NAMESVOL" >/dev/null || exit 1

# Run the way docker-compose.yml runs it: read-only, with its two tmpfs. A
# resolver that only works writable is one the compose file cannot start.
docker run -d --name "$DNS" --network "$DNSNET" --ip "$RESOLVER" \
    --read-only --tmpfs /var/log/unbound --tmpfs /run/awg-dns:uid=100,gid=101 \
    -v "$WORK/blocklist.txt:/etc/unbound/blacklist.d/test.txt:ro" \
    -v "$WORK/dns:/etc/awg-dns:ro" \
    -v "$NAMESVOL:/var/lib/awg-names:ro" "$DNSIMG" >/dev/null || exit 1
# The status page, at the slot unbound.conf answers amiunder.vpn with, so the
# name, the resolver and the page are tested together rather than one at a time.
docker run -d --name "$STATUS" --network "$DNSNET" --ip "$STATUS_IP" "$STATUSIMG" >/dev/null || exit 1
docker run -d --name "$SRV" --network "$NET" --ip 172.31.98.10 \
    --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 \
    -v "$WORK/server.conf:/etc/amnezia/awg/awg0.conf:ro" \
    -v "$NAMESVOL:/var/lib/awg-names" "$IMG" >/dev/null || exit 1
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

# DIRECTION 5 — the page. amiunder.vpn is answered by the tunnel resolver and
# lives on the resolver network, so the name answering, the page loading and
# `awg-under` are three ways of proving the same thing from both sides.
hr "DIRECTION 5 — amiunder.vpn answers through the tunnel, and nothing else"
out_name=$(docker exec "$CLI" timeout 8 nslookup amiunder.vpn "$RESOLVER" 2>&1)
echo "$out_name" | tail -3
grep -q "$STATUS_IP" <<< "$out_name"; check $? "the tunnel resolver answers amiunder.vpn with $STATUS_IP"
out_tld=$(docker exec "$BY1" timeout 8 nslookup amiunder.vpn 2>&1); rc_tld=$?
[ "$rc_tld" != 0 ]; check $? "a bystander cannot resolve amiunder.vpn — .vpn is not a real TLD"
out_page=$(docker exec "$CLI" timeout 8 curl -fsS "http://$STATUS_IP/" 2>&1 | head -1)
echo "client page: $out_page"
grep -qi 'doctype html' <<< "$out_page"; check $? "the client fetched the page through the tunnel"
docker exec "$BY1" timeout 5 curl -fsS "http://$STATUS_IP/" >/dev/null 2>&1; rc_by_page=$?
[ "$rc_by_page" != 0 ]; check $? "the same page is unreachable from a container outside the tunnel"

# DIRECTION 6 — the utilities that ship in every node image, run where they are
# meant to run: inside the client.
hr "DIRECTION 6 — awg-under and awg-leak, inside the client"
out_under=$(docker exec "$CLI" awg-under "$STATUS_IP" 2>&1); rc_under=$?
echo "$out_under"
[ "$rc_under" = 0 ]; check $? "awg-under says the client is under the VPN"
out_leak=$(docker exec "$CLI" awg-leak 2>&1); rc_leak=$?
echo "$out_leak"
[ "$rc_leak" = 0 ]; check $? "awg-leak finds no leak on the client"
# The client's own resolver is docker's embedded one — the tunnel resolver has
# to be asked for by address — so what this asserts is that the tool says so
# instead of reporting a resolver the node does not have. The proof that it can
# fail lives in utiltest.sh, where a fake full tunnel is built for it.
out_named=$(docker exec "$CLI" env AWG_CLIENT_DNS="$RESOLVER" awg-leak 2>&1)
echo "$out_named" | head -2
grep -q "docker's embedded" <<< "$out_named"; check $? "awg-leak names docker's embedded resolver instead of the tunnel's"

# DIRECTION 7: what the operator configures, and what the node tells the
# resolver, both answered to the tunnel client.
hr "DIRECTION 7: allowlist, own records, the .vpn zone and peer names"
ask() { docker exec "$CLI" timeout 8 nslookup "$@" "$RESOLVER" 2>&1; }
ask www.example.net | grep -qE '^Address: [0-9]'
check $? "the allowlist lets www.example.net through a blocked example.net"
ask nas.home | grep -q '192.168.7.7'; check $? "an own record answers (nas.home)"
ask files.vpn | grep -q '172.29.172.250'; check $? "an own .vpn record answers (files.vpn)"
ask dns.vpn | grep -q "$STATUS_IP"; check $? "the built-in pages are in the zone (dns.vpn)"
ask resolver.vpn | grep -q "$RESOLVER"; check $? "the resolver names itself (resolver.vpn)"
ask "n$RANDOM.leak.vpn" | grep -q "$STATUS_IP"; check $? "any <nonce>.leak.vpn answers"

issued=$(docker exec -e AWG_ENDPOINT=172.31.98.10:51820 "$SRV" awg-peer add phone 2>&1)
phone_ip=$(sed -n 's/^Address = //p' <<< "$issued" | cut -d/ -f1)
echo "issued phone at ${phone_ip:-nothing}"
if [ "$V" = 3.1 ]; then
    grep -q '^RandomTrailers' "$WORK/server.conf" && grep -q '^RandomTrailers' <<< "$issued"
    check $? "the issued config carries the server's RandomTrailers"
fi
allowed=$(sed -n 's/^AllowedIPs = //p' <<< "$issued")
echo "issued AllowedIPs: $allowed"
grep -qE '172\.29\.172\.(0/24|253)|0\.0\.0\.0/0' <<< "$allowed"
check $? "the issued config routes the status page, not only the resolver"
found=
for _ in $(seq 1 6); do
    if ask phone.peer.vpn | grep -q "${phone_ip:-none}"; then found=1; break; fi
    sleep 3
done
[ -n "$found" ]; check $? "a new peer answers as phone.peer.vpn without a resolver restart"
rev=$(awk -F. '{print $4"."$3"."$2"."$1}' <<< "${phone_ip:-0.0.0.0}")
ask -type=PTR "$rev.in-addr.arpa" | grep -q 'phone.peer.vpn'
check $? "and its address reads back as phone.peer.vpn"

hr "RESULT"
if [ "$FAIL" = 0 ]; then
    echo "AWG $V DNS: reachable through the tunnel, unreachable from outside it"
else
    echo "AWG $V DNS: FAILURES above"
fi
exit "$FAIL"
