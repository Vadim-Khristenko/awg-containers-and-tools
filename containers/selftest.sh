#!/usr/bin/env bash
# Stands up a two-container AmneziaWG tunnel on a throwaway docker network and
# proves it works: UAPI acceptance, handshake, traffic. Removes everything it
# made when it is done.
#
#   ./selftest.sh 3.1        # or 1.0 / 1.5 / 2.0 / 3.0; default 3.0
set -uo pipefail

V=${1:-3.0}
PREFIX="${AWG_IMAGE_PREFIX:-vaiprog/}"
case "$V" in
    1.0) IMG=${PREFIX}amnezia-wg-1:latest  ;;
    1.5) IMG=${PREFIX}amnezia-wg-15:latest ;;
    2.0) IMG=${PREFIX}amnezia-wg-2:latest  ;;
    3.0) IMG=${PREFIX}amnezia-wg-3:latest  ;;
    3.1) IMG=${PREFIX}amnezia-wg-31:latest ;;
    *)   echo "usage: $0 [1.0|1.5|2.0|3.0|3.1]" >&2; exit 2 ;;
esac

NET=awgselftest
SRV=awg-selftest-server
CLI=awg-selftest-client
WORK=
AWG_TOOL=${AWG_TOOL:-$(dirname "$0")/../target/debug/awg-tool}
FAIL=0

hr()   { printf '\n===== %s =====\n' "$*"; }
check() { if [ "$1" = 0 ]; then echo "  PASS  $2"; else echo "  FAIL  $2"; FAIL=1; fi; }
cleanup() {
    docker rm -f "$SRV" "$CLI" >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
    if [ -n "$WORK" ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
cleanup
WORK=$(mktemp -d)

hr "AWG $V — parameters"
"$AWG_TOOL" gen --version "$V" > "$WORK/params.conf" || exit 1
cat "$WORK/params.conf"

srv_priv=$(docker run --rm --entrypoint awg "$IMG" genkey)
srv_pub=$(printf '%s' "$srv_priv" | docker run --rm -i --entrypoint awg "$IMG" pubkey)
cli_priv=$(docker run --rm --entrypoint awg "$IMG" genkey)
cli_pub=$(printf '%s' "$cli_priv" | docker run --rm -i --entrypoint awg "$IMG" pubkey)
psk=$(docker run --rm --entrypoint awg "$IMG" genpsk)
params=$(cat "$WORK/params.conf")

# In 1.5 the I-chains are client-side only, so they are stripped from the server
# config — a 1.5 server that echoes them back is not what a 1.5 client expects.
srv_params=$params
if [ "$V" = 1.5 ]; then srv_params=$(grep -vE '^I[1-5] ' <<< "$params"); fi

cat > "$WORK/server.conf" <<EOF
[Interface]
PrivateKey = $srv_priv
Address = 10.99.0.1/24
ListenPort = 51820
MTU = 1280
$srv_params

[Peer]
PublicKey = $cli_pub
PresharedKey = $psk
AllowedIPs = 10.99.0.2/32
EOF

cat > "$WORK/client.conf" <<EOF
[Interface]
PrivateKey = $cli_priv
Address = 10.99.0.2/24
MTU = 1280
$params

[Peer]
PublicKey = $srv_pub
PresharedKey = $psk
AllowedIPs = 10.99.0.0/24
Endpoint = $SRV:51820
PersistentKeepalive = 15
EOF
chmod 644 "$WORK"/*.conf; chmod 755 "$WORK"

hr "containers"
docker network create --subnet 172.31.99.0/24 "$NET" >/dev/null || exit 1
docker run -d --name "$SRV" --network "$NET" --ip 172.31.99.10 \
    --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 \
    -e AWG_DUMP_REQUEST=1 -v "$WORK/server.conf:/etc/amnezia/awg/awg0.conf:ro" \
    "$IMG" >/dev/null || exit 1
sleep 3
docker run -d --name "$CLI" --network "$NET" --ip 172.31.99.11 \
    --cap-add NET_ADMIN --device /dev/net/tun \
    -e AWG_DUMP_REQUEST=1 -v "$WORK/client.conf:/etc/amnezia/awg/awg0.conf:ro" \
    "$IMG" >/dev/null || exit 1
sleep 6
docker logs "$SRV" 2>&1 | grep -E '^(>>|!!)'
docker logs "$CLI" 2>&1 | grep -E '^(>>|!!)'

hr "PROOF 1 — the daemon accepted the parameters"
for c in "$SRV" "$CLI"; do
    out=$(docker exec "$c" cat /tmp/uapi-set.out 2>&1)
    echo "$c set=1 -> $out"
    [ "$out" = "errno=0" ]; check $? "$c accepted the config"
done
echo "--- server get=1 ---"
docker exec "$SRV" awg-uapi get 2>&1 | grep -vE '^(private_key|preshared_key)='

hr "PROOF 2 — handshake"
for _ in $(seq 1 20); do
    hs=$(docker exec "$SRV" awg-uapi get 2>/dev/null | grep -m1 '^last_handshake_time_sec=')
    [ -n "$hs" ] && [ "$hs" != "last_handshake_time_sec=0" ] && break
    sleep 3
done
echo "server: $hs   (now: $(date +%s))"
echo "client: $(docker exec "$CLI" awg-uapi get 2>/dev/null | grep -m1 '^last_handshake_time_sec=')"
[ -n "$hs" ] && [ "$hs" != "last_handshake_time_sec=0" ]; check $? "handshake completed"

hr "PROOF 3 — traffic"
docker exec "$CLI" ping -c 4 -W 3 10.99.0.1 2>&1 | tail -3
docker exec "$CLI" ping -c 4 -W 3 10.99.0.1 >/dev/null 2>&1; check $? "ICMP client -> server"
docker exec "$SRV" ping -c 4 -W 3 10.99.0.2 >/dev/null 2>&1; check $? "ICMP server -> client"

docker exec "$SRV" sh -c 'nohup socat -u TCP-LISTEN:9000,reuseaddr,bind=10.99.0.1 CREATE:/tmp/recv.bin >/dev/null 2>&1 &'
sleep 2
a=$(docker exec "$CLI" sh -c 'dd if=/dev/urandom of=/tmp/send.bin bs=1M count=4 2>/dev/null; socat -u OPEN:/tmp/send.bin TCP:10.99.0.1:9000; sha256sum /tmp/send.bin | cut -d" " -f1')
sleep 2
b=$(docker exec "$SRV" sh -c 'sha256sum /tmp/recv.bin | cut -d" " -f1')
echo "sent   sha256: $a"
echo "recv   sha256: $b"
[ -n "$a" ] && [ "$a" = "$b" ]; check $? "4 MiB TCP transfer intact"
docker exec "$SRV" awg-uapi get 2>&1 | grep -E '^(tx_bytes|rx_bytes)='

# The health check and the diagnostic bundle run on a live node, because that
# is where they will be used. The dump gets its own secret check: it is made
# for pasting, so the one way it must never fail is by carrying a key.
hr "PROOF 4 — health check and the diagnostic bundle"
docker exec "$SRV" awg-health >/dev/null 2>&1; check $? "awg-health: server reports healthy"
docker exec "$CLI" awg-health >/dev/null 2>&1; check $? "awg-health: client reports healthy"
dump=$(docker exec "$SRV" awg-dump 2>&1)
echo "$dump" | sed -n '1,8p'
echo "$dump" | grep -q "===== interface"; check $? "awg-dump produced its sections"
if printf '%s' "$dump" | grep -qF -- "$srv_priv"; then rc=1; else rc=0; fi
check $rc "awg-dump carries no private key"
if printf '%s' "$dump" | grep -qF -- "$psk"; then rc=1; else rc=0; fi
check $rc "awg-dump carries no preshared key"
# By now more than one 30s health interval has passed since start; the
# orchestrator-visible status should agree with what awg-health just said.
status=$(docker inspect -f '{{.State.Health.Status}}' "$SRV" 2>/dev/null || echo unknown)
echo "docker health status: $status"
[ "$status" = "healthy" ]; check $? "docker reports the server container healthy"

hr "RESULT"
if [ "$FAIL" = 0 ]; then echo "AWG $V: all checks passed"; else echo "AWG $V: FAILURES above"; fi
exit "$FAIL"
