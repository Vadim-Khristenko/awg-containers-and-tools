#!/usr/bin/env bash
# All five AmneziaWG generations on one host at the same time.
#
#   ./paralleltest.sh
#
# Not five runs of selftest.sh in sequence — that proves nothing about
# interference. Everything is stood up first, and only then is every tunnel
# checked, so each check happens with the other four running. The transfers are
# started together on purpose.
#
# What is deliberately made distinct, and what would collide if it were not:
#
#   listen port     51821..51825      published on the host; two services cannot
#                                     bind the same UDP port, so this one is real
#   tunnel subnet   10.20{1..5}.0/24  overlapping tunnels would send a packet
#                                     down whichever interface matched first
#   interface name  awg1 awg15 awg2 awg3 awg31
#   transport net   172.30.1{1..5}.0/24
#   fwmark / table  default to the listen port (see entrypoint.sh) rather than a
#                   constant, which is what makes host-network operation safe
set -uo pipefail

PREFIX="${AWG_IMAGE_PREFIX:-vaiprog/}"
VERSIONS=(1.0 1.5 2.0 3.0 3.1)
declare -A IMG=(
    [1.0]=${PREFIX}amnezia-wg-1:latest
    [1.5]=${PREFIX}amnezia-wg-15:latest
    [2.0]=${PREFIX}amnezia-wg-2:latest
    [3.0]=${PREFIX}amnezia-wg-3:latest
    [3.1]=${PREFIX}amnezia-wg-31:latest
)
declare -A IFACE=([1.0]=awg1 [1.5]=awg15 [2.0]=awg2 [3.0]=awg3 [3.1]=awg31)
declare -A PORT=( [1.0]=51821 [1.5]=51822 [2.0]=51823 [3.0]=51824 [3.1]=51825)
declare -A TUN=(  [1.0]=10.201 [1.5]=10.202 [2.0]=10.203 [3.0]=10.204 [3.1]=10.205)
declare -A XNET=( [1.0]=172.30.11 [1.5]=172.30.12 [2.0]=172.30.13 [3.0]=172.30.14 [3.1]=172.30.15)

WORK=
AWG_TOOL=${AWG_TOOL:-$(dirname "$0")/../target/debug/awg-tool}
FAIL=0

hr()    { printf '\n===== %s =====\n' "$*"; }
check() { if [ "$1" = 0 ]; then echo "  PASS  $2"; else echo "  FAIL  $2"; FAIL=1; fi; }
net()   { printf 'awgpar-%s' "${1/./}"; }
srv()   { printf 'awgpar-%s-server' "${1/./}"; }
cli()   { printf 'awgpar-%s-client' "${1/./}"; }

cleanup() {
    for v in "${VERSIONS[@]}"; do
        docker rm -f "$(srv "$v")" "$(cli "$v")" >/dev/null 2>&1
        docker network rm "$(net "$v")" >/dev/null 2>&1
    done
    if [ -n "$WORK" ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
cleanup
WORK=$(mktemp -d)

hr "bringing up five generations at once"
for v in "${VERSIONS[@]}"; do
    i=${IFACE[$v]}; t=${TUN[$v]}; x=${XNET[$v]}; p=${PORT[$v]}; img=${IMG[$v]}
    "$AWG_TOOL" gen --version "$v" > "$WORK/params-$v.conf" || exit 1

    sp=$(docker run --rm --entrypoint awg "$img" genkey)
    su=$(printf '%s' "$sp" | docker run --rm -i --entrypoint awg "$img" pubkey)
    cp=$(docker run --rm --entrypoint awg "$img" genkey)
    cu=$(printf '%s' "$cp" | docker run --rm -i --entrypoint awg "$img" pubkey)
    k=$(docker run --rm --entrypoint awg "$img" genpsk)
    params=$(cat "$WORK/params-$v.conf")
    srv_params=$params
    # 1.5 sends its I-chains client-side only.
    if [ "$v" = 1.5 ]; then srv_params=$(grep -vE '^I[1-5] ' <<< "$params"); fi

    cat > "$WORK/server-$v.conf" <<EOF
[Interface]
PrivateKey = $sp
Address = $t.0.1/24
ListenPort = $p
MTU = 1280
$srv_params

[Peer]
PublicKey = $cu
PresharedKey = $k
AllowedIPs = $t.0.2/32
EOF
    cat > "$WORK/client-$v.conf" <<EOF
[Interface]
PrivateKey = $cp
Address = $t.0.2/24
MTU = 1280
$params

[Peer]
PublicKey = $su
PresharedKey = $k
AllowedIPs = $t.0.0/24
Endpoint = $(srv "$v"):$p
PersistentKeepalive = 15
EOF
    chmod 644 "$WORK"/*.conf

    docker network create --subnet "$x.0/24" "$(net "$v")" >/dev/null || exit 1
    docker run -d --name "$(srv "$v")" --network "$(net "$v")" --ip "$x.10" \
        --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 \
        -p "$p:$p/udp" -e "AWG_IFACE=$i" \
        -v "$WORK/server-$v.conf:/etc/amnezia/awg/$i.conf:ro" "${IMG[$v]}" >/dev/null || exit 1
    echo "  AWG $v  iface=$i  port=$p  tunnel=$t.0.0/24  transport=$x.0/24"
done
chmod 755 "$WORK"
sleep 4
for v in "${VERSIONS[@]}"; do
    docker run -d --name "$(cli "$v")" --network "$(net "$v")" --ip "${XNET[$v]}.11" \
        --cap-add NET_ADMIN --device /dev/net/tun -e "AWG_IFACE=${IFACE[$v]}" \
        -v "$WORK/client-$v.conf:/etc/amnezia/awg/${IFACE[$v]}.conf:ro" "${IMG[$v]}" >/dev/null || exit 1
done
sleep 10

hr "all ten containers are running at the same time"
docker ps --filter name=awgpar- --format '  {{.Names}}  {{.Image}}  {{.Status}}  {{.Ports}}'
running=$(docker ps --filter name=awgpar- --filter status=running -q | wc -l)
echo "  running: $running/8"
[ "$running" = 10 ]; check $? "ten containers up simultaneously"

hr "the host really is listening on five distinct ports"
ss -lnup 2>/dev/null | grep -E ':(5182[1-5])\b' || docker ps --filter name=awgpar- --format '{{.Ports}}'
n=$(docker ps --filter name=awgpar- --format '{{.Ports}}' | grep -oE '5182[1-5]->' | sort -u | wc -l)
echo "  distinct published UDP ports: $n"
[ "$n" = 5 ]; check $? "five distinct listen ports"

hr "distinct interface names and tunnel subnets"
for v in "${VERSIONS[@]}"; do
    echo "  AWG $v server: $(docker exec "$(srv "$v")" ip -o -4 addr show dev "${IFACE[$v]}" | awk '{print $2, $4}')"
done
u=$(for v in "${VERSIONS[@]}"; do docker exec "$(srv "$v")" ip -o -4 addr show dev "${IFACE[$v]}" | awk '{print $2 $4}'; done | sort -u | wc -l)
[ "$u" = 5 ]; check $? "five distinct interface/address pairs"

hr "each server's NAT rules name only its own interface"
for v in "${VERSIONS[@]}"; do
    echo "  AWG $v: $(docker exec "$(srv "$v")" iptables -t nat -S POSTROUTING | grep MASQUERADE)"
done

hr "every tunnel handshakes while the other four are up"
for v in "${VERSIONS[@]}"; do
    hs=""
    for _ in $(seq 1 15); do
        hs=$(docker exec "$(srv "$v")" awg-uapi get "${IFACE[$v]}" 2>/dev/null | grep -m1 '^last_handshake_time_sec=')
        [ -n "$hs" ] && [ "$hs" != "last_handshake_time_sec=0" ] && break
        sleep 2
    done
    echo "  AWG $v server: $hs"
    [ -n "$hs" ] && [ "$hs" != "last_handshake_time_sec=0" ]; check $? "AWG $v handshake"
done

hr "traffic on all five at once"
for v in "${VERSIONS[@]}"; do
    docker exec "$(srv "$v")" sh -c "nohup socat -u TCP-LISTEN:9000,reuseaddr,bind=${TUN[$v]}.0.1 CREATE:/tmp/recv.bin >/dev/null 2>&1 &"
done
sleep 2
# Started together, not one after another: the point is five tunnels moving data
# in the same seconds, on one host, through one kernel's tun driver.
for v in "${VERSIONS[@]}"; do
    ( docker exec "$(cli "$v")" sh -c \
        "dd if=/dev/urandom of=/tmp/send.bin bs=1M count=4 2>/dev/null; \
         socat -u OPEN:/tmp/send.bin TCP:${TUN[$v]}.0.1:9000; \
         sha256sum /tmp/send.bin | cut -d' ' -f1" > "$WORK/sent-$v" 2>&1 ) &
done
wait
sleep 3
for v in "${VERSIONS[@]}"; do
    a=$(tail -1 "$WORK/sent-$v")
    b=$(docker exec "$(srv "$v")" sh -c 'sha256sum /tmp/recv.bin | cut -d" " -f1')
    echo "  AWG $v  sent $a"
    echo "  AWG $v  recv $b"
    [ -n "$a" ] && [ "$a" = "$b" ]; check $? "AWG $v moved 4 MiB intact"
    docker exec "$(cli "$v")" ping -c 3 -W 3 "${TUN[$v]}.0.1" >/dev/null 2>&1
    check $? "AWG $v ICMP client -> server"
done

hr "and all five are still up afterwards"
for v in "${VERSIONS[@]}"; do
    echo "  AWG $v: $(docker exec "$(srv "$v")" awg-uapi get "${IFACE[$v]}" 2>/dev/null | grep -E '^(tx_bytes|rx_bytes)=' | tr '\n' ' ')"
done
still=$(docker ps --filter name=awgpar- --filter status=running -q | wc -l)
echo "  running: $still/8"
[ "$still" = 10 ]; check $? "nothing died while the others worked"

hr "RESULT"
if [ "$FAIL" = 0 ]; then
    echo "1.0, 1.5, 2.0 and 3.0 ran together on one host with no interference"
else
    echo "FAILURES above"
fi
exit "$FAIL"
