#!/usr/bin/env bash
# The node utilities on their own: awg-health, awg-under, awg-leak.
#
#   ./utiltest.sh [1.0|1.5|2.0|3.0|3.1]      default 3.0
#
# No tunnel and no second network — a dummy interface, a page, seconds rather
# than minutes. selftest.sh is what proves a tunnel carries traffic; this is
# what proves the checks can say no.
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
PAGE=${PREFIX}amnezia-wg-status:latest
NODE=awg-util-node
PAGE_C=awg-util-page
FAIL=0

hr()    { printf '\n===== %s =====\n' "$*"; }
check() { if [ "$1" = 0 ]; then echo "  PASS  $2"; else echo "  FAIL  $2"; FAIL=1; fi; }
cleanup() { docker rm -f "$NODE" "$PAGE_C" >/dev/null 2>&1; }
trap cleanup EXIT
cleanup

hr "a node with no tunnel says so"
docker run -d --name "$NODE" --cap-add NET_ADMIN --entrypoint sleep "$IMG" 600 >/dev/null || exit 1
out=$(docker exec "$NODE" awg-health 2>&1); rc=$?
echo "$out"
[ "$rc" != 0 ]; check $? "awg-health fails when there is no interface"
grep -q 'does not exist' <<< "$out"; check $? "...and names the interface that is missing"
out=$(docker exec "$NODE" awg-under 2>&1); rc=$?
echo "$out"
[ "$rc" != 0 ]; check $? "awg-under answers 'not under the VPN' with no tunnel"

hr "a fake tunnel: awg-leak must find what a copied config leaks"
# A full-tunnel config with a default route that does not go into awg0 is
# exactly what a client is left with when the tunnel is up but nothing routes.
docker exec "$NODE" ip link add awg0 type dummy
docker exec "$NODE" ip addr add 10.99.0.2/24 dev awg0
docker exec "$NODE" ip link set awg0 up
docker exec "$NODE" sh -c \
    'mkdir -p /etc/amnezia/awg && printf "[Interface]\nAddress = 10.99.0.2/24\n\n[Peer]\nAllowedIPs = 0.0.0.0/0\n" > /etc/amnezia/awg/awg0.conf'
out=$(docker exec "$NODE" awg-leak 2>&1); rc=$?
echo "$out"
[ "$rc" != 0 ]; check $? "awg-leak fails a full tunnel whose default route is elsewhere"
grep -q 'not the tunnel' <<< "$out"; check $? "...and says which line is the leak"
grep -q '^tunnel' <<< "$out"; check $? "...while still reporting the interface it looked at"

# The interface is there now, so this is the other half of the health check:
# up does not mean answering.
docker exec "$NODE" awg-health >/dev/null 2>&1; rc=$?
[ "$rc" != 0 ]; check $? "awg-health still fails when nothing answers on UAPI"

hr "awg-under: a page that answers is the answer"
docker run -d --name "$PAGE_C" "$PAGE" >/dev/null || exit 1
sleep 3
node_ip=$(docker inspect -f '{{.NetworkSettings.IPAddress}}' "$NODE")
out=$(docker exec "$NODE" awg-under "$PAGE_C" 2>&1); rc=$?
echo "$out"
[ "$rc" = 0 ] && grep -q 'under the VPN: http://' <<< "$out"; check $? "awg-under passes when the page answers"
# ...and tells the two cases apart: the same page, with the address it should
# report, is a confirmation rather than a note about translation.
out=$(docker exec -e AWG_UNDER_EXPECT="$node_ip" "$NODE" awg-under "$PAGE_C" 2>&1); rc=$?
echo "$out"
[ "$rc" = 0 ] && grep -q 'which is this node' <<< "$out"; check $? "...and confirms the address when it matches"
out=$(docker exec "$NODE" awg-under "$PAGE_C:9" 2>&1); rc=$?
echo "$out"
[ "$rc" != 0 ]; check $? "awg-under fails when nothing answers"

hr "RESULT"
if [ "$FAIL" = 0 ]; then echo "AWG $V utilities: all checks passed"; else echo "AWG $V utilities: FAILURES above"; fi
exit "$FAIL"
