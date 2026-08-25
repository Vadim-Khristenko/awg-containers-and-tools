#!/bin/sh
# One command, the whole picture: a diagnostic bundle for "why is this node
# not working" moments.
#
#   awg-dump              # everything, to stdout
#   awg-dump > dump.txt   # the usual way — it is made for pasting
#
# What goes in: interface state, routes and rules, the UAPI view of the device
# (peers, handshakes, transfer counters), the NAT rules, and the tail of the
# operational event log. The things an operator needs to see side by side,
# because the bug is usually in how two of them disagree.
#
# What never goes in, and this is the point of the script rather than a nice
# extra: private keys and preshared keys. A bundle is made to leave the node —
# pasted into an issue, attached to a message, read by whoever helps today.
# The UAPI dump is filtered the same way the event log is: a public key
# identifies a peer perfectly well, and nothing here needs a secret.
#
# Sections that fail (no NAT rules, no event log yet) print a marker and move
# on — a broken node rarely breaks every source the same way, and the dump is
# most useful exactly when the node is at its worst.
set -u

IFACE="${AWG_IFACE:-awg0}"
EVENT_LOG="${AWG_EVENT_LOG:-/var/log/awg/events.log}"

hr() { printf '\n===== %s =====\n' "$*"; }

hr "node"
echo "protocol: ${AWG_PROTOCOL:-unknown}"
echo "daemon:   $(amneziawg-go --version 2>/dev/null | head -1 || echo 'unknown')"
echo "uptime:   $(cat /proc/uptime 2>/dev/null | cut -d' ' -f1 || echo '?')s"
echo "date:     $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

hr "interface $IFACE"
ip address show dev "$IFACE" 2>&1 || echo "($IFACE does not exist)"

hr "routes"
ip route show 2>&1
echo "--- rules ---"
ip rule show 2>&1

hr "device (UAPI get=1, keys redacted)"
# private_key and preshared_key are the only lines the daemon sends in clear;
# everything else — endpoints, handshakes, counters — is public by nature.
awg-uapi get "$IFACE" 2>&1 | grep -vE '^(private_key|preshared_key)=' || echo "(UAPI did not answer)"

hr "firewall (rules naming $IFACE)"
iptables -S 2>/dev/null | grep "$IFACE" || echo "(no rules naming $IFACE)"
iptables -t nat -S 2>/dev/null | grep "$IFACE" || echo "(no NAT rules naming $IFACE)"

hr "event log (last 40)"
if [ -r "$EVENT_LOG" ]; then
    tail -n 40 "$EVENT_LOG"
else
    echo "(no event log at $EVENT_LOG)"
fi

hr "end of dump"
