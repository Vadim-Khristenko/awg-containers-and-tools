#!/bin/sh
# CGI: what node.vpn says about the node, in key=value lines.
#
# The node writes node.txt next to its peer names (protocol, daemon, MTU, when
# it came up). Of the names themselves only their count is given: every peer
# can open this page, and which other peers exist is not theirs to read.
printf 'Content-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\n\r\n'
DIR="${AWG_NAMES_DIR:-/var/lib/awg-names}"
if [ -r "$DIR/node.txt" ]; then
    grep -E '^(protocol|daemon|mtu|started)=[A-Za-z0-9._-]*$' "$DIR/node.txt"
else
    printf 'node=unknown\n'
fi
if [ -r "$DIR/names.hosts" ]; then
    printf 'peers=%s\n' "$(grep -c . "$DIR/names.hosts" 2>/dev/null || echo 0)"
fi
printf 'now=%s\n' "$(date +%s)"
