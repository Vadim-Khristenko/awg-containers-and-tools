#!/bin/sh
# CGI: ask the tunnel resolver one name, for the dns.vpn page.
#
#   /cgi-bin/lookup?name=example.com
#
# The page cannot ask DNS itself, and its own name resolving proves only that
# the browser's lookups reach the resolver, not what the resolver says about
# anything else. This asks it from next door, on the resolver's own network.
# Only a name is accepted, nothing is logged, and the answer is key=value
# lines:
#
#   name=example.com
#   status=ok|nxdomain|fail
#   address=93.184.215.14       (one line per address)
set -f
printf 'Content-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\n\r\n'
RESOLVER="${AWG_RESOLVER:-172.29.172.254}"

name=
for kv in $(printf '%s' "${QUERY_STRING:-}" | tr '&' ' '); do
    case "$kv" in name=*) name=${kv#name=} ;; esac
done
name=$(printf '%s' "$name" | tr 'A-Z' 'a-z')
name=${name%.}
case "$name" in
    ""|*[!a-z0-9._-]*|.*|*..*)
        printf 'status=refused\n'
        exit 0 ;;
esac
if [ "${#name}" -gt 253 ]; then
    printf 'status=refused\n'
    exit 0
fi

printf 'name=%s\n' "$name"
out=$(nslookup -timeout=3 -retry=1 "$name" "$RESOLVER" 2>&1) || true
case "$out" in
    *NXDOMAIN*) printf 'status=nxdomain\n'; exit 0 ;;
esac
addrs=$(printf '%s\n' "$out" | awk '/^Name:/ { named = 1 } named && /^Address/ { sub(/^Address[^:]*: */, ""); print }' | sort -u)
if [ -n "$addrs" ]; then
    printf 'status=ok\n'
    printf '%s\n' "$addrs" | sed 's/^/address=/'
else
    printf 'status=fail\n'
fi
