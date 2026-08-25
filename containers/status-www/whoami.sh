#!/bin/sh
# CGI under busybox httpd: echo the address the request came from.
#
# That address is the visitor's own tunnel IP — the one thing this page can
# say about them that they cannot already see in their client. No headers are
# forwarded anywhere, nothing is logged by this script, and the answer never
# leaves the tunnel.
#
# busybox httpd runs CGI with REMOTE_ADDR in the environment; the body is
# plain text, one line, ready for a fetch().
#
# A dual-stack socket reports IPv4 clients in IPv4-mapped form, wrapped in
# brackets — [::ffff:10.0.0.2] — which is true and useless at the same time:
# the visitor's client shows the plain four octets, and the page should speak
# the same language. The brackets are why this is a case rather than a ${#}
# trim: a leading [ in a pattern starts a character class, and quoting the
# prefix is the one way to say "literal" that every shell agrees on.
printf 'Content-Type: text/plain; charset=utf-8\r\n\r\n'
addr=${REMOTE_ADDR:-unknown}
prefix='[::ffff:'
case "$addr" in
    "$prefix"*) addr=${addr#"$prefix"}; addr=${addr%\]} ;;
esac
printf '%s\n' "$addr"
