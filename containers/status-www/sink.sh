#!/bin/sh
# CGI: read an upload and throw it away, for the speed.vpn and mtu.vpn pages.
#
# Answers with the number of bytes it read, so the page knows the whole body
# arrived rather than only that the request ended. Bodies past 64 MiB are not
# read at all: the measurement needs megabytes, and a page that anybody in the
# tunnel can open must not be a way to keep this container busy.
printf 'Content-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\n\r\n'
n=${CONTENT_LENGTH:-0}
case "$n" in ""|*[!0-9]*) n=0 ;; esac
if [ "$n" -gt 67108864 ]; then
    printf 'refused\n'
    exit 0
fi
got=$(head -c "$n" | wc -c | tr -d ' ')
printf '%s\n' "$got"
