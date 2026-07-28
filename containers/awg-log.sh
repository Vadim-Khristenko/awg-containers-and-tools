#!/bin/sh
# The operational event log, shared by entrypoint.sh and awg-peer.
#
# What goes in: the things an operator has to be able to reconstruct after the
# fact — when the node came up, when the interface was configured, who was given
# access and when it was taken away. A peer is named by its *public* key and by
# whatever label the operator chose, both of which are already public.
#
# What never goes in, and why: private keys, preshared keys, passphrases and
# whole config bodies. A log is copied, tailed, shipped to a collector and read
# by whoever is debugging today. Putting a key in it turns one secret into an
# unbounded number of copies of that secret, and nothing in here needs a key to
# be useful — a public key identifies a peer perfectly well.
#
# The log is therefore still sensitive: it is a list of who has access to this
# server and when they got it. It stays on the node; see containers/README.md.

EVENT_LOG="${AWG_EVENT_LOG:-/var/log/awg/events.log}"
# Bounded by construction: at most this many bytes live, plus one rotation of
# the same size. A node that flaps every ten seconds for a year still costs the
# same half megabyte, which is the point — an unbounded log on a VPN gateway
# fills the disk and takes the tunnel down with it.
EVENT_LOG_MAX="${AWG_EVENT_LOG_MAX_BYTES:-262144}"

# awg_event <kind> [key=value ...]
awg_event() {
    _kind=$1
    shift
    _line="$(date -u '+%Y-%m-%dT%H:%M:%SZ') iface=${AWG_IFACE:-awg0} event=${_kind}"
    for _kv in "$@"; do
        _line="${_line} ${_kv}"
    done
    # stderr as well as the file, so `docker logs` shows the same story without
    # anyone having to know the log exists.
    printf '%s\n' "$_line" >&2

    _dir=$(dirname "$EVENT_LOG")
    mkdir -p "$_dir" 2>/dev/null || return 0
    # Rotation is checked here because nothing in this image runs on a timer:
    # the moment of writing is the only moment the file can have grown.
    if [ -f "$EVENT_LOG" ]; then
        _sz=$(wc -c < "$EVENT_LOG" 2>/dev/null || echo 0)
        if [ "${_sz:-0}" -ge "$EVENT_LOG_MAX" ]; then
            mv -f "$EVENT_LOG" "${EVENT_LOG}.1" 2>/dev/null || : > "$EVENT_LOG"
        fi
    fi
    printf '%s\n' "$_line" >> "$EVENT_LOG" 2>/dev/null || true
    # The log names who has access; nobody but root needs to read it.
    chmod 600 "$EVENT_LOG" 2>/dev/null || true
    unset _kind _line _kv _dir _sz
}
