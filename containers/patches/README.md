# Patches to amneziawg-go

Fixes this project applies to a daemon tag that upstream will not release
again. Each lives under the tag it applies to and is applied in name order by
the `Dockerfile` (`git apply`), right after the clone; the names of what was
applied are kept in the image at `/usr/share/awg/patches`, and `awg-dump`
prints them. A tag without a directory here is built exactly as upstream
tagged it.

A patch changes an image's inputs fingerprint (`inputs-digest.sh`), so the
release pipeline rebuilds that image and only that one.

## v0.2.14-beta-awg-1.5-1 (AWG 1.5)

### 0001: keep transport packets that line up with a handshake size

The last tag of the 1.5 line drops every transport packet whose size equals
the size of a handshake message (`S1 + 148`, `S2 + 92`, or the cookie reply's).
`ProcessAWGPacket` looks for the expected magic header at the junk offset;
a transport packet has ciphertext there, which almost never matches any
header, and the resulting error made `RoutineReceiveIncoming` discard the
packet. The fallback to the transport path a few lines down was written for
exactly this case and was only reached when the ciphertext happened to match
another message's header.

What it looked like: a tunnel that handshakes and passes `ping` of most sizes,
while particular packet sizes never arrive. In `dnstest.sh` the tunnel client's
DNS queries and the page's TCP handshake were the ones that matched, so
everything forwarded to the resolver network timed out while ICMP got through.

1.0 (`v0.2.12`) keeps such a packet: it checks the type at the junk offset and
falls back to treating it as transport. From 2.0 (`v0.2.16`) the receive path
was rewritten (`DeterminePacketTypeAndPadding`) and does not have the problem.
The patch makes 1.5 do what 1.0 did: a known size whose header does not match
goes down the transport path, where it is decrypted or rejected as any other
transport packet would be.
