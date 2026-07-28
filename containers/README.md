# AmneziaWG containers — 1.0, 1.5, 2.0, 3.0

Self-hosted AmneziaWG server/client images, plus a tunnel-only resolver.
Unofficial: a community build by Vadim Khristenko (VAI_PROG), not affiliated
with, endorsed by or supported by AmneziaVPN. Problems with these images belong
in [this project's tracker](https://github.com/Vadim-Khristenko/awg-containers-and-tools),
not in theirs.

| file | what it does |
|---|---|
| `Dockerfile` / `build.sh` | the four protocol images, one build arg apart |
| `Dockerfile.dns` / `unbound.conf` | the resolver, `vaiprog/amnezia-wg-dns` |
| `entrypoint.sh` | `.conf` → UAPI, addresses, routes, NAT, event log |
| `awg-peer` | add / list / revoke peers, issue client configs |
| `awg-uapi` | raw `get=1` / arbitrary requests against the socket |
| `awg-log.sh` | the event log, shared by the two above |
| `selftest.sh` | one generation end to end: `errno=0`, handshake, traffic |
| `dnstest.sh` | the DNS anti-leak claim, in both directions |
| `paralleltest.sh` | all four generations at once on one host |
| `docker-compose.yml` | a 3.0 pair plus the resolver |

## Why these exist

Upstream ships no self-hosted AmneziaWG 3.0. Their server pipeline drives
`awg-quick`, and `amneziawg-tools` — on released tags *and* on master — parses
only the AWG 2.0 keys. Feeding it a 3.0 config fails at the first new line:

```
$ awg setconf awg0 server.conf
Line unrecognized: `HeaderProtectionKey=tuLp212e3bgF3N95SURzUJuJO1CzrZJeO54ZATG0cQo='
Configuration parsing error
$ # remove that line and it just moves on to the next one
Line unrecognized: `ContentPaddingAddition=22-86'
Configuration parsing error
```

`amneziawg-go` itself understands all of it. So the entrypoint skips the tools
entirely: it translates the `.conf` into a UAPI `set=1` request and writes it to
the daemon's socket. The daemon is the only component that has to know about
3.0, and the same code path serves every older generation, because only the keys
actually present in the config are ever emitted.

`awg` is still shipped in the image, but only for key material
(`genkey`/`pubkey`/`genpsk`), which no AWG generation changed.

## Images

One `Dockerfile`, one build arg. The only thing that differs between the four
images is the `amneziawg-go` tag — the entrypoint, the base and the tools build
are identical — so four copies of the same file would only be four things to
keep in sync.

| image                     | AWG | size   | `amneziawg-go` | what that tag adds                                        |
|---------------------------|-----|--------|----------------|-----------------------------------------------------------|
| `vaiprog/amnezia-wg-1`    | 1.0 | 33.3 MB | `v0.2.12`      | Jc/Jmin/Jmax, S1/S2, fixed H1–H4                          |
| `vaiprog/amnezia-wg-15`   | 1.5 | 34.1 MB | `v0.2.14-beta-awg-1.5-1` | + I1–I5 special junk (`<b> <c> <t> <r> <wt>` only), `Itime` |
| `vaiprog/amnezia-wg-2`    | 2.0 | 33.4 MB | `v0.2.19`      | + S3/S4, H1–H4 as ranges, `<rc> <rd> <d> <ds> <dz>` chain tags |
| `vaiprog/amnezia-wg-3`    | 3.0 | 33.4 MB | `v3.0.2`       | + HeaderProtectionKey, ContentPaddingAddition, timer ranges |
| `vaiprog/amnezia-wg-dns`  | —   | 19.6 MB | —              | unbound; the tunnel-only resolver, see [DNS](#dns-with-no-leaks) |

The major number is spelled without its dot — `amnezia-wg-15`, not
`amnezia-wg-1.5` — because a Docker repository path segment containing a dot
reads as a registry hostname.

### Metadata

Every image carries the full OCI set, so `docker inspect` answers the questions
an operator actually asks without anyone having to remember what a tag meant:

```
$ docker inspect vaiprog/amnezia-wg-15 --format '{{json .Config.Labels}}' | jq
{
  "org.opencontainers.image.title":         "AmneziaWG 1.5 node (unofficial)",
  "org.opencontainers.image.description":   "Self-hosted AmneziaWG 1.5 server/client on amneziawg-go v0.2.14-beta-awg-1.5-1. UNOFFICIAL community build — not affiliated with, endorsed by or supported by AmneziaVPN; report problems to this project, not to them.",
  "org.opencontainers.image.authors":       "Vadim Khristenko (VAI_PROG)",
  "org.opencontainers.image.vendor":        "Vadim Khristenko (VAI_PROG)",
  "org.opencontainers.image.licenses":      "MIT",
  "org.opencontainers.image.source":        "https://github.com/Vadim-Khristenko/awg-containers-and-tools",
  "org.opencontainers.image.url":           "https://github.com/Vadim-Khristenko/awg-containers-and-tools",
  "org.opencontainers.image.documentation": "https://architect.vai-rice.space",
  "org.opencontainers.image.version":       "v0.2.14-beta-awg-1.5-1",
  "org.opencontainers.image.created":       "2026-07-28T16:54:47Z",
  "org.opencontainers.image.base.name":     "docker.io/library/alpine:3.24",
  "space.vai-rice.awg.protocol":            "1.5",
  "space.vai-rice.awg.go-version":          "v0.2.14-beta-awg-1.5-1",
  "space.vai-rice.awg.tools-version":       "v1.0.20260618-2"
}
```

`image.version` is the `amneziawg-go` tag rather than the protocol generation:
it is the only thing that actually differs between the four images, and it is
what someone comparing a running container against an advisory needs. The
protocol generation is `space.vai-rice.awg.protocol`, and the container also
exports it as `$AWG_PROTOCOL` so the event log can name it.

`image.created` comes from `build.sh`, which stamps one timestamp across the
whole run. The `Dockerfile` default is the epoch, not `now`: a Dockerfile that
reads the clock produces an image nobody can reproduce, and an obvious zero is
better than a plausible lie. Set `SOURCE_DATE_EPOCH` to pin it.

Tags were picked by diffing the `case "…"` list in `device/uapi.go` at every
tag, not by reading release notes:

* `v0.2.12` is the last tag where `h1` is `strconv.ParseUint` and there is no
  `s3`/`s4` and no `i1`–`i5` — i.e. exactly the 1.0 key set.
* `v0.2.13` introduces `i1`–`i5` plus `itime`, still with a fixed `h1`;
  `v0.2.14-beta-awg-1.5-1` is the last tag in that line (upstream labels these
  `-beta-awg-1.5-*`, which is as explicit as it gets).
* `v0.2.15` drops `itime` and moves to `awg.ParseMagicHeader`; by `v0.2.16` the
  headers are `newMagicHeader`, which accepts `lo-hi`. `v0.2.19` is the last
  0.2.x and the complete 2.0 set.
* `v3.0.x` adds `header_protection_key`, `content_padding_addition`,
  `rekey_after_time`, `rekey_timeout`, `reject_after_time`, `keepalive_timeout`
  and `max_handshake_attempts`. `v3.0.2` is pinned; it carries the same UAPI
  surface as `v3.0.1`.

Go 1.25 is the build floor — `amneziawg-go v3.0.2`'s `go.mod` says `go 1.25.0`
and its Makefile builds with `GOTOOLCHAIN=local`, so a 1.24 image fails
outright. The image builds on `golang:1.26-alpine`, which satisfies that floor
and also builds the older tags.

### Build

```sh
./build.sh              # all four, plus the resolver
./build.sh 3.0          # just one
./build.sh dns          # just the resolver
AWG_IMAGE_PREFIX=ghcr.io/you/ ./build.sh
```

### Publishing

Not done here, and deliberately: pushing decides what the world sees under
someone's name, which is the owner's call and not a build step. The images are
built and tagged locally; these are the exact commands that publish them, to be
run by hand after `docker login -u vaiprog`:

```sh
docker login -u vaiprog                       # Docker Hub, https://hub.docker.com/u/vaiprog

docker push vaiprog/amnezia-wg-1:latest
docker push vaiprog/amnezia-wg-15:latest
docker push vaiprog/amnezia-wg-2:latest
docker push vaiprog/amnezia-wg-3:latest
docker push vaiprog/amnezia-wg-dns:latest
```

`:latest` is what `build.sh` tags. To publish an immutable tag alongside it —
worth doing, because `latest` on a VPN daemon is a moving target — tag the
`amneziawg-go` version in as well and push both:

```sh
docker tag  vaiprog/amnezia-wg-3:latest vaiprog/amnezia-wg-3:v3.0.2
docker push vaiprog/amnezia-wg-3:v3.0.2
docker tag  vaiprog/amnezia-wg-2:latest vaiprog/amnezia-wg-2:v0.2.19
docker push vaiprog/amnezia-wg-2:v0.2.19
docker tag  vaiprog/amnezia-wg-15:latest vaiprog/amnezia-wg-15:v0.2.14-beta-awg-1.5-1
docker push vaiprog/amnezia-wg-15:v0.2.14-beta-awg-1.5-1
docker tag  vaiprog/amnezia-wg-1:latest vaiprog/amnezia-wg-1:v0.2.12
docker push vaiprog/amnezia-wg-1:v0.2.12
```

## Running

```sh
docker run -d --name awg-server \
    --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 \
    -p 51820:51820/udp \
    -v $PWD/server.conf:/etc/amnezia/awg/awg0.conf:ro \
    -v awg-state:/var/lib/awg -v awg-log:/var/log/awg \
    vaiprog/amnezia-wg-3:latest
```

`NET_ADMIN` and `/dev/net/tun` are both required: `amneziawg-go` is a userspace
implementation and the entrypoint installs addresses, routes and NAT itself.
`--sysctl net.ipv4.ip_forward=1` is required on the server side only — `/proc/sys`
is read-only inside an unprivileged container, so it cannot be set from within.
The two volumes are optional but wanted on anything long-lived: they hold the
peers added with `awg-peer`, the boot counter and the event log, and without
them a restart quietly revokes every peer that was not in the mounted `.conf`.

See `docker-compose.yml` for a full example — a 3.0 pair plus the resolver.

### Config

An ordinary AmneziaWG `.conf`. Generate the obfuscation block with the sibling
tool and paste **the same block into both ends** — parameters that differ mean a
handshake that silently never completes:

```sh
awg-tool gen --version 3.0
```

```ini
[Interface]
PrivateKey = <base64>
Address = 10.99.0.1/24
ListenPort = 51820
MTU = 1280
# ... the generated H/S/J/I block, HeaderProtectionKey,
#     ContentPaddingAddition and the five timer ranges ...

[Peer]
PublicKey = <base64>
PresharedKey = <base64>
AllowedIPs = 10.99.0.2/32
```

Client side adds `Endpoint = host:port` and usually
`PersistentKeepalive`. `AllowedIPs = 0.0.0.0/0` is handled with awg-quick's
fwmark + `suppress_prefixlength` rules.

Note on MTU: AWG 3.0 appends `ContentPaddingAddition` bytes (up to ~90) to every
transport packet on top of the usual 32 bytes of WireGuard overhead. `1280` is
a safe tunnel MTU on a 1500-byte path; the usual `1420` is not.

### Environment

| variable | default | meaning |
|---|---|---|
| `AWG_IFACE` | `awg0` | interface name |
| `AWG_CONF` | `/etc/amnezia/awg/$AWG_IFACE.conf` | config path |
| `AWG_NAT` | `auto` | `auto` = MASQUERADE when the config has a `ListenPort` |
| `AWG_FWMARK` / `AWG_TABLE` | the `ListenPort` | only used for a `0.0.0.0/0` client |
| `AWG_SOCK_DIR` | `/var/run/amneziawg` | UAPI socket directory |
| `AWG_STATE_DIR` | `/var/lib/awg` | boot counter and `peers.d` |
| `AWG_EVENT_LOG` | `/var/log/awg/events.log` | operational log, see below |
| `AWG_EVENT_LOG_MAX_BYTES` | `262144` | rotate at this size; one old file kept |
| `AWG_ENDPOINT` | `SERVER_PUBLIC_IP:<port>` | what `awg-peer` writes into issued configs |
| `AWG_CLIENT_DNS` | `172.29.172.254` | resolver for issued configs |
| `AWG_CLIENT_ALLOWED` | `<tunnel>/24, <dns>/32` | `AllowedIPs` for issued configs |
| `AWG_DUMP_REQUEST` | `0` | write the outgoing UAPI request to `/tmp/uapi-set.req` — **contains the private key** |
| `LOG_LEVEL` | — | `verbose` for amneziawg-go's own logging |

`AWG_FWMARK`/`AWG_TABLE` default to the listen port rather than to a constant.
In a container each instance has its own network namespace and a constant is
harmless, but under `network_mode: host` several generations side by side would
all write rules for table `51820` and quietly steal each other's default route.

### Inspecting a running device

`awg show` cannot render the 3.0 fields (it errors on
`ContentPaddingAddition` and drops everything after it), so the image ships
`awg-uapi`:

```sh
docker exec awg-server awg-uapi get        # full get=1 dump
docker exec awg-server awg-uapi raw < req  # arbitrary request
```

### Peers

`awg-peer` adds, lists and revokes peers on a running device, over the same UAPI
socket and for the same reason — `awg set` comes from `amneziawg-tools`, which
cannot read the 3.0 keys and would rewrite the device without them.

```sh
docker exec awg-server awg-peer add laptop        # prints the client config, once
docker exec awg-server awg-peer add phone 10.99.0.7
docker exec awg-server awg-peer list
docker exec awg-server awg-peer rm laptop
```

`add` picks the lowest free address by reading the live device, so it will not
collide with a peer written into the mounted `.conf` by hand. The client's
private key is generated, printed and never stored; what is kept in
`/var/lib/awg/peers.d/<label>.peer` (mode 0600) is the label, the public key,
the address and the preshared key — the last because the server needs it again
after a restart. The entrypoint reinstalls those peers on every start, which is
why `/var/lib/awg` wants to be a volume.

The issued config copies the server's obfuscation block verbatim and points
`DNS` at the tunnel-only resolver below.

## What was verified

`./selftest.sh 3.0` reproduces this end to end: it generates one parameter set,
gives both ends the identical block, and runs a server and a client as two
containers on a throwaway `172.31.99.0/24` bridge network.

**1. The daemon accepted the 3.0 parameters.** Both ends answered the `set=1`
write with `errno=0`, and the `get=1` readback shows the daemon is actually
holding them (identical on both sides):

```
header_protection_key=b6e2e9db5d9eddb805dcdf79494473509b893b50b3ad925e3b9e190131b4710a
content_padding_addition=22-86
rekey_after_time=104-129
rekey_timeout=5-8
reject_after_time=170-186
keepalive_timeout=13-16
max_handshake_attempts=15-25
```

**2. A handshake completed.** Both sides report the same non-zero timestamp:

```
server: last_handshake_time_sec=1785255029  last_handshake_time_nsec=521151754
client: last_handshake_time_sec=1785255029  last_handshake_time_nsec=520896751
```

**3. Traffic passed.** ICMP both ways with no loss, and a 4 MiB TCP transfer
that arrived byte-identical:

```
5 packets transmitted, 5 packets received, 0% packet loss
round-trip min/avg/max = 0.691/1.169/1.374 ms      (client -> server)
round-trip min/avg/max = 0.514/1.156/1.484 ms      (server -> client)

581121cc2def8236c3014175a47c41af7fd080a6175268959c08cdaf04b9d397  /tmp/send.bin
581121cc2def8236c3014175a47c41af7fd080a6175268959c08cdaf04b9d397  /tmp/recv.bin

tx_bytes=16087  rx_bytes=4484268
```

For contrast, the same config through `amneziawg-tools` on the same running
container is the failure quoted at the top of this file.

### Every generation

`./selftest.sh` was run for all four images. 1.0, 2.0 and 3.0 pass all six
checks (both ends `errno=0`, matching non-zero handshake timestamps, ICMP both
ways, 4 MiB TCP transfer with matching sha256):

| version | daemon | set=1 | handshake | ICMP | 4 MiB TCP |
|---|---|---|---|---|---|
| 1.0 | `v0.2.12` | errno=0 | ok | 0% loss | sha256 match |
| 1.5 | `v0.2.14-beta-awg-1.5-1` | errno=0 | ok | 0% loss | sha256 match |
| 2.0 | `v0.2.19` | errno=0 | ok | 0% loss | sha256 match |
| 3.0 | `v3.0.2` | errno=0 | ok | 0% loss | sha256 match |

#### 1.5 used to fail here, and it was the generator, not the image

`awg-tool gen --version 1.5` used to emit `<rc N>` and `<rd N>` inside I1–I5,
and the 1.5 daemon refused the whole config:

```
ERROR: (awg0) IPC error -22: invalid i1: invalid tag: rc
errno=-22
```

The two generations do not share a chain parser, and the vocabularies are not
nested — they were *replaced*:

* 1.5 (`v0.2.13`, `v0.2.14-beta-awg-1.5-1`) parses I1–I5 in
  `device/awg/tag_parser.go`, whose `generatorCreator` map holds `b c t r wt`.
  `<c>` works here and only here. The same file's `uniqueTags` allows one `<c>`
  and one `<t>` per chain.
* From `v0.2.16` (AWG 2.0) `uapi.go` hands `i1`…`i5` to `newObfChain` in
  `device/obf.go`, whose `obfBuilders` map holds `b t r rc rd d ds dz` — no `c`
  at all, which is the `ErrorCode 1000` several people have reported for `<c>`.

The generator now gates the tag vocabulary on the version rather than only on
whether chains exist at all (`AwgVersion::chain_tags` in
`crates/awg-core/src/versions.rs`), so 1.5 emits `<b> <r> <c> <t>` and 2.0/3.0
emit `<b> <r> <rc> <rd> <t>`. `<c>`, which the generator never produced for any
version before, is now emitted on 1.5 where it is native. A 1.5 chain today:

```
I1 = <b 0xc000000001109361cd0754373f12b01d7551e23bd96a128033905cbf0172155147c58178bf80ce55df00b07e3868><c><t><r 118>
I5 = <b 0x0aeb7d62788451e1d0840aa1><r 500><t><c>
```

and `./selftest.sh 1.5` on the same image and the same daemon:

```
>> amneziawg-go amneziawg-go v0.2.14-beta-awg-1.5-1
>> configuration accepted by amneziawg-go (17 UAPI lines, errno=0)
awg-selftest-server set=1 -> errno=0
awg-selftest-client set=1 -> errno=0
server: last_handshake_time_sec=1785258320
client: last_handshake_time_sec=1785258320
sent   sha256: 99eb72a3e5a8fb68655c955bc0d3f9cc2d89ae43679d20965cbdfb42cc04b916
recv   sha256: 99eb72a3e5a8fb68655c955bc0d3f9cc2d89ae43679d20965cbdfb42cc04b916
AWG 1.5: all checks passed
```

## DNS with no leaks

`docker-compose.yml` puts an `unbound` container on a dedicated bridge at a
fixed `172.29.172.254`, joins the AWG container to that bridge, and issues
client configs with `DNS = 172.29.172.254` — the shape upstream AmneziaVPN uses.

The anti-leak property is not cryptographic and it is worth being precise about
what it is: `172.29.172.254` is an RFC1918 address on a bridge that nothing but
the server joins, it is never published to the host, and docker's own
`DOCKER-ISOLATION` rules drop forwarding between bridges. A client that sends
DNS there can therefore only be answered through the tunnel. If the tunnel is
down, or a query escapes it, the query does not quietly fall back to the café's
resolver — it gets no answer at all. **The leak announces itself instead of
hiding.**

`unbound` recurses from the root rather than forwarding to a public resolver:
forwarding would only move the leak, leaving the whole query stream legible to
whoever runs `1.1.1.1`. DNSSEC validation is on, with `trust-anchor-file` rather
than `auto-trust-anchor-file` because the automatic form rewrites the anchor in
place and a read-only container cannot.

The client side needs one thing beyond `DNS =`, and `awg-peer` writes it:

```ini
[Peer]
AllowedIPs = 10.99.0.0/24, 172.29.172.254/32
```

The `/32` is what routes the query into the tunnel.

### Proof, both directions

`./dnstest.sh` stands up a resolver, a tunnel and two bystander containers —
same host, same docker, same image, the only difference being that neither
bystander is a peer — and sends the identical query from all three:

```
resolver:   172.29.172.254   on [awgdnstest-resolver]
server:     172.29.172.2 172.31.98.10   on [awgdnstest-transport awgdnstest-resolver]
client:     172.31.98.11   on [awgdnstest-transport] + tunnel
bystander1: 172.31.98.2   on [awgdnstest-transport], no tunnel
bystander2: 172.16.0.2   on [bridge], no tunnel

===== DIRECTION 1 — from inside the tunnel (must answer) =====
Server:		172.29.172.254
Address:	172.29.172.254:53
Non-authoritative answer:
Name:	example.com
Address: 104.20.23.154
Name:	example.com
Address: 172.66.147.243
  PASS  tunnel client resolved example.com via 172.29.172.254

===== DIRECTION 2 — same bridge as the server, no tunnel (must fail) =====
;; connection timed out; no servers could be reached
exit status: 1
  PASS  bystander on awgdnstest-transport could NOT reach 172.29.172.254

===== DIRECTION 3 — default docker bridge, no tunnel (must fail) =====
;; connection timed out; no servers could be reached
exit status: 1
  PASS  bystander on the default bridge could NOT reach 172.29.172.254

===== DIRECTION 2b — and it is not that the bystander has no network at all =====
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max = 0.103/0.129/0.156 ms
  PASS  the same bystander can still reach the server's transport address
```

The last check is there because "the query failed" is not evidence on its own —
a container with no network at all would produce the same timeout. The same
bystander pings the server's transport address in the same second.

## Four generations on one host

`./paralleltest.sh` brings up all four server/client pairs, and only then checks
each one, so every check happens with the other three running and moving data.
Distinct listen ports (51821–51824, published on the host, where two services
genuinely cannot share one), distinct tunnel subnets, distinct interface names,
distinct transport bridges:

```
  AWG 1.0  iface=awg1   port=51821  tunnel=10.201.0.0/24  transport=172.30.11.0/24
  AWG 1.5  iface=awg15  port=51822  tunnel=10.202.0.0/24  transport=172.30.12.0/24
  AWG 2.0  iface=awg2   port=51823  tunnel=10.203.0.0/24  transport=172.30.13.0/24
  AWG 3.0  iface=awg3   port=51824  tunnel=10.204.0.0/24  transport=172.30.14.0/24

  running: 8/8
  PASS  eight containers up simultaneously
UNCONN 0 0   0.0.0.0:51821   0.0.0.0:*
UNCONN 0 0   0.0.0.0:51822   0.0.0.0:*
UNCONN 0 0   0.0.0.0:51823   0.0.0.0:*
UNCONN 0 0   0.0.0.0:51824   0.0.0.0:*
  PASS  four distinct listen ports

  AWG 1.0 server: awg1 10.201.0.1/24
  AWG 1.5 server: awg15 10.202.0.1/24
  AWG 2.0 server: awg2 10.203.0.1/24
  AWG 3.0 server: awg3 10.204.0.1/24
  PASS  four distinct interface/address pairs

  AWG 1.0: -A POSTROUTING -s 10.201.0.0/24 ! -o awg1 -j MASQUERADE
  AWG 1.5: -A POSTROUTING -s 10.202.0.0/24 ! -o awg15 -j MASQUERADE
  AWG 2.0: -A POSTROUTING -s 10.203.0.0/24 ! -o awg2 -j MASQUERADE
  AWG 3.0: -A POSTROUTING -s 10.204.0.0/24 ! -o awg3 -j MASQUERADE

  PASS  AWG 1.0 handshake        PASS  AWG 1.0 moved 4 MiB intact
  PASS  AWG 1.5 handshake        PASS  AWG 1.5 moved 4 MiB intact
  PASS  AWG 2.0 handshake        PASS  AWG 2.0 moved 4 MiB intact
  PASS  AWG 3.0 handshake        PASS  AWG 3.0 moved 4 MiB intact

  AWG 1.0: tx_bytes=9546  rx_bytes=4482196
  AWG 1.5: tx_bytes=68258 rx_bytes=4482116
  AWG 2.0: tx_bytes=16473 rx_bytes=4482212
  AWG 3.0: tx_bytes=26114 rx_bytes=4482697
  PASS  nothing died while the others worked
```

The four 4 MiB transfers are started together rather than one after another —
four tunnels moving data in the same seconds, through one kernel's tun driver.

Two things were changed to make this hold rather than happen to work:

* the MASQUERADE rule is now `! -o $IFACE` instead of `-o <default route>`. A
  server with a side network — the DNS bridge — has more than one way out, and
  pinning NAT to the default route silently drops tunnel traffic aimed at any of
  the others.
* `AWG_FWMARK`/`AWG_TABLE` default to the listen port instead of `51820`, so
  four full-tunnel servers under `network_mode: host` cannot fight over one
  routing table.

## The event log

The entrypoint and `awg-peer` write a line per operational event to
`/var/log/awg/events.log`, and the same line to stderr so `docker logs` tells
the same story:

```
2026-07-28T17:04:19Z iface=awg0 event=start boot=1 daemon=v3.0.2 protocol=3.0
2026-07-28T17:04:19Z iface=awg0 event=config-applied errno=0 uapi_lines=30 peers=1 port=51820
2026-07-28T17:04:19Z iface=awg0 event=peer-add peer=xIVbWBSO0gGUyby7gIDwHko6ry+wG6GSXOfmUUgb+yc= source=config
2026-07-28T17:04:19Z iface=awg0 event=iface-up addr=10.96.0.1/24 mtu=1280 port=51820 nat=1 full_tunnel=0
2026-07-28T17:04:24Z iface=awg0 event=peer-add peer=juGrfLM080knRTOCY1B5+XBkzYGLrWXZFNMq22gGaB8= label=laptop address=10.96.0.4/32
2026-07-28T17:04:24Z iface=awg0 event=client-config-issued peer=juGrfLM080knRTOCY1B5+XBkzYGLrWXZFNMq22gGaB8= label=laptop endpoint=vpn.example.com:51820 dns=172.29.172.254
2026-07-28T17:04:24Z iface=awg0 event=peer-remove peer=juGrfLM080knRTOCY1B5+XBkzYGLrWXZFNMq22gGaB8= label=laptop
2026-07-28T17:04:24Z iface=awg0 event=stop
2026-07-28T17:04:24Z iface=awg0 event=start boot=2 daemon=v3.0.2 protocol=3.0
2026-07-28T17:04:24Z iface=awg0 event=peer-add peer=juGrfLM080knRTOCY1B5+XBkzYGLrWXZFNMq22gGaB8= label=laptop address=10.96.0.4/32 source=peers.d
```

| event | when |
|---|---|
| `start` | container start; `boot=N` with `N>1` is a restart |
| `config-applied` | the daemon accepted `set=1` — line count and peer count only |
| `config-rejected` | it did not, with the errno |
| `peer-add` | a peer was installed, from the `.conf`, from `peers.d` or from `awg-peer` |
| `peer-remove` | a peer was revoked |
| `client-config-issued` | a client config was generated and handed out |
| `iface-up` | address, MTU, port, whether NAT and full-tunnel are on |
| `stop` | the interface is being torn down |

**What it deliberately does not contain:** private keys, preshared keys,
passphrases, and config bodies of any kind. A peer is named by its *public* key
and by the operator's label, both of which are already public. `config-applied`
records how many UAPI lines were written, never the lines — the request carries
the interface private key. `AWG_DUMP_REQUEST=1` still exists for debugging and
still writes that request in clear to `/tmp`, which is why it is off by default
and says so every time it runs.

The reasoning is simple: a log gets copied, tailed, shipped to a collector and
read by whoever is debugging today. A key in it becomes an unbounded number of
copies of that key, and nothing above needs one to be useful.

**It is still sensitive, and it stays on the node.** The log is a dated list of
who has access to this server, who used to, and when each of them was given a
config. That is exactly the thing an adversary wants and exactly the thing a
subpoena asks for. Nothing here ships it anywhere: no syslog, no remote target,
no metrics endpoint. It is mode 0600 in a volume on the host, and the decision
to move it off the node is one an operator has to make on purpose.

Size is bounded by construction: the file rotates to `events.log.1` at
`AWG_EVENT_LOG_MAX_BYTES` (256 KiB by default) and exactly one old file is kept,
so a node that flaps every ten seconds for a year still costs the same half
megabyte. There is no timer — the size is checked at write time, which is the
only moment the file can have grown.
