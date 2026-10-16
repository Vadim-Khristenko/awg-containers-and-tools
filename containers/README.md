# AmneziaWG containers: 1.0, 1.5, 2.0, 3.0, 3.1

Self-hosted AmneziaWG server/client images, a tunnel-only resolver and the
tunnel's own pages. Unofficial: a community build by Vadim Khristenko
(VAI_PROG), not affiliated with, endorsed by or supported by AmneziaVPN.
Problems with these images belong in [this project's tracker](https://github.com/Vadim-Khristenko/awg-containers-and-tools),
not in theirs.

| file | what it does |
|---|---|
| `Dockerfile` / `build.sh` | the five protocol images, one build arg apart |
| `entrypoint.sh` | `.conf` to UAPI, addresses, routes, NAT, event log, node facts |
| `awg-peer` | add, list and revoke peers, issue client configs, write peer names |
| `awg-uapi` | raw `get=1` and arbitrary requests against the socket |
| `awg-log.sh` | the event log, shared by the scripts above |
| `awg-health` | health check: interface up, UAPI answering |
| `awg-dump.sh` | the diagnostic bundle, made for pasting |
| `awg-under` | "am I under the VPN?" from inside a client node |
| `awg-leak` | DNS, IPv6 and routing leak check from inside a client node |
| `awg-mtu` | the largest packet the tunnel really carries |
| `awg-watch` | peers that go quiet or come back, logged |
| `Dockerfile.dns` / `unbound.conf` / `entrypoint-dns.sh` | the resolver, `vaiprog/amnezia-wg-dns` |
| `awg-dns-list` | the resolver's managed lists and state, for `awg-tool dns` |
| `dns-chain/` | `awg-dns-chain`, the resolver chain, built into the resolver image |
| `Dockerfile.status` / `status-www/` | the pages: amiunder, dns, speed, mtu, leak and node.vpn |
| `selftest.sh` | one generation end to end: `errno=0`, handshake, traffic |
| `utiltest.sh` | the in-image checks on their own, including where they must say no |
| `dnstest.sh` | the resolver, its pages and the chain, from inside and outside the tunnel |
| `paralleltest.sh` | the generations at once on one host |
| `docker-compose.yml` | a server and client pair, the resolver and the pages |

## Why these exist

The entrypoint translates the `.conf` into a UAPI `set=1` request and writes it to the daemon's socket. One request format covers every generation, 1.0 through 3.1, and it does not depend on what the `amneziawg-tools` in the image happen to parse in a given release: `amneziawg-tools` knew only the 2.0 keys for a long time, and the 3.x keys arrived in it much later than the daemon:

```
$ awg setconf awg0 server.conf       # with older tools
Line unrecognized: `HeaderProtectionKey=...'
Configuration parsing error
```

`awg` is still shipped in the image for key material (`genkey`, `pubkey`, `genpsk`) and for `awg show` while debugging. It is deliberately not what brings the interface up.

## Images

One `Dockerfile`, one build arg. The only thing that differs between the
protocol images is the `amneziawg-go` tag; the entrypoint, the base and the
tools build are identical, so five copies of the same file would only be five
things to keep in sync.

| image                     | AWG | size   | `amneziawg-go` | what that tag adds                                        |
|---------------------------|-----|--------|----------------|-----------------------------------------------------------|
| `vaiprog/amnezia-wg-1`    | 1.0 | 33.3 MB | `v0.2.12`      | Jc/Jmin/Jmax, S1/S2, fixed H1-H4                          |
| `vaiprog/amnezia-wg-15`   | 1.5 | 34.1 MB | `v0.2.14-beta-awg-1.5-1` | + I1-I5 special junk (`<b> <c> <t> <r> <wt>` only), `Itime` |
| `vaiprog/amnezia-wg-2`    | 2.0 | 33.4 MB | `v0.2.19`      | + S3/S4, H1-H4 as ranges, `<rc> <rd> <d> <ds> <dz>` chain tags |
| `vaiprog/amnezia-wg-3`    | 3.0 | 33.4 MB | `v3.0.20260805` | + HeaderProtectionKey, ContentPaddingAddition, timer ranges |
| `vaiprog/amnezia-wg-31`   | 3.1 | 33.4 MB | `v3.1.20260828` | + RandomTrailers and DisableCookies |
| `vaiprog/amnezia-wg-dns`  |     | ~20 MB |                | unbound and awg-dns-chain; see [DNS](#dns) |
| `vaiprog/amnezia-wg-status` |   | 30.1 MB |               | the tunnel's own pages; see [The pages](#the-pages) |

The major number is spelled without its dot (`amnezia-wg-15`, not
`amnezia-wg-1.5`) because a Docker repository path segment containing a dot
reads as a registry hostname.

### Metadata

Every image carries the full OCI set, so `docker inspect` answers the questions
an operator actually asks without anyone having to remember what a tag meant:

```
$ docker inspect vaiprog/amnezia-wg-15 --format '{{json .Config.Labels}}' | jq
{
  "org.opencontainers.image.title":         "AmneziaWG 1.5 node (unofficial)",
  "org.opencontainers.image.authors":       "Vadim Khristenko (VAI_PROG)",
  "org.opencontainers.image.licenses":      "MIT",
  "org.opencontainers.image.source":        "https://github.com/Vadim-Khristenko/awg-containers-and-tools",
  "org.opencontainers.image.version":       "v0.2.14-beta-awg-1.5-1",
  "org.opencontainers.image.created":       "2026-07-28T16:54:47Z",
  "org.opencontainers.image.base.name":     "docker.io/library/alpine:3.24",
  "space.vai-rice.awg.protocol":            "1.5",
  "space.vai-rice.awg.go-version":          "v0.2.14-beta-awg-1.5-1",
  "space.vai-rice.awg.tools-version":       "v3.1.20260812",
  ...
}
```

`image.version` is the `amneziawg-go` tag rather than the protocol generation:
it is the only thing that actually differs between the images, and it is what
someone comparing a running container against an advisory needs. The protocol
generation is `space.vai-rice.awg.protocol`, which is also how `awg-tool`
recognises a node whose image was renamed, and the container exports it as
`$AWG_PROTOCOL` so the event log can name it.

`image.created` comes from `build.sh`, which stamps one timestamp across the
whole run. The `Dockerfile` default is the epoch, not `now`: a Dockerfile that
reads the clock produces an image nobody can reproduce, and an obvious zero is
better than a plausible lie. Set `SOURCE_DATE_EPOCH` to pin it.

Tags were picked by diffing the `case "..."` list in `device/uapi.go` at every
tag, not by reading release notes:

* `v0.2.12` is the last tag where `h1` is `strconv.ParseUint` and there is no
  `s3`/`s4` and no `i1`-`i5`: exactly the 1.0 key set.
* `v0.2.13` introduces `i1`-`i5` plus `itime`, still with a fixed `h1`;
  `v0.2.14-beta-awg-1.5-1` is the last tag in that line (upstream labels these
  `-beta-awg-1.5-*`, which is as explicit as it gets).
* `v0.2.15` drops `itime` and moves to `awg.ParseMagicHeader`; by `v0.2.16` the
  headers are `newMagicHeader`, which accepts `lo-hi`. `v0.2.19` is the last
  0.2.x and the complete 2.0 set.
* `v3.0.x` adds `header_protection_key`, `content_padding_addition`,
  `rekey_after_time`, `rekey_timeout`, `reject_after_time`, `keepalive_timeout`
  and `max_handshake_attempts`. The newest 3.0 tag is pinned, `v3.0.20260805`,
  which carries the keepalive fix over `v3.0.3`, so the 3.0 image tracks
  patches without ever picking up a 3.1 daemon.
* `v3.1.x` adds `random_trailers` and `disable_cookies`. Pinned at
  `v3.1.20260828`, the tag that fixes RandomTrailers panicking on a cookie
  reply and DisableCookies not disabling the whole underload.

The tools the image builds come from `amneziawg-tools` and are pinned at
`v3.1.20260812`, which knows the 3.x keys; they are used for key material and
for reading state, never for bringing the interface up.

Go 1.25 is the build floor: the `v3.0.x` `go.mod` says `go 1.25.0` and the
Makefile builds with `GOTOOLCHAIN=local`, so a 1.24 image fails outright. The
image builds on `golang:1.26-alpine`, which satisfies that floor and also
builds the older tags.

### Build

```sh
./build.sh              # all five, plus the resolver and the pages
./build.sh 3.1          # just one
./build.sh dns status   # just the resolver and the pages
AWG_IMAGE_PREFIX=ghcr.io/you/ ./build.sh
```

The resolver's build has a stage of its own that compiles `dns-chain/` with
`rust:1-alpine`; it has no dependencies, so it takes seconds.

### Publishing

Not done here, and deliberately: pushing decides what the world sees under
someone's name, which is the owner's call and not a build step. The release
workflow publishes on a tag; by hand, after `docker login -u vaiprog`:

```sh
for i in 1 15 2 3 31 dns status; do docker push vaiprog/amnezia-wg-$i:latest; done
```

`:latest` is what `build.sh` tags. An immutable tag alongside it is worth
having, because `latest` on a VPN daemon is a moving target:

```sh
docker tag  vaiprog/amnezia-wg-31:latest vaiprog/amnezia-wg-31:v3.1.20260828
docker push vaiprog/amnezia-wg-31:v3.1.20260828
```

## Running

```sh
docker run -d --name awg-server \
    --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 \
    -p 51820:51820/udp \
    -v $PWD/server.conf:/etc/amnezia/awg/awg0.conf:ro \
    -v awg-state:/var/lib/awg -v awg-log:/var/log/awg \
    vaiprog/amnezia-wg-31:latest
```

`NET_ADMIN` and `/dev/net/tun` are both required: `amneziawg-go` is a userspace
implementation and the entrypoint installs addresses, routes and NAT itself.
`--sysctl net.ipv4.ip_forward=1` is required on the server side only:
`/proc/sys` is read-only inside an unprivileged container, so it cannot be set
from within. The two volumes are optional but wanted on anything long-lived:
they hold the peers added with `awg-peer`, the boot counter and the event log,
and without them a restart quietly revokes every peer that was not in the
mounted `.conf`.

See `docker-compose.yml` for a full example: a server and client pair, the
resolver and the pages, with the volumes they share.

### Config

An ordinary AmneziaWG `.conf`. Generate the obfuscation block with the sibling
tool and paste **the same block into both ends**: parameters that differ mean a
handshake that silently never completes.

```sh
awg-tool gen --version 3.1
```

```ini
[Interface]
PrivateKey = <base64>
Address = 10.99.0.1/24
ListenPort = 51820
MTU = 1280
# ... the generated H/S/J/I block, HeaderProtectionKey,
#     ContentPaddingAddition, the timer ranges and the 3.1 switches ...

[Peer]
PublicKey = <base64>
PresharedKey = <base64>
AllowedIPs = 10.99.0.2/32
```

The client side adds `Endpoint = host:port` and usually `PersistentKeepalive`.
`AllowedIPs = 0.0.0.0/0` is handled with awg-quick's fwmark and
`suppress_prefixlength` rules.

On MTU: AWG 3.x appends `ContentPaddingAddition` bytes (up to ~90) to every
transport packet on top of the usual 32 bytes of WireGuard overhead, and 3.1's
`RandomTrailers` adds a random tail on top of that. `1280` is a safe tunnel MTU
on a 1500-byte path, and it is what the 3.1 preset writes; the usual `1420` is
not. `awg-mtu` measures what a given path really carries.

To give a running node new obfuscation, `awg-tool rotate` rewrites the block in
the mounted file, keeps a backup next to it, restarts the container and rolls
back if it does not come up.

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
| `AWG_SERVICES_NET` | the resolver's `/24` | the resolver and the pages, routed into the tunnel by issued configs |
| `AWG_CLIENT_ALLOWED` | `<tunnel>/24, <services>/24` | `AllowedIPs` for issued configs |
| `AWG_NAMES_FILE` | `/var/lib/awg-names/names.hosts` | peer names for the resolver, and the node's facts beside it |
| `AWG_WATCH` | `on` | `off` leaves `awg-watch` out |
| `AWG_WATCH_QUIET` | `600` | seconds without a handshake before a peer counts as quiet |
| `AWG_WATCH_INTERVAL` | `60` | seconds between looks |
| `AWG_DUMP_REQUEST` | `0` | write the outgoing UAPI request to `/tmp/uapi-set.req`: **contains the private key** |
| `LOG_LEVEL` | | `verbose` for amneziawg-go's own logging |

`AWG_FWMARK`/`AWG_TABLE` default to the listen port rather than to a constant.
In a container each instance has its own network namespace and a constant is
harmless, but under `network_mode: host` several generations side by side would
all write rules for table `51820` and quietly steal each other's default route.

### Inspecting a running device

`awg show` cannot render the 3.x fields (it errors on
`ContentPaddingAddition` and drops everything after it), so the image ships
`awg-uapi`:

```sh
docker exec awg-server awg-uapi get        # full get=1 dump
docker exec awg-server awg-uapi raw < req  # arbitrary request
```

### Peers

`awg-peer` adds, lists and revokes peers on a running device, over the same UAPI
socket and for the same reason: `awg set` comes from `amneziawg-tools`, which
could not read the 3.x keys and would rewrite the device without them.

```sh
docker exec awg-server awg-peer add laptop        # prints the client config, once
docker exec awg-server awg-peer add phone 10.99.0.7
docker exec awg-server awg-peer list
docker exec awg-server awg-peer rm laptop
```

`awg-tool peer add|list|rm` runs the same thing on whichever node `status`
picks, here or over SSH.

`add` picks the lowest free address by reading the live device, so it will not
collide with a peer written into the mounted `.conf` by hand. The client's
private key is generated, printed and never stored; what is kept in
`/var/lib/awg/peers.d/<label>.peer` (mode 0600) is the label, the public key,
the address and the preshared key, the last because the server needs it again
after a restart. The entrypoint reinstalls those peers on every start, which is
why `/var/lib/awg` wants to be a volume.

The issued config copies the server's obfuscation block verbatim (the 3.1
switches included), points `DNS` at the tunnel-only resolver below and routes
the services network into the tunnel. With a names volume mounted, every peer
also answers as `<label>.peer.vpn`, and its address reads back as that name.

### When it does not work

```sh
docker exec awg-server awg-health      # exit 0 when the node can carry traffic
docker exec awg-client awg-under       # under the VPN, and how it knows
docker exec awg-client awg-leak        # DNS, IPv6 and routing leaks
docker exec awg-client awg-mtu         # the largest packet through the tunnel
docker exec awg-server awg-watch       # active, quiet or never connected
docker exec awg-server awg-dump        # the whole picture
```

`awg-under` answers from more than one side: the tunnel resolver answers the
page's name, the node's own resolver does or does not (which says where its
queries go), the page answers and with which address, and where an IPv6
default route leaves. `--json` for scripts.

`awg-leak` checks which resolver the node uses, that it answers, that it is the
tunnel's own (it asks `resolver.vpn`, which only the real one answers with its
own address; a network that answers DNS sent to any address is otherwise
indistinguishable), whether Firefox's DoH canary is switched off, and where the
IPv4 and IPv6 default routes go. Exit 1 on a leak.

`awg-mtu` pings through the tunnel and searches for the largest size that is
answered, two tries a size. Below the interface MTU it says what to put in the
config, in steps of 8. `AWG_MTU_MAX` probes past the interface, raising it for
the duration.

`awg-watch` reads the UAPI socket; with `--loop`, which the entrypoint runs,
every change becomes an event: `peer-quiet`, `peer-back`,
`peer-first-handshake`.

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

`./selftest.sh` was run for every image; each passes all six checks (both ends
`errno=0`, matching non-zero handshake timestamps, ICMP both ways, 4 MiB TCP
transfer with matching sha256):

| version | daemon | set=1 | handshake | ICMP | 4 MiB TCP |
|---|---|---|---|---|---|
| 1.0 | `v0.2.12` | errno=0 | ok | 0% loss | sha256 match |
| 1.5 | `v0.2.14-beta-awg-1.5-1` | errno=0 | ok | 0% loss | sha256 match |
| 2.0 | `v0.2.19` | errno=0 | ok | 0% loss | sha256 match |
| 3.0 | `v3.0.2` | errno=0 | ok | 0% loss | sha256 match |
| 3.1 | `v3.1.20260828` | errno=0 | ok | 0% loss | sha256 match |

The 3.1 row, with `dnstest.sh` and `utiltest.sh`, passes on Docker Desktop and
on a Linux host alike.

#### 1.5 used to fail here, and it was the generator, not the image

`awg-tool gen --version 1.5` used to emit `<rc N>` and `<rd N>` inside I1-I5,
and the 1.5 daemon refused the whole config:

```
ERROR: (awg0) IPC error -22: invalid i1: invalid tag: rc
errno=-22
```

The two generations do not share a chain parser, and the vocabularies are not
nested; they were *replaced*:

* 1.5 (`v0.2.13`, `v0.2.14-beta-awg-1.5-1`) parses I1-I5 in
  `device/awg/tag_parser.go`, whose `generatorCreator` map holds `b c t r wt`.
  `<c>` works here and only here among the amneziawg-go generations. The same
  file's `uniqueTags` allows one `<c>` and one `<t>` per chain.
* From `v0.2.16` (AWG 2.0) `uapi.go` hands `i1` to `i5` to `newObfChain` in
  `device/obf.go`, whose `obfBuilders` map holds `b t r rc rd d ds dz`, with no
  `c` at all, which is the `ErrorCode 1000` several people have reported for
  `<c>`.

The generator gates the tag vocabulary on the version and on the engines at
both ends of the tunnel (`crates/awg-core/src/engines.rs`), so 1.5 emits
`<b> <r> <c> <t>` and 2.0 and later emit `<b> <r> <rc> <rd> <t>` on these
images. A 1.5 chain:

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

## DNS

`docker-compose.yml` puts the resolver on a dedicated bridge at a fixed
`172.29.172.254`, joins the server container to that bridge, and `awg-peer`
issues client configs with `DNS = 172.29.172.254`, the shape upstream
AmneziaVPN uses.

The anti-leak property is not cryptographic and it is worth being precise about
what it is: `172.29.172.254` is an RFC1918 address on a bridge that nothing but
the server joins, it is never published to the host, and docker's own
isolation rules drop forwarding between bridges. A client that sends DNS there
can therefore only be answered through the tunnel. If the tunnel is down, or a
query escapes it, the query does not quietly fall back to the café's resolver:
it gets no answer at all. **The leak announces itself instead of hiding.**

The client side needs one thing beyond `DNS =`, and `awg-peer` writes it:

```ini
[Peer]
AllowedIPs = 10.99.0.0/24, 172.29.172.0/24
```

The `/24` is what routes the query (and the pages beside the resolver) into the
tunnel.

### How it resolves

| `AWG_DNS_MODE` | |
|---|---|
| `auto` (default) | asks two root servers once at start: recursion when they answer, DoT forwarding when this network drops plain DNS on the way out |
| `recursive` | from the root, so the query stream is no single provider's to read |
| `forward` | over DoT to `AWG_DNS_FORWARD`, by default Cloudflare and Quad9 (`ip@853#name` each) |

DNSSEC validation is on, with `trust-anchor-file` rather than
`auto-trust-anchor-file`, because the automatic form rewrites the anchor in
place and a read-only container cannot.

The resolver runs as its own user with a read-only root filesystem. The rest of
its hardening: `deny-any`, minimal responses, rate limiting per zone, stale
answers for an hour while an authority is unreachable, no ECS, no query
logging, and the control interface on loopback only.

### What you configure

Everything lives in one directory, mounted read-only at `/etc/awg-dns`, all of
it optional:

```
blocklists.d/*.txt     names to block: plain, hosts-file or adblock `||name^` lines
blocklists.url         list URLs, one per line, refreshed every AWG_DNS_REFRESH seconds
allowlist.d/*.txt      names never blocked, whatever a list says
records.d/*.records    your own records: `name TYPE value` (A AAAA CNAME TXT MX SRV PTR)
vpn.d/*.records        records in the tunnel's own .vpn zone
forward.d/*.conf       zones sent to resolvers you name: `zone server [server...]`
chain.conf             resolvers asked in order, `default` being this one's own path
```

A blocked name, and everything beneath it, answers NXDOMAIN from the resolver
itself; an allowed name beneath a blocked parent resolves. The pre-0.5 path,
`/etc/unbound/blacklist.d`, is still read.

The resolver watches the directory, its own volume and the peer names, and
reloads within seconds of a change, without a restart. Every generated config
is checked with `unbound-checkconf` before it is used: a bad line keeps the last
good config, and at first start falls back to the built-in `.vpn` zone alone,
so a mounted file cannot take the resolver down.

`awg-tool dns block|unblock|allow|unallow NAME` writes to the resolver's own
volume at `/var/lib/awg-dns`, since the operator directory is usually mounted
read-only; `awg-tool dns` shows the state and `awg-tool dns query NAME` asks it.

| variable | default | meaning |
|---|---|---|
| `AWG_DNS_MODE` | `auto` | `auto`, `recursive` or `forward` |
| `AWG_DNS_FORWARD` | Cloudflare, Quad9 | DoT upstreams for forward mode |
| `AWG_DNS_BLOCKLISTS` | | more list URLs, space separated |
| `AWG_DNS_REFRESH` | `86400` | seconds between list refreshes, `0` = once |
| `AWG_DNS_IPV6` | `0` | `1` to listen and resolve over IPv6 as well |
| `AWG_DNS_CANARY` | `firefox` | encrypted-DNS bypasses to switch off: `firefox`, `icloud`, both, or `none` |
| `AWG_DNS_ZONES` | | more forwarded zones: `zone=server,server ...` |
| `AWG_DNS_CHAIN` | | the chain when there is no `chain.conf` |
| `AWG_DNS_CHAIN_SINKHOLES` | | more addresses that mean "blocked" (ip or cidr) |
| `AWG_DNS_CHAIN_KEEP` | | reasons to accept rather than move on: `nxdomain servfail refused sinkhole` |
| `AWG_DNS_CHAIN_TIMEOUT_MS` | `1500` | how long each resolver in the chain gets |
| `AWG_DNS_NAMES` | `/var/lib/awg-names/names.hosts` | the node's peer names |
| `AWG_DNS_PUBLIC` | `/var/lib/awg-dns-public` | where the page's counters go, skipped if absent |

The canaries: Firefox keeps to the network's resolver when
`use-application-dns.net` does not exist there, and iCloud Private Relay stays
off when `mask.icloud.com` does not. Either would otherwise skip this resolver
and its lists. They join the blocklist, so an allowlist entry brings either
back.

### Forwarded zones

```
# forward.d/zones.conf
geek.          185.121.177.177 168.235.111.72
home.arpa.     192.168.1.1
168.192.in-addr.arpa.   192.168.1.1
corp.example.  10.0.0.53@5353
secure.test.   9.9.9.9@853#dns.quad9.net
```

Each zone goes to its own resolvers, over DoT when a server carries `#name`.
Validation stands aside for them, since nothing signs another root's TLDs under
the ICANN one, and a zone unbound answers itself by default (`test.`,
`home.arpa.`, the private reverse zones of RFC 6303) is let through, so a home
network's names and reverse lookups can come from its router. `.vpn` belongs to
the tunnel and cannot be forwarded.

### The chain

```
# chain.conf
default
185.121.177.177     # OpenNIC
```

With a chain, unbound keeps the `.vpn` zone, the lists, your records and the
cache, and forwards everything else to `awg-dns-chain` on `127.0.0.1:5300`,
which asks each resolver in order and passes an answer back unless it is:

| answer | reason | |
|---|---|---|
| nothing, in time | `timeout` | always moves on |
| SERVFAIL | `servfail` | moves on unless kept |
| REFUSED | `refused` | moves on unless kept |
| NXDOMAIN | `nxdomain` | moves on unless kept |
| only `0.0.0.0`, `127.0.0.0/8`, `::`, `::1` | `sinkhole` | moves on unless kept |

`default` is a second unbound inside the container on `127.0.0.1:5301`, doing
what the resolver does without a chain: recursion or DoT, with DNSSEC. So the
chain above resolves every name as before and asks OpenNIC only for what the
real root says does not exist. Put a filtering resolver first and the next one
answers what it blocks.

The details that make it dependable:

- After 400 ms of silence the next resolver is asked alongside the first, and
  the first keeps priority for twice that: a slow but right answer still wins,
  a dead resolver costs 0.8 s instead of the whole timeout.
- An answer counts only when it came from the address asked, with the query's
  id and its own question; a forged one is waited past as if it never arrived.
- Truncated answers are fetched over TCP. When nothing acceptable came back
  anywhere, the first answer in list order is returned, so a name that exists
  nowhere still reads as NXDOMAIN, and SERVFAIL only when nobody answered.
- The chain starts, changes and stops with `chain.conf`, without a restart;
  whatever of it stops is started again within seconds. When the chain or the
  zones change the cache is dropped, since an NXDOMAIN cached from the real
  root would otherwise outlive the chain that can answer it.
- With a chain the front unbound only iterates: answers from another root
  cannot pass a validator that trusts only the ICANN one. The default path is
  still validated, by the inner resolver; answers from further down are not.

`awg-tool dns` shows each resolver with how often it answered, passed a query on
and stayed silent.

### The pages

The status container answers every page name in the `.vpn` zone and draws the
page for the name it was opened by:

| | reads | |
|---|---|---|
| `amiunder.vpn` | `/cgi-bin/whoami` | the page opening at all is the answer |
| `dns.vpn` | `/state/dns.txt`, `/cgi-bin/lookup` | the resolver's mode and counters, the chain's counts, a lookup box |
| `speed.vpn` | `/speedtest.bin`, `/cgi-bin/sink` | latency, download and upload |
| `mtu.vpn` | `/mtu/*.bin`, `/cgi-bin/sink` | 1 KB to 1 MB both ways, under deadlines that cover the whole body |
| `leak.vpn` | `<nonce>.leak.vpn` | a name that never existed, which only the tunnel resolver can answer |
| `node.vpn` | `/cgi-bin/node` | protocol, daemon, MTU, uptime, the number of named peers |

Opened by address, a fragment picks the page (`http://172.29.172.253/#dns`).
`/state` is the resolver's `awg-dns-public` volume, mounted read-only; it holds
counts and counters, never a name anybody asked for and never a name on a list.
`/cgi-bin/node` reads `node.txt` from the names volume and gives only the
number of names in it. The page image creates neither mount point, on purpose:
docker copies an image directory's owner onto an empty volume, and the page
starting before the resolver had written anything would hand the resolver's
volume to root.

### Proof, both directions

`./dnstest.sh` stands up a resolver, the pages, a tunnel and two bystander
containers (same host, same docker, same image, the only difference being that
neither bystander is a peer) and sends the identical query from all three:

```
resolver:   172.29.172.254   on [awgdnstest-resolver]
server:     172.29.172.2 172.31.98.10   on [awgdnstest-transport awgdnstest-resolver]
client:     172.31.98.11   on [awgdnstest-transport] + tunnel
bystander1: 172.31.98.2   on [awgdnstest-transport], no tunnel
bystander2: 172.16.0.2   on [bridge], no tunnel

===== DIRECTION 1: from inside the tunnel (must answer) =====
Name:	example.com
Address: 104.20.23.154
  PASS  tunnel client resolved example.com via 172.29.172.254

===== DIRECTION 2: same bridge as the server, no tunnel (must fail) =====
;; connection timed out; no servers could be reached
  PASS  bystander on awgdnstest-transport could NOT reach 172.29.172.254

===== DIRECTION 3: default docker bridge, no tunnel (must fail) =====
;; connection timed out; no servers could be reached
  PASS  bystander on the default bridge could NOT reach 172.29.172.254

===== DIRECTION 2b: and it is not that the bystander has no network at all =====
  PASS  the same bystander can still reach the server's transport address
```

The last check is there because "the query failed" is not evidence on its own:
a container with no network at all would produce the same timeout.

The rest of the run checks the lists (a blocked zone, a name beneath it, an
allowed name through it, a name blocked and unblocked through `awg-dns-list`
without a restart), your records, the `.vpn` zone, a peer answering as
`<label>.peer.vpn` without a restart, the pages and their CGIs, `awg-under`,
`awg-leak`, `awg-mtu` against an artificial blackhole, `awg-watch` against a
client that goes away and comes back, and the chain against a second resolver
standing in for another root: switched on, reordered and off while the
resolver runs.

## Generations on one host

`./paralleltest.sh` brings up server/client pairs for several generations, and
only then checks each one, so every check happens with the others running and
moving data. Distinct listen ports (published on the host, where two services
genuinely cannot share one), distinct tunnel subnets, distinct interface names,
distinct transport bridges:

```
  AWG 1.0  iface=awg1   port=51821  tunnel=10.201.0.0/24  transport=172.30.11.0/24
  AWG 1.5  iface=awg15  port=51822  tunnel=10.202.0.0/24  transport=172.30.12.0/24
  AWG 2.0  iface=awg2   port=51823  tunnel=10.203.0.0/24  transport=172.30.13.0/24
  AWG 3.0  iface=awg3   port=51824  tunnel=10.204.0.0/24  transport=172.30.14.0/24

  PASS  eight containers up simultaneously
  PASS  four distinct listen ports
  PASS  four distinct interface/address pairs
  PASS  AWG 1.0 handshake        PASS  AWG 1.0 moved 4 MiB intact
  PASS  AWG 1.5 handshake        PASS  AWG 1.5 moved 4 MiB intact
  PASS  AWG 2.0 handshake        PASS  AWG 2.0 moved 4 MiB intact
  PASS  AWG 3.0 handshake        PASS  AWG 3.0 moved 4 MiB intact
  PASS  nothing died while the others worked
```

The 4 MiB transfers are started together rather than one after another: four
tunnels moving data in the same seconds, through one kernel's tun driver.

Two things were changed to make this hold rather than happen to work:

* the MASQUERADE rule is `! -o $IFACE` instead of `-o <default route>`. A
  server with a side network (the DNS bridge) has more than one way out, and
  pinning NAT to the default route silently drops tunnel traffic aimed at any
  of the others.
* `AWG_FWMARK`/`AWG_TABLE` default to the listen port instead of `51820`, so
  several full-tunnel servers under `network_mode: host` cannot fight over one
  routing table.

## The event log

The entrypoint, `awg-peer` and `awg-watch` write a line per operational event
to `/var/log/awg/events.log`, and the same line to stderr so `docker logs`
tells the same story:

```
2026-07-28T17:04:19Z iface=awg0 event=start boot=1 daemon=v3.0.2 protocol=3.0
2026-07-28T17:04:19Z iface=awg0 event=config-applied errno=0 uapi_lines=30 peers=1 port=51820
2026-07-28T17:04:19Z iface=awg0 event=peer-add peer=xIVbWBSO0gGUyby7gIDwHko6ry+wG6GSXOfmUUgb+yc= source=config
2026-07-28T17:04:19Z iface=awg0 event=iface-up addr=10.96.0.1/24 mtu=1280 port=51820 nat=1 full_tunnel=0
2026-07-28T17:04:24Z iface=awg0 event=peer-add peer=juGrfLM080knRTOCY1B5+XBkzYGLrWXZFNMq22gGaB8= label=laptop address=10.96.0.4/32
2026-07-28T17:04:24Z iface=awg0 event=client-config-issued peer=juGrfLM080knRTOCY1B5+XBkzYGLrWXZFNMq22gGaB8= label=laptop endpoint=vpn.example.com:51820 dns=172.29.172.254
2026-07-28T17:14:31Z iface=awg0 event=peer-quiet peer=juGrfLM080knRTOCY1B5+XBkzYGLrWXZFNMq22gGaB8= label=laptop last_handshake=2026-07-28T17:04:30Z
2026-07-28T17:20:02Z iface=awg0 event=peer-back peer=juGrfLM080knRTOCY1B5+XBkzYGLrWXZFNMq22gGaB8= label=laptop
2026-07-28T17:24:24Z iface=awg0 event=peer-remove peer=juGrfLM080knRTOCY1B5+XBkzYGLrWXZFNMq22gGaB8= label=laptop
2026-07-28T17:24:24Z iface=awg0 event=stop
```

| event | when |
|---|---|
| `start` | container start; `boot=N` with `N>1` is a restart |
| `config-applied` | the daemon accepted `set=1`: line count and peer count only |
| `config-rejected` | it did not, with the errno |
| `peer-add` | a peer was installed, from the `.conf`, from `peers.d` or from `awg-peer` |
| `peer-remove` | a peer was revoked |
| `client-config-issued` | a client config was generated and handed out |
| `iface-up` | address, MTU, port, whether NAT and full-tunnel are on |
| `peer-first-handshake` | a peer handshaked for the first time since the watcher started |
| `peer-quiet` | a peer has not handshaked for `AWG_WATCH_QUIET` seconds |
| `peer-back` | a quiet peer handshaked again |
| `stop` | the interface is being torn down |

**What it deliberately does not contain:** private keys, preshared keys,
passphrases, and config bodies of any kind. A peer is named by its *public* key
and by the operator's label, both of which are already public. `config-applied`
records how many UAPI lines were written, never the lines: the request carries
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
megabyte. There is no timer: the size is checked at write time, which is the
only moment the file can have grown.
