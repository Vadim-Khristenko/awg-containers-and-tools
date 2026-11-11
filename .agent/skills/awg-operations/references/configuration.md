# Configuration, protocols and the network

## Contents

- [Sources and choosing a generation](#sources-and-choosing-a-generation)
- [Generating parameters](#generating-parameters)
- [Checking a finished config](#checking-a-finished-config)
- [Config structure](#config-structure)
- [Container variables](#container-variables)
- [DNS, the .vpn pages and routing](#dns-the-vpn-pages-and-routing)
- [Changing settings](#changing-settings)

## Sources and choosing a generation

Paths here are relative to the repository root. Check capabilities against
`crates/awg-core/src/versions.rs` and `crates/awg-core/src/engines.rs`, `.conf`
handling against `containers/entrypoint.sh`, the topology against
`containers/docker-compose.yml`, the resolver against
`containers/entrypoint-dns.sh`. The docs do not replace the code of the
current checkout.

| Version | Image | Parameters |
|---|---|---|
| 1.0 | `vaiprog/amnezia-wg-1` | `Jc/Jmin/Jmax`, `S1/S2`, fixed `H1-H4`; no `I1-I5` |
| 1.5 | `vaiprog/amnezia-wg-15` | Adds client-side `I1-I5`; its own chain tag set |
| 2.0 | `vaiprog/amnezia-wg-2` | `S3/S4`, H ranges, the new chain tag set |
| 3.0 | `vaiprog/amnezia-wg-3` | `HeaderProtectionKey`, `ContentPaddingAddition`, timer ranges |
| 3.1 | `vaiprog/amnezia-wg-31` | Adds `RandomTrailers`, `DisableCookies` |

These are different protocol generations, not interchangeable tags of one
config. Choose the generation by what the app on every device really supports,
not only by the client's name. `--client` limits the generated values; it does
not update the app.

The 1.5 and 2.0+ chain tag sets do not nest:

- 1.5 knows `b c t r wt`; `<c>` and `<t>` are unique within a chain. The
  generator does not emit `wt`.
- amneziawg-go 2.0+ knows `b t r rc rd d ds dz`, but not `c`. The `<c>` tag
  (packet counter) exists only in the Linux kernel module; the generator uses
  the intersection of the engines at **both** ends (`--server-engine`, default
  `go`, which is these images).
- Never carry `<rc>`/`<rd>` into 1.5 and never force `<c>` on 2.0/3.x. The
  error `invalid i1: invalid tag: rc` needs the right generation, not removing
  all obfuscation.
- In 1.5 the client sends the chains. A server without `I1-I5` does not by
  itself mean a broken connection.

## Generating parameters

Commands assume an installed `awg-tool`; without it use
`cargo run -p awg-cli --` instead of `awg-tool`.

```bash
awg-tool profiles
awg-tool clients
awg-tool hosts --role quic --region ru
awg-tool gen --version 3.1 --client amneziavpn
awg-tool gen --version 3.0 --profile tls --region ru --whitelisted ru
awg-tool gen --version 2.0 --client amneziawg-windows --client-release pre-2.0.2
awg-tool gen --version 3.1 --uapi
awg-tool gen --version 3.1 --mihomo
awg-tool gen --version 3.1 --save phone      # save a set of settings
awg-tool gen --set phone                     # apply it again
```

`gen` prints an obfuscation block, **not a ready server**, not a client key
pair and not a peer registration. Each run gives a new set. For one pair,
generate the block once and keep matching parameters at both ends. Never run a
new generation on a working server just to add a device: it breaks step with
the other clients. Changing the block for everyone is `awg-tool rotate` (see
[clients.md](clients.md)).

`gen --host` is the name for mimicry packets (for example SNI), not an SSH
address or an `Endpoint`; in `install` the same thing is `--mimic-host`.
Without it the name comes from a database of about 2400 hosts by role and
region (`--region`, `--whitelisted`).

Profiles: `quic`, `quic0rtt`, `tls`, `noise`, `dtls12`, `dtls13`, `http3`,
`sip`, `tls-to-quic`, `quic-burst`, `dns`, `stun`, `random`. `profiles` prints
the current list.

Clients in the matrix: `amneziawg-android`, `amneziawg-ios`,
`amneziawg-windows`, `amneziavpn`, `wg-tunnel`, `wiresock`, `mihomo`,
`opnsense`, `keenetic-native`, `wg-easy`, `awg-go-legacy`, `awg-kmod`,
`openwrt`, `asus-merlin`. Check the id with `clients`: the UI name and the CLI
id can differ, and the per-client warnings are listed there too.

- AmneziaWG Windows before build 2.0.2 limits H to `2_147_483_647`: pass
  `--client-release pre-2.0.2` if the device has an old build.
- WireSock does not send `I1-I5` at all; configs for it leave them out. mihomo
  runs 3.x only with `version: 3` (`gen --mihomo` writes it).
- A large S4 and a long junk train cost traffic, CPU and battery. Do not turn
  on `--extreme` to "fix" a connection without measuring.
- `--junk` takes 0..32, default 5, but the result is capped by version and
  client. Check the Jc you got, not the flag's promise.

### Switches and presets

Choosing `--version` applies that version's preset, the same way Any Tech
ARCHITECT does. For 3.1: MTU 1280, `RandomTrailers` on, H1-H4 = 1, 2, 3, 4
(`--disable-h`), narrow H windows; `DisableCookies` off. Every switch takes
`on` or `off`, and a flag with no value turns it on:

```bash
awg-tool gen --version 3.1 --random-trailers off --disable-h off
awg-tool gen --version 3.0 --random-timings --content-padding off
```

`--same-s` and `--disable-h` act only on 3.1 with header protection and
trailers on. `DisableCookies` removes the under-load protection and can break
NAT keepalive: never turn it on by default. Older versions silently ignore 3.1
fields; do not judge support for an option by the exit code alone.

Main `gen` flags and their defaults:

| Flag | Default | Meaning |
|---|---|---|
| `--version` | `3.0` | Protocol generation and its preset |
| `--profile` | `quic` | I1 mimicry |
| `--client` | `amneziavpn` | Value and tag limits |
| `--client-release` | current | An old client build with its own limits |
| `--server-engine` | `go` | What parses `I1-I5` on the server |
| `--intensity` | `medium` | `low`/`medium`/`high` |
| `--mtu` | `1500` | Path MTU for size calculations; does not set the tunnel MTU |
| `--router` | off | Moderate junk and padding for a weak device |
| `--browser` | unset | Browser packet sizes (chrome, edge, firefox, safari, ios, yandex-desktop, yandex-mobile, 360, qq) |
| `--mimic-all` | off | The chosen profile for all five I packets |
| `--uapi` | off | UAPI lines, not a full `set=1` request with keys and peers |
| `--json` | off | JSON with version, profile, params and lines |
| `--mihomo` | off | A proxy block for mihomo |
| `--out PATH` | stdout | Write to an owner-only file, overwriting |
| `--set`/`--save` | | Load or save a set of settings (`awg-tool sets`) |
| `--lang` | from the environment | `en`/`ru`; wins over `AWG_LANG`, `LC_ALL`, `LANG` |

`--tag-c` is accepted for old scripts and forces nothing: `<c>` is used where
both engines understand it. A 3.x block holds the secret
`HeaderProtectionKey`, so never commit `params.conf`.

## Checking a finished config

```bash
awg-tool check client.conf
awg-tool check 'vpn://...' --client amneziawg-windows
awg-tool check - --json < server.conf
```

Exit code 0 with no findings, 1 with warnings, 2 with errors. The check finds
sizes over the MTU, size collisions the generation's daemon refuses, invalid
tags, client limits, a placeholder endpoint, and the known client quirks (see
"Client quirks" in [clients.md](clients.md)). Never paste a config with keys
into the chat to check it: run `check` where the file is.

## Config structure

The templates below show the structure and are **not ready to run**: replace
the values in angle brackets with real keys and paste in the generator's
block. Keep secrets out of Git and public issues.

Server `server.conf`:

```ini
[Interface]
PrivateKey = <server-private-key-base64>
Address = 10.99.0.1/24
ListenPort = 51820
MTU = 1280
# Paste the awg-tool gen block that matches the image version here.

[Peer]
PublicKey = <client-public-key-base64>
PresharedKey = <shared-psk-base64>
AllowedIPs = 10.99.0.2/32
```

Client `client.conf`:

```ini
[Interface]
PrivateKey = <client-private-key-base64>
Address = 10.99.0.2/32
DNS = 172.29.172.254
MTU = 1280
# Paste the same compatible obfuscation block.

[Peer]
PublicKey = <server-public-key-base64>
PresharedKey = <shared-psk-base64>
AllowedIPs = 10.99.0.0/24, 172.29.172.0/24
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
```

For the demo pair inside Compose the client's `Endpoint` can be
`172.31.99.10:51820`. An outside device needs the server's reachable public IP
or domain and a published UDP port; the container name and bridge IP are not
reachable from outside. Behind NAT, forward UDP on the edge device as well.

The two sides have different private keys. On the server, `[Peer]` holds the
client's public key; on the client, the server's. One pair shares the same
`PresharedKey`. The server's `AllowedIPs` limits **this** client's address,
usually a `/32`; never put the client's `0.0.0.0/0` there to reach the
internet.

For a full tunnel on the client use `AllowedIPs = 0.0.0.0/0, ::/0`, both
default routes: AmneziaVPN ignores its site lists with only one of them, and
without `::/0` the device's IPv6 goes around the tunnel (`awg-leak` and
`awg-tool under` catch that). The container network, NAT and SSH install are
IPv4: `::/0` keeps IPv6 off the open internet but does not by itself give
working IPv6. For a split tunnel list the wanted networks plus the services
network `172.29.172.0/24`, home of the resolver (`.254`) and the pages
(`.253`).

`MTU = 1280` suits 3.x with extra padding and 3.1 trailers on a 1500 path.
The entrypoint sets 1420 when there is no `MTU`, while an issued client config
gets 1280 when the server file has none: set the MTU explicitly so the sides
match. `awg-mtu` and the `mtu.vpn` page measure the real path limit. Some
clients bring the tunnel up with a larger MTU than the config says; a node with
NAT clamps forwarded TCP to its own MTU (`AWG_MSS`).

The entrypoint reads the known keys and sets up addresses, routes and NAT
itself through UAPI. `PreUp`, `PostUp`, `PreDown`, `PostDown`, `SaveConfig` and
`Table` are not run as in `wg-quick`. The `DNS` field in a container client's
`.conf` **does not rewrite** `/etc/resolv.conf`; the container's DNS is set up
through Docker. A domain in `Endpoint` is resolved at start; a changed A record
is not followed live.

## Container variables

These belong to the current `entrypoint.sh`, `awg-peer`, `awg-watch` and
Compose; `awg-tool install` flags are a different interface.

| Variable | Default | Purpose |
|---|---|---|
| `AWG_IFACE` | `awg0` | Interface name |
| `AWG_CONF` | `/etc/amnezia/awg/${AWG_IFACE}.conf` | The mounted `.conf` |
| `AWG_SOCK_DIR` | `/var/run/amneziawg` | UAPI socket directory |
| `AWG_NAT` | `auto` | `on`/`off`; `auto` turns NAT on when there is a `ListenPort` |
| `AWG_MSS` | `auto` | With NAT, holds forwarded TCP MSS to the tunnel MTU (MTU minus 40); a number sets its own value, `off` turns it off |
| `AWG_FWMARK`, `AWG_TABLE` | `ListenPort`, else `51820` | Mark and table for a client's default route |
| `AWG_EXCLUDE` | unset | Client container with a full tunnel: these CIDRs stay on `eth0` (`ip rule` bypasses above the tunnel's rules). Refuses to start when they cover a `DNS =` address |
| `AWG_STATE_DIR` | `/var/lib/awg` | Start counter and peer restore |
| `AWG_PEERS_DIR` | see below | Directory of dynamic peer records |
| `AWG_EVENT_LOG` | `/var/log/awg/events.log` | Event log |
| `AWG_EVENT_LOG_MAX_BYTES` | `262144` | Rotation size; one old copy |
| `AWG_ENDPOINT` | `SERVER_PUBLIC_IP:<ListenPort>` | External endpoint for new configs |
| `AWG_PUBLIC_HOST` | unset | Fallback host for issuing when there is no `AWG_ENDPOINT` |
| `AWG_CLIENT_DNS` | `172.29.172.254` | DNS in the issued client `.conf` |
| `AWG_SERVICES_NET` | the resolver's `/24` | Resolver and pages network routed into the tunnel |
| `AWG_CLIENT_ALLOWED` | `<tunnel>/24, <services>/24` | Routes in the issued client `.conf`. A full tunnel is `0.0.0.0/0, ::/0`: with only one of them AmneziaVPN silently skips its site lists, and `awg-peer` warns |
| `AWG_CLIENT_EXCLUDE` | unset | CIDRs kept off a full tunnel: the issued `.conf` gets `0.0.0.0/0, ::/0` minus these. Not together with `AWG_CLIENT_ALLOWED`; refused when it covers the resolver |
| `AWG_NAMES_FILE` | `/var/lib/awg-names/names.hosts` | Peer names for the resolver, with node facts next to it |
| `AWG_WATCH` | `on` | `off` stops the background `awg-watch` |
| `AWG_WATCH_QUIET` | `600` | Seconds without a handshake before "went quiet" |
| `AWG_DUMP_REQUEST` | `0` | `1` keeps the secret UAPI request in `/tmp/uapi-set.req` |
| `LOG_LEVEL` | unset | `verbose` turns on the daemon's detailed log |

`awg-peer` has `AWG_PEERS_DIR=/var/lib/awg/peers.d` fixed, while the
entrypoint derives it from `AWG_STATE_DIR`. When moving the state directory
set **both** the same way, or new peers and the restore after start look in
different places.

## DNS, the .vpn pages and routing

In the stock Compose the server joins the transport network `172.31.99.0/24`
and a separate DNS bridge `172.29.172.0/24`. The resolver is on
`172.29.172.254`, the pages on `172.29.172.253`. Neither port 53 nor the pages'
HTTP is published outside.

- Do not add `ports: 53:53` for outside clients: they must reach DNS
  **through the tunnel**, and the server must reach the bridge.
- A split tunnel with `DNS = 172.29.172.254` needs a route to the services
  network; the default issue already includes `172.29.172.0/24` (resolver and
  pages). Configs issued before 0.5.0 with only the resolver's `/32` do not
  open the pages: add `172.29.172.0/24` or reissue.
- The fail-closed property covers queries to this private address while the
  networks stay isolated. It does not block a system fallback, browser DoH or
  another VPN on the device; check the real client.
- Do not swap tunnel-only DNS for a public `1.1.1.1`/`8.8.8.8` and then claim
  the old guarantees.
- The resolver runs with every capability dropped and needs
  `cap_add: [NET_BIND_SERVICE]` for port 53 (the stock Compose has it). Since
  0.5.1 it also starts without it where Docker allows low ports.
- On a server on two networks, check which one carries its default route: if
  it goes through the resolver's network, set `gw_priority` (Docker Engine 28+);
  `containers/README.md` shows how.

### How the resolver gets answers

`AWG_DNS_MODE=auto` (the default) asks the root servers at start: if they
answer, it recurses; if not (the network cuts outgoing DNS), it uses DoT to
`AWG_DNS_FORWARD` (Cloudflare and Quad9). `recursive` and `forward` pin the
mode. DNSSEC is validated. No answers can be the server's egress limit, not a
missing handshake.

### Lists, own records, zones

Everything optional lives in a directory mounted at `/etc/awg-dns`
(read-only); changes are picked up within seconds, without a restart:

| Path | Content |
|---|---|
| `blocklists.d/*.txt` | Names to block: plain names, hosts lines or `\|\|name^` |
| `blocklists.url` | List URLs, refreshed every `AWG_DNS_REFRESH` seconds |
| `allowlist.d/*.txt` | Names never blocked, whatever the lists say |
| `records.d/*.records` | Own records: `nas.home A 192.168.1.10` (A AAAA CNAME TXT MX SRV PTR) |
| `vpn.d/*.records` | Names in the own `.vpn` zone |
| `forward.d/*.conf` | Zones sent to chosen resolvers: `home.arpa. 192.168.1.1` |
| `chain.conf` | The resolver chain, in order |

The old path `/etc/unbound/blacklist.d` is read too. A blocked name and
everything under it gets NXDOMAIN from the resolver itself. A broken line does
not take the resolver down: the config is checked before it is applied, and
otherwise the old one stays.

From the CLI, on the host `status` would pick:

```bash
awg-tool dns                      # mode, counters, zones, chain
awg-tool dns block ads.example
awg-tool dns allow www.example
awg-tool dns query example.com
```

`block`/`allow` write to the resolver's own volume (`awg-dns-state`), not to
the operator's directory. No new list handler is needed.

### The chain and forwarded zones

`chain.conf` lists resolvers asked in order; `default` is the resolver's own
path (recursion or DoT, with DNSSEC):

```
default
185.121.177.177
```

The chain moves to the next one when there is no answer in time, on SERVFAIL,
REFUSED, NXDOMAIN, or when the addresses are only `0.0.0.0`, `127.0.0.0/8`,
`::`, `::1` (how filters say "blocked"). That way domains of another root
(`.geek`) resolve, and ordinary names go as before. `AWG_DNS_CHAIN_KEEP`
accepts a reason instead of moving on, `AWG_DNS_CHAIN_SINKHOLES` adds sinkhole
addresses. Answers further down the chain are **not DNSSEC-validated**; say so.
For a single zone `forward.d` is simpler: it goes only to the named resolvers,
including zones unbound would otherwise answer itself (`home.arpa.`, `test.`,
private reverse zones). The `.vpn` zone cannot be forwarded.

### The .vpn pages

`amiunder.vpn` (under the VPN or not), `dns.vpn` (mode, counters, name
lookup), `speed.vpn`, `mtu.vpn`, `leak.vpn` (does the browser resolve around
the tunnel), `node.vpn`. At the bare address a fragment picks the page:
`http://172.29.172.253/#dns`. The pages show only counts, never the names of
other peers.

## Changing settings

1. Record the current `.conf` paths, volumes, image and digest, port and peer
   list without publishing secrets.
2. Warn about the tunnel dropping before a restart. Keep a backup of the config
   and state, readable by the operator only.
3. To change obfuscation use `awg-tool rotate` and update every client
   together; when changing the endpoint, DNS or routes, reissue or edit the
   files already handed out. Container variables change future issues, not the
   files on phones.
4. Changing `environment`, the image or a mount in Compose needs the service
   recreated with `docker compose up -d server`; a plain `restart` does not
   apply a changed container description. The `.conf` itself is reread at
   start.
5. Never delete named volumes to "reset": they hold PSKs and dynamic peers.
   Lost state cannot be rebuilt from a list of public keys.
6. After the change check the handshake and real DNS and traffic, not only
   `healthy`. The diagnostic order is in [operations.md](operations.md).
