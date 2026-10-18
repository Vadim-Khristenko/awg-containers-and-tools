# AmneziaWG Containers and Tools

Self-hosted AmneziaWG servers for **every** protocol generation (1.0, 1.5, 2.0, **3.0** and **3.1**) as small container images, a tunnel-only resolver with its own `.vpn` pages, and a Rust CLI with an interactive UI that generates the obfuscation parameters, installs servers over SSH and runs them afterwards.

**Русская версия: [RU.README.MD](RU.README.MD)**

> **Unofficial.** This is a community project. It is not affiliated with, endorsed by, or supported by AmneziaVPN. If something here breaks, open an issue **on this repository**, please, not upstream.

---

## Why this exists

AmneziaWG 3.0 has been out for a while, and the clients support it. Self-hosting it was a different story.

The official server pipeline configures tunnels through `awg-quick`, which reads a `.conf` file and hands it to `awg setconf`. That parser lives in `amneziawg-tools`, and for a long time it only understood the 2.0 key set. Feed it a 3.0 config and it stopped at the first unknown line:

```
$ awg setconf awg0 awg0.conf
Line unrecognized: `HeaderProtectionKey=...'
Configuration parsing error
```

The daemon itself was fine: `amneziawg-go` implements 3.0 (and now 3.1) completely. Only the config path in front of it lagged behind. So this project skips that path and talks to the daemon directly over its UAPI socket: one request format that covers 1.0 through 3.1 and does not depend on what the tools in the image happen to parse.

That is the whole trick. Everything else here is packaging, parameter generation and making it pleasant to run.

### How it ended up like this

It began as a small thing to make installing AmneziaWG less tedious, a wrapper around steps people were already doing by hand. Then it turned out nobody could self-host 3.0 at all, and, well, you only live once. So it grew up into the operator of its own stack: it builds the images, puts them on your server, issues the client configs, rotates the obfuscation when you ask, and tells you when something is wrong with the result.

Official self-hosted 3.0 will land upstream sooner or later. When it does, use it. Until then, this works.

## What you get

| | |
|---|---|
| **Five server images** | one per protocol generation, ~33 MB each, with the node utilities inside |
| **A DNS resolver image** | ~20 MB, reachable only from inside the tunnel, with lists, your own records, forwarded zones and a resolver chain |
| **A status page image** | `amiunder.vpn` and its siblings `dns`, `speed`, `mtu`, `leak` and `node.vpn` |
| **`awg-tool`** | generates and checks parameters, installs servers over SSH, issues peers, rotates obfuscation, runs the resolver |
| **An interactive UI** | run `awg-tool` with no arguments |

Images are published on Docker Hub under [`vaiprog`](https://hub.docker.com/u/vaiprog):

| Image | Protocol | Built on |
|---|---|---|
| `vaiprog/amnezia-wg-1` | AWG 1.0 | amneziawg-go v0.2.12 |
| `vaiprog/amnezia-wg-15` | AWG 1.5 | amneziawg-go v0.2.14-beta-awg-1.5-1, plus [one fix](containers/patches/README.md) |
| `vaiprog/amnezia-wg-2` | AWG 2.0 | amneziawg-go v0.2.19 |
| `vaiprog/amnezia-wg-3` | AWG 3.0 | amneziawg-go v3.0.20260805 |
| `vaiprog/amnezia-wg-31` | AWG 3.1 | amneziawg-go v3.1.20260828 |
| `vaiprog/amnezia-wg-dns` | | unbound and awg-dns-chain |
| `vaiprog/amnezia-wg-status` | | the tunnel's own pages |

The last 1.5 tag drops every transport packet that happens to be the size of a handshake message, and upstream will not tag that line again, so the 1.5 image carries [one small patch](containers/patches/README.md) that keeps them. All five tunnel generations run side by side on one host without stepping on each other. Every image is published for `amd64` and `arm64`, the latter being what most boards people actually run tunnels on speak.

---

## Quick start

### Run a server with Docker Compose

```bash
git clone https://github.com/Vadim-Khristenko/awg-containers-and-tools
cd awg-containers-and-tools/containers
```

Generate one parameter block and paste it into **both** `server.conf` and `client.conf`. The obfuscation parameters have to match on the two ends, or the peers will not recognise each other's packets:

```bash
awg-tool gen --version 3.1
```

Add your keys and addresses, then:

```bash
docker compose up -d
docker compose exec server awg-uapi get      # handshakes, transfer counters
docker compose exec server awg-peer add laptop
```

`awg-peer add` prints a complete client config, ready to import. The compose file also brings up the resolver and the status pages, with the volumes they share: the node's peer names (for `<label>.peer.vpn`), the resolver's own lists, and the counters the `dns.vpn` page shows.

### Install on a remote server over SSH

```bash
awg-tool install --host 203.0.113.9 --user root --key ~/.ssh/id_ed25519
```

It looks at the machine before it changes anything: which distribution, whether docker is usable and whether it needs `sudo`, and what address clients should be pointed at. It knows the twelve most common distributions and falls back through `ID_LIKE` for derivatives, so Zorin is treated as Ubuntu and CachyOS as Arch.

If a package is missing it prints the exact command and asks before running it. On NixOS it stops and hands you a `configuration.nix` snippet instead, because installing packages imperatively there would not survive the next rebuild.

If something is already listening on the tunnel port it tells you what, and stops. It will not kill another process for you: picking a free port with `--listen-port` costs one flag, and killing the wrong thing costs a server.

When it finishes you get the client `.conf` and the `vpn://` link on stdout. Every option `gen` takes works here too; the name the mimicry imitates is `--mimic-host` here, since `--host` is the server.

The survey makes no outbound connections *from* your server: the endpoint address comes from the default route's source, not from an echo service. And `sudo docker info` is only attempted if the unprivileged call already failed: a needless `sudo` is how a survey trips an audit alert on someone else's machine.

Connection profiles are saved so the second run is `--server NAME`. Passwords only reach the disk if you ask for that. A host key is never accepted silently: the first connection shows its fingerprint and asks, and a changed key stops everything.

### Where the binary comes from

There are published binaries for every release since `0.3.0`: `awg-tool-linux-amd64`, `awg-tool-linux-arm64`, Windows and macOS builds, plus checksums. If you would rather build it yourself:

```bash
cargo build --release            # needs Rust 1.90+, edition 2024
./target/release/awg-tool --help
```

or run it without installing:

```bash
cargo run -p awg-cli -- gen --version 3.1
```

---

## Running what is already there

```bash
awg-tool status --server home     # what is running, peers, handshakes, traffic
awg-tool status --local           # the containers on this machine, no SSH
awg-tool doctor                   # why is it not carrying traffic?
awg-tool logs --lines 200         # the log, with key material stripped out
awg-tool update                   # is the tool, or an image, out of date?
```

`status` finds our containers by image reference, and by the label the images carry when the image was renamed, so a node someone renamed is still found and a container that is not ours is not touched. With neither `--server` nor `--host` given, a machine that already runs our containers answers locally instead of asking which server you meant. `--local` forces that; `--container NAME` (or `auto`) picks one node when several are up.

`doctor` returns a verdict with a confidence level, the evidence behind it and the next step, not a wall of log text. It tells a missing `/dev/net/tun` from a missing `NET_ADMIN` from `ip_forward` being off from a peer that has simply never handshaked, and when the evidence cannot separate two causes it says so and lists both.

`logs` redacts on the way out of the library, not at the print site: private keys, pre-shared keys and header-protection keys cannot cross that boundary, so the output is safe to paste somewhere.

### Peers

```bash
awg-tool peer add phone                  # a new peer; prints its config once
awg-tool peer add phone --vpn --mihomo   # ...plus the vpn:// link and a mihomo entry
awg-tool peer add phone --out phone.conf # written owner-only instead of printed
awg-tool peer list                       # label, public key, address, last handshake
awg-tool peer rm phone                   # revoke, by label or public key
```

All of these work here or over SSH, the same as `status`. The issued config is checked before it is printed, so a node whose own config drifted says so at once rather than in a client that never connects.

### New obfuscation for a running node

```bash
awg-tool rotate --dry-run         # what would change, and who would need the new block
awg-tool rotate                   # asks, then does it
awg-tool rotate --out block.conf  # the clients' new block to a file
```

Rotation replaces everything both ends share (junk, sizes, headers, chains, the 3.x keys) and leaves the server's own key, address, port and peers alone. It reads the config through the container, finds the file it came from on the host, keeps a backup next to it, restarts the node and waits for it, and puts the old config back if the node does not come up. Every client then needs the new block, which is why this is a deliberate act and not a setting.

Over SSH, the server's private key and its peers' pre-shared keys never travel, not even inside a command line `ps` would show on the server: only the new block is sent, the rewrite happens next to the file, and what the container then reads must match the planned config byte for byte or the backup goes back.

### The UI

`awg-tool` with no arguments opens it. Every command above is there too: the generator with every knob and saved sets, a check screen, and a servers screen with this machine's docker as its first row and your saved connections below it. On a node: `p` lists peers, `+` issues one, `-` revokes one, `R` rotates (shown first, then confirmed by typing the node's name), `d` diagnoses, `L` shows the log. On the resolver: `b`/`B` block and unblock a name, `a`/`A` allow and unallow one, `/` asks it a name.

---

## Parameter generation

```bash
awg-tool gen --version 3.1 --client amneziavpn
awg-tool gen --version 3.0 --profile quic --region ru --whitelisted ru
awg-tool gen --version 2.0 --client amneziawg-windows --client-release pre-2.0.2
awg-tool gen --version 3.1 --uapi              # UAPI lines instead of .conf
awg-tool gen --version 3.1 --mihomo            # a mihomo (Clash.Meta) proxy entry
awg-tool gen --version 3.1 --json              # for scripts
awg-tool gen --version 3.1 --save phone        # keep these settings as a set
awg-tool gen --set phone                       # and use them again
```

Every run produces a fresh parameter set. This matters more than it looks: if everyone deployed the same numbers, every server built with this tool would share one DPI fingerprint, and blocking all of them at once would be trivial.

The generator enforces the protocol's real constraints rather than emitting plausible-looking numbers: the S-value ceilings that keep every message inside the MTU, the S-value floor when header protection is on, the relationship between the rekey and reject timers, the size collisions each daemon generation refuses, the tag vocabulary of the engine on each end, and the 3200-byte netlink budget of the kernel module.

Choosing a version applies its preset, as Any Tech ARCHITECT does. On 3.1 that means MTU 1280, `RandomTrailers` on and H1 to H4 as 1, 2, 3, 4; `DisableCookies` stays off, since it breaks NAT keepalive under load. Every switch takes `on` or `off`: `--random-trailers off`, `--disable-h off`, `--header-protection`, `--content-padding`, `--random-timings`, `--same-s`. `awg-tool --help` lists them all.

### Mimicry profiles

The `I1` to `I5` packets can be shaped to look like ordinary traffic:

```
quic  quic0rtt  tls  noise  dtls12  dtls13  http3  sip  tls-to-quic  quic-burst  dns  stun  random
```

```bash
awg-tool profiles                      # list them
awg-tool hosts --role quic --region ru # the host names they may use
awg-tool gen --profile tls --host cdn.example.com
```

Names come from a database of about 2,400 hosts by role and region, so a QUIC packet names a host that really speaks QUIC and is plausible where you are; `--whitelisted ru` keeps to hosts that still work when the network is cut down. `--browser` matches a real browser's packet sizes (chrome, edge, firefox, safari, ios, yandex-desktop, yandex-mobile, 360, qq).

### Clients

```bash
awg-tool clients
```

Clients do not all accept the same things, and a config that exceeds one of these limits fails at import, sometimes loudly, sometimes not. `--client` trims the output to what your target accepts, `--client-release` to an older build of it, and `--server-engine` to what parses the chains on the server. The `<c>` tag is used only where both engines parse it: amneziawg-go has no packet counter, only the Linux kernel module does.

### Checking a config someone else wrote

```bash
awg-tool check client.conf
awg-tool check 'vpn://...' --client amneziawg-windows
awg-tool check - --json < server.conf
```

Exit 0 when clean, 1 with warnings, 2 with errors, so a script can gate on it. The findings come in English or Russian (`--lang ru`).

---

## DNS

The resolver sits on its own bridge network at `172.29.172.254`, matching what AmneziaVPN does upstream. Nothing publishes its port and no other network can reach that bridge, so a client configured with `DNS = 172.29.172.254` can only get an answer through the tunnel. A query that leaks outside the tunnel does not quietly reach your ISP's resolver instead: it reaches nothing at all, and fails visibly.

It resolves from the root itself when the root answers from your network, and over DoT to Cloudflare and Quad9 when it does not (`AWG_DNS_MODE=auto`, the default; `recursive` and `forward` pin one). DNSSEC is validated.

### Lists, records and zones

Everything you change lives in one directory, mounted at `/etc/awg-dns`, all of it optional and reloaded without a restart:

```
blocklists.d/*.txt     names to block: plain, hosts-file or adblock `||name^` lines
blocklists.url         list URLs, one per line, refreshed daily
allowlist.d/*.txt      names never blocked, whatever a list says
records.d/*.records    your own records: `nas.home A 192.168.1.10`
vpn.d/*.records        names in the tunnel's own .vpn zone
forward.d/*.conf       zones sent to resolvers you name: `home.arpa. 192.168.1.1`
chain.conf             resolvers asked in order (below)
```

From the CLI, on whichever host `status` would pick:

```bash
awg-tool dns                      # mode, counts, zones, the chain, cache share
awg-tool dns block ads.example    # and everything beneath it
awg-tool dns allow www.example    # through a blocked parent
awg-tool dns query example.com    # what the resolver answers
```

A blocked name answers NXDOMAIN from the resolver itself. A file with a bad line does not take the resolver down: every generated config is checked before it is used, and a broken one falls back to the last good one. The resolver also answers Firefox's DoH canary (and, with `AWG_DNS_CANARY="firefox icloud"`, iCloud Private Relay's) so browsers keep to it instead of resolving around it.

### The chain: other roots, filters and fallbacks

`chain.conf` lists resolvers in the order they are asked, `default` being the resolver's own way of resolving:

```
default
185.121.177.177     # OpenNIC
```

With a chain, every name resolves as before, and a name the real root says does not exist (`.geek`, say) is asked further down. The chain moves to the next resolver on no answer in time, SERVFAIL, REFUSED, NXDOMAIN, or an answer that only points at `0.0.0.0`, `127.0.0.0/8`, `::` or `::1`, which is how most filtering resolvers say "blocked". Put a filtering resolver first and the next one answers what it blocks; put `default` first and the others answer what the real root does not have.

A silent resolver is not waited out: after 400 ms the next one is asked alongside it, and the earlier one keeps priority a little longer, so a slow but right answer still wins. An answer counts only when it came from the address asked, with the query's id and question. `AWG_DNS_CHAIN_SINKHOLES` adds addresses that mean "blocked", `AWG_DNS_CHAIN_KEEP` accepts a reason instead of moving on, and `AWG_DNS_CHAIN` sets the chain without a file. The chain starts, changes and stops with the file, without a restart.

For a single zone, `forward.d` is simpler: `geek. 185.121.177.177` sends that zone, and only that zone, to OpenNIC. It also works for zones unbound answers itself by default, such as `home.arpa.` or a private reverse zone, so a home network's names can come from its router.

### The tunnel's pages

The compose file stands up a status container that answers several names in the `.vpn` zone:

| | |
|---|---|
| `amiunder.vpn` | are you under the VPN? If the page opens, yes: `.vpn` is not a real TLD and the address answers only inside the tunnel |
| `dns.vpn` | the resolver's mode, its counters, the chain's counts, and a box to ask it a name |
| `speed.vpn` | latency, download and upload through the tunnel, to this node and back |
| `mtu.vpn` | whether large packets get through, sizes from 1 KB to 1 MB both ways |
| `leak.vpn` | whether your browser resolves through the tunnel or around it (DoH, mostly) |
| `node.vpn` | the protocol, daemon and MTU of the node, and every page above |

Opened by address rather than by name, the page is chosen with a fragment (`http://172.29.172.253/#dns`). Everything on them comes from the same host: no third-party speed test, no counters, no request that could reveal your real address. The pages show counts only, never a name anybody asked for and never another peer's name. They speak Russian and English, and the stylesheet is the Architect kit itself, served locally.

---

## Inside the node

```bash
awg-peer add <label> [ip]        # new peer; prints the client config once
awg-peer list                    # label, public key, allowed IP, last handshake
awg-peer rm <label|pubkey>       # revoke
awg-uapi get                     # raw daemon state
```

A new peer's private key is generated inside the container, printed once and never written to disk. What is stored is the label, public key, address and pre-shared key, the last because the server needs it again after every restart.

The node keeps an event log at `/var/log/awg/events.log`, mirrored to `docker logs`: when it came up, when the interface was configured, who was given access and when it was taken away, and which peers went quiet or came back. It contains no private keys, pre-shared keys or config bodies. It is still sensitive, because it *is* the list of who has access. It is bounded at 256 KiB plus one rotation.

### When it does not work

Every node image carries the utilities for that moment:

```bash
awg-health                 # exit 0 when the node can carry traffic
awg-under                  # "am I under the VPN?" from inside a client node
awg-leak                   # DNS, IPv6 and routing leak check from inside a client node
awg-mtu                    # the largest packet the tunnel really carries
awg-watch                  # peers: active, quiet, or never connected
awg-dump > dump.txt        # the whole picture, made for pasting
```

`awg-leak` asks `resolver.vpn` rather than trusting any answer: on networks that answer DNS sent to any address themselves, the tunnel resolver's address answers even with no tunnel up, and only the real one knows its own name. It also catches an IPv6 default route outside a full IPv4 tunnel, the most common leak a copied config has.

`awg-mtu` finds the largest size that is answered through the tunnel; when that is below the interface MTU it says what to put in the config. `awg-watch` runs in every node by default (`AWG_WATCH=off` leaves it out) and logs `peer-quiet` and `peer-back` as peers stop and start handshaking.

From the client machine itself:

```bash
awg-tool under             # asks the tunnel resolver and the page, exit 0 when under the VPN
awg-tool under --json
```

---

## Building from source

Rust 1.90 or newer (edition 2024):

```bash
cargo build --release
./target/release/awg-tool --help
```

Building the images and testing them against live tunnels:

```bash
cd containers
./build.sh
./selftest.sh 3.1     # a real tunnel, data through it, checksums compared on the far side
./dnstest.sh 3.1      # the resolver from inside and outside the tunnel, the pages, the chain
./utiltest.sh 3.1     # the node utilities, including the cases where they must say no
```

None of these are smoke tests. `dnstest.sh` alone proves the resolver unreachable from outside the tunnel, the lists, your records, the pages and their CGIs, `awg-mtu` against an artificial blackhole, `awg-watch` against a client that goes away and comes back, and the chain switched on, reordered and off while the resolver runs.

---

## Status

This is release `0.5.0`. There are 443 tests (392 in `awg-core`, 43 in `awg-cli`, 8 in `awg-dns-chain`), all green, and the container suites pass against live tunnels on a Linux host.

Planned: a web UI, WASM builds, Android builds.

### Verifying a download

Every release ships a checksum file named after its tag:

```bash
sha256sum -c checksums-v0.5.0.sha256
```

The binaries are not signed. The checksum tells you the file arrived intact; it does not tell you who built it.

Known limits, so they are not a surprise:

- The UI connects to saved profiles that need no password, or whose password you chose to store. Anything else is a command away, and the screen says so.
- If the tunnel port is taken, the tool tells you what holds it and stops. It will not kill it for you.
- Answers from a resolver further down the chain are not DNSSEC-validated: another root cannot pass a validator that trusts only the ICANN one.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) ([по-русски](RU.CONTRIBUTING.MD)).

Справка для AI-агентов по установке, настройке, клиентам и диагностике:
[`.agent/skills`](.agent/skills/README.md) (на русском, без дополнительных скриптов).

## Support the project

```bash
awg-tool donate
```

Prints the same cards, recurring options and crypto addresses that [Any Tech ARCHITECT](https://architect.vai-rice.space) lists, so you do not have to go and find a web page to support something you are already running. Each address is on a line of its own, so selecting one cannot pick up a label along with it.

## License

MIT, see [LICENSE](LICENSE).

Parameter-generation logic is shared with [Any Tech ARCHITECT](https://github.com/Vadim-Khristenko/Any-Tech-ARCHITECT). A joint release of Any Tech ARCHITECT and VAIEXIA.

Built by Vadim Khristenko (VAI_PROG).
