# AmneziaWG Containers and Tools

Self-hosted AmneziaWG servers for **every** protocol generation — 1.0, 1.5, 2.0 and **3.0** — as small container images, plus a Rust CLI that generates the obfuscation parameters and can install a server on a remote machine over SSH.

**Русская версия: [RU.README.MD](RU.README.MD)**

> **Unofficial.** This is a community project. It is not affiliated with, endorsed by, or supported by AmneziaVPN. If something here breaks, open an issue **on this repository** — please do not send it upstream.

---

## Why this exists

AmneziaWG 3.0 has been out for a while, and the clients support it. Self-hosting it is a different story.

The official server pipeline configures tunnels through `awg-quick`, which reads a `.conf` file and hands it to `awg setconf`. That parser lives in `amneziawg-tools`, and it still only understands the 2.0 key set. Feed it a 3.0 config and it stops at the first unknown line:

```
$ awg setconf awg0 awg0.conf
Line unrecognized: `HeaderProtectionKey=...'
Configuration parsing error
```

The daemon itself is fine — `amneziawg-go` v3.0.2 implements 3.0 completely. Only the config path in front of it is behind. So this project skips that path and talks to the daemon directly over its UAPI socket, which accepts every 3.0 key today.

That is the whole trick. Everything else here is packaging, parameter generation and making it pleasant to use.

### How it ended up like this

It began as a small thing to make installing AmneziaWG less tedious — a wrapper around steps people were already doing by hand. Then it turned out nobody could self-host 3.0 at all, and, well, you only live once. So it grew up into the operator of its own stack: it builds the images, puts them on your server, issues the client configs and tells you when something is wrong with the result.

Official self-hosted 3.0 will land upstream sooner or later. When it does, use it. Until then, this works.

## What you get

| | |
|---|---|
| **Four server images** | one per protocol generation, ~33 MB each |
| **A DNS resolver image** | ~20 MB, reachable only from inside the tunnel |
| **`awg-tool`** | generates parameters, exports `.conf` and `vpn://`, installs servers over SSH |
| **An interactive UI** | run `awg-tool` with no arguments |

Images are published on Docker Hub under [`vaiprog`](https://hub.docker.com/u/vaiprog):

| Image | Protocol | Built on |
|---|---|---|
| `vaiprog/amnezia-wg-1` | AWG 1.0 | amneziawg-go v0.2.12 |
| `vaiprog/amnezia-wg-15` | AWG 1.5 | amneziawg-go v0.2.14-beta-awg-1.5-1 |
| `vaiprog/amnezia-wg-2` | AWG 2.0 | amneziawg-go v0.2.19 |
| `vaiprog/amnezia-wg-3` | AWG 3.0 | amneziawg-go v3.0.2 |
| `vaiprog/amnezia-wg-dns` | — | unbound |

All four run side by side on one host without stepping on each other.

---

## Quick start

### Run a 3.0 server with Docker Compose

```bash
git clone https://github.com/Vadim-Khristenko/awg-containers-and-tools
cd awg-containers-and-tools/containers
```

Generate one parameter block and paste it into **both** `server.conf` and `client.conf` — the obfuscation parameters have to match on the two ends, or the peers will not recognise each other's packets:

```bash
awg-tool gen --version 3.0
```

Add your keys and addresses, then:

```bash
docker compose up -d
docker compose exec server awg-uapi get      # handshakes, transfer counters
docker compose exec server awg-peer add laptop
```

`awg-peer add` prints a complete client config, ready to import.

### Install on a remote server over SSH

```bash
awg-tool install --host 203.0.113.9 --user root --key ~/.ssh/id_ed25519
```

It looks at the machine before it changes anything: which distribution, whether docker is usable and whether it needs `sudo`, and what address clients should be pointed at. It knows the twelve most common distributions and falls back through `ID_LIKE` for derivatives, so Zorin is treated as Ubuntu and CachyOS as Arch.

If a package is missing it prints the exact command and asks before running it. On NixOS it stops and hands you a `configuration.nix` snippet instead, because installing packages imperatively there would not survive the next rebuild.

If something is already listening on the tunnel port it tells you what, and stops. It will not kill another process for you — picking a free port with `--listen-port` costs one flag, and killing the wrong thing costs a server.

When it finishes you get the client `.conf` and the `vpn://` link on stdout.

The survey makes no outbound connections *from* your server: the endpoint address comes from the default route's source, not from an echo service. And `sudo docker info` is only attempted if the unprivileged call already failed — a needless `sudo` is how a survey trips an audit alert on someone else's machine.

Connection profiles are saved so the second run is `--server NAME`. Passwords only reach the disk if you ask for that.

### Managing what is already there

```bash
awg-tool status --server home     # what is running, peers, handshakes, traffic
awg-tool doctor                   # why is it not carrying traffic?
awg-tool logs --lines 200         # the log, with key material stripped out
awg-tool update                   # is the tool, or an image, out of date?
```

`status` finds our containers by image reference, so a node someone renamed is still found, and a container that is not ours is not touched.

`doctor` returns a verdict with a confidence level, the evidence behind it and the next step — not a wall of log text. It distinguishes a missing `/dev/net/tun` from a missing `NET_ADMIN` from `ip_forward` being off from a peer that has simply never handshaked, and when the evidence cannot separate two causes it says so and lists both instead of picking the likelier one.

`logs` redacts on the way out of the library, not at the print site: private keys, pre-shared keys and header-protection keys cannot cross that boundary, so the output is safe to paste somewhere.

### Just generate a config

```bash
awg-tool gen --version 3.0 --profile quic --client amneziavpn
awg-tool gen --version 2.0 --client amneziawg-windows --browser chrome
awg-tool gen --version 3.0 --uapi          # UAPI lines instead of .conf
```

---

## Parameter generation

Every run produces a fresh parameter set. This matters more than it looks: if everyone deployed the same numbers, every server built with this tool would share one DPI fingerprint, and blocking all of them at once would be trivial. Randomising per install is the point.

The generator enforces the protocol's real constraints rather than emitting plausible-looking numbers — the S-value floor when header protection is on, the relationship between the rekey and reject timers, the per-version tag vocabulary, and the size ceilings that keep junk packets inside your MTU.

### Mimicry profiles

The `I1`–`I5` junk packets can be shaped to look like ordinary traffic:

```
quic  quic0rtt  tls  noise  dtls  http3  sip  tls-to-quic  quic-burst  dns  random
```

```bash
awg-tool profiles          # list them
awg-tool gen --profile tls --host cdn.example.com
```

`--browser chrome|edge|firefox|safari|yandex-desktop|yandex-mobile` matches the packet sizes a real browser produces, instead of picking sizes that no browser would ever emit.

### Client limits

Clients do not all accept the same things, and a config that exceeds one of these limits fails at import — sometimes loudly, sometimes not. `--client` trims the output to what your target actually supports:

```bash
awg-tool clients
```

| Client | Notable limit |
|---|---|
| AmneziaVPN | full support |
| AmneziaWG Android / iOS | full support |
| AmneziaWG Windows | H-values capped at `INT32_MAX` |
| WG Tunnel | large S3/S4 drains battery — keep S4 modest |
| WireSock | no `<c>`/`<rc>`/`<rd>` tags |
| Keenetic (native) | sensitive to complex `I1`; prefer simple junk or DNS mimicry |
| amneziawg-go (legacy) | `<c>` is unimplemented — produces ErrorCode 1000 |
| OpenWRT, ASUS Merlin | full support |

The `<c>` tag is **off by default** for exactly that reason. `--tag-c` turns it on if you know your client handles it.

### Export formats

Both formats the Amnezia ecosystem uses:

- `.conf` — the standard WireGuard-style file
- `vpn://` — the one-line link the Amnezia client imports directly

---

## DNS leak protection

The resolver sits on its own bridge network at `172.29.172.254`, matching what AmneziaVPN does upstream. Nothing publishes its port and no other network can reach that bridge, so a client configured with `DNS = 172.29.172.254` can only get an answer through the tunnel.

That is a stronger guarantee than "the resolver is preferred". A query that leaks outside the tunnel does not quietly reach your ISP's resolver instead — it reaches nothing at all, and fails visibly.

---

## Server management

Once a server is up:

```bash
awg-peer add <label> [ip]        # new peer; prints the client config once
awg-peer list                    # label, public key, allowed IP, last handshake
awg-peer rm <label|pubkey>       # revoke
awg-uapi get                     # raw daemon state
```

A new peer's private key is generated inside the container, printed once and never written to disk. What is stored is the label, public key, address and pre-shared key — the last one because the server needs it again after every restart.

The node also keeps an event log at `/var/log/awg/events.log`, mirrored to `docker logs`: when the node came up, when the interface was configured, who was given access and when it was taken away. It contains no private keys, pre-shared keys or config bodies — a public key identifies a peer perfectly well. It is still sensitive, though, because it *is* the list of who has access, so treat it accordingly rather than pasting it into an issue. It is bounded at 256 KiB plus one rotation, so a node that flaps for a year still costs half a megabyte.

---

## Building from source

Rust 1.90 or newer (edition 2024):

```bash
cargo build --release
./target/release/awg-tool --help
```

Building the images yourself:

```bash
cd containers
./build.sh
./selftest.sh        # brings up a real tunnel per generation and proves it carries traffic
```

`selftest.sh` is not a smoke test — it establishes a handshake, pushes data through and compares checksums on the far side, for each of the four generations.

---

## Status

Working today: parameter generation for all four versions, the interactive UI, all five container images, SSH deployment, container discovery, health, diagnosis, redacted logs, update checks, and both export formats.

Planned: a web UI, WASM builds, Android builds.

This is release `0.1.1`. There are 318 tests, and the containers are verified against live tunnels rather than smoke tests — but the tool is young, so please report what breaks.

Known limits, so they are not a surprise:

- The UI connects to saved profiles that need no password, or whose password you chose to store. Anything else is a command away, and the screen says so.
- If the tunnel port is taken, the tool tells you what holds it and stops. It will not kill it for you.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) ([по-русски](RU.CONTRIBUTING.MD)).

## Support the project

```bash
awg-tool donate
```

## License

MIT — see [LICENSE](LICENSE).

Parameter-generation logic is shared with [AmneziaWG Architect](https://github.com/Vadim-Khristenko/AmneziaWG-Architect). A joint release of AmneziaWG Architect and VAIEXIA.

Built by Vadim Khristenko (VAI_PROG).
