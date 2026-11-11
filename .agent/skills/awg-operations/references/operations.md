# Operations, diagnostics and upkeep

## Contents

- [Choosing a target and an overview](#choosing-a-target-and-an-overview)
- [Diagnostics by layer](#diagnostics-by-layer)
- [Node utilities and pages](#node-utilities-and-pages)
- [Logs and secrets](#logs-and-secrets)
- [Updating and rolling back](#updating-and-rolling-back)
- [Backup and restore](#backup-and-restore)
- [Source map and contribution checks](#source-map-and-contribution-checks)

## Choosing a target and an overview

```bash
awg-tool status --local
awg-tool status --server home
awg-tool status --host 203.0.113.9 --user root --key "$HOME/.ssh/id_ed25519"
awg-tool doctor --local --container awg-server
awg-tool logs --server home --container awg31-server --lines 200
```

Replace the example names with real ones. `status` picks a container with
`--container`; `logs` and `doctor` also take a positional name. `auto` picks
the only AWG node, leaving out the resolver and the pages; with several nodes
an exact name is needed. Discovery goes by the image and the
`space.vai-rice.awg.protocol` label, not by a name prefix: a renamed node is
still found.

Without `--server`, `--host` or `--local` the target is chosen like this: a
single saved profile is used by itself; several need a choice; with no
profiles and our containers running on this machine, the answer is local.
`--local` picks this machine explicitly. In local mode `--sudo` does not change
how Docker is run: the current user already needs agreed access.

Remote commands (`status`, `doctor`, `logs`, `peer`, `dns`, `rotate`) look at
the containers of the remote host. Before 0.5.0 they wrongly showed the local
list: an empty answer from an old binary does not prove the VPS is empty.
Check the version on the first line of `awg-tool --help`.

`status` shows the image, state, ports, uptime, interface, total RX/TX and the
number of peers that ever shook hands. It is not a "who is online now" list: a
phone that is off stays in the count. For single rows: `awg-tool peer list`;
for "active, went quiet, never connected": `docker exec <node> awg-watch`.
Since 0.5.1 `status` skips the resolver and the pages instead of probing them.

The UI (`awg-tool` with no arguments) shows the same on the servers screen:
this machine's Docker first, the saved connections below. On a node: `p`
peers, `+` issue, `-` revoke, `R` rotate, `d` diagnose, `L` log. On the
resolver: `b`/`B`, `a`/`A`, `/` to search.

## Diagnostics by layer

Start by observing, without a restart. After the client is switched on, make
some traffic: without it an old or zero handshake is not always a fault.

| Layer | Check | What it proves |
|---|---|---|
| Container | `docker compose ps` or `docker ps -a` | The process runs, ports are published |
| Interface and UAPI | `docker exec <node> awg-health` | The interface is up, UAPI answers; not real internet |
| Peers | `awg-tool peer list` | Addresses, public keys, last handshake |
| Tunnel routes | `docker exec <node> ip route` and `ip rule` | Routes and rules in the right namespace |
| DNS | `awg-tool dns`, a query from the client to `172.29.172.254` | The resolver's state and whether the client's path reaches it |
| The wanted service | traffic from a real client, `awg-tool under` | That one route works, not every path |

`doctor` adds evidence, confidence, alternatives and blind spots. Keep that
distinction in the answer: `possible` is not a confirmed cause. There is no
`--client-conf` flag. To compare obfuscation, run `awg-tool check` on the
client file where it lies and compare the fields privately; never ask for the
full secret config in the chat.

Typical symptoms:

| Symptom | Smallest next check |
|---|---|
| TUN or the interface is missing | TUN on the host, the `/dev/net/tun` mount, `NET_ADMIN`, the start error |
| The daemon refused the config | Image generation, allowed keys and tags, `errno`; `awg-tool check` |
| A full-tunnel client refused on images before 0.5.1 | `fwmark` was written after the peers; update the image |
| A tool does not know `HeaderProtectionKey` | Do not use the old `awg setconf`; the entrypoint turns the `.conf` into UAPI |
| Peer `never`, the device was never switched on | Switch it on and make traffic first; do not change the server |
| No handshake after traffic | Endpoint (not `SERVER_PUBLIC_IP`), UDP publish, firewall, NAT, keys and PSK, obfuscation and app version |
| Handshake, but no IP traffic | `AllowedIPs` on both sides, IPv4 forwarding, NAT, routes and MTU |
| IP works, names do not | Client DNS, the route to the services network, the server's access to the resolver bridge, the resolver's egress (`awg-tool dns`) |
| The resolver does not start | `cap_add: [NET_BIND_SERVICE]` with `cap_drop: [ALL]`; images from 0.5.1 also start without it where Docker allows low ports |
| DNS works, `amiunder.vpn` does not | The `172.29.172.0/24` route on a split tunnel (old configs with one `/32`), the pages container |
| New peers vanished after a recreate | Persistent state volume, `AWG_PEERS_DIR`, the restore log |
| A removed peer came back | Its `[Peer]` in the persistent `.conf` or a record in `peers.d` |
| Big requests hang, small ones pass (TLS to large sites) | Path MTU: `awg-mtu` on the client node or the `mtu.vpn` page; on images from 0.5.1 a NAT node clamps TCP MSS (`AWG_MSS`); not bigger S/J |
| AmneziaVPN site lists do nothing | `AllowedIPs` must hold both `0.0.0.0/0` and `::/0`; `awg-tool check` says so |
| A `vpn://` link will not import into AmneziaVPN | Links from awg-tool before 0.5.1; reissue |
| A name under another root (`.geek`) does not resolve | The resolver's `chain.conf` or `forward.d`, `awg-tool dns` (chain counters) |

Zero DNAT counters on the host do not prove no packets come in: the Docker
proxy can pass them another way. An old handshake (doctor's threshold is over
300 seconds) does not prove a switched-off client is broken. Never kill a
foreign process on a taken UDP port.

## Node utilities and pages

```bash
docker exec awg-client awg-under        # under the VPN, and how that is known
docker exec awg-client awg-leak         # DNS, IPv6 and route leaks
docker exec awg-client awg-mtu          # the biggest packet that gets through
docker exec awg-server awg-watch        # active, went quiet, never connected
awg-tool under                          # the same from the user's computer
```

`awg-under` checks the page from **this** namespace; on the server it may be
reachable straight over the bridge and proves nothing about a VPN on a phone.
The answer carries dns, system, page and ipv6 signals; `--json` for scripts.

`awg-leak` checks the container's resolver, that it answers, that it is the
tunnel's own resolver (it asks for `resolver.vpn`: a network that answers DNS
to any address is otherwise indistinguishable), the Firefox DoH canary, and
where internet traffic goes. It asks the kernel for the route with
`ip route get` to a public address, so fwmark rules count: a full tunnel with
its own table, as the entrypoint makes it, counts as the tunnel even though the
main table keeps the old default route. An IPv6 route around a full IPv4
tunnel is a leak. The `DNS` field in a `.conf` does not change the container's
`/etc/resolv.conf`: Docker's resolver `127.0.0.11` stays a way around a full
tunnel, and `awg-leak` names it.

`awg-mtu` pings through the tunnel and finds the biggest size that answers; if
it is below the interface MTU, it says what to put into the config (in steps of
8). `AWG_MTU_MAX` tests above the interface MTU by raising it for a while.

`awg-watch` runs in the background of every node by default and logs
`peer-quiet`, `peer-back`, `peer-first-handshake`.

No utility checks DoH, IPv6 and fallback on outside devices by itself. That is
what the pages are for: `amiunder.vpn`, `leak.vpn` (a fresh name only the
tunnel's resolver knows), `mtu.vpn`, `speed.vpn`, `dns.vpn`, `node.vpn`.
Without DNS: `http://172.29.172.253/#leak`.

## Logs and secrets

`awg-tool logs` scrubs known field names and key shapes in the library. Prefer
it for a first look. It is a heuristic scrub, not a guarantee against an
arbitrary secret. `--lines` defaults to 200; `--follow` and `--since` do not
exist.

Raw `docker logs`, `install` stdout and errors, arbitrary config dumps and
`vpn://` do not go through that scrub. Never run `awg-uapi get` into a public
transcript: UAPI returns the private key, the PSK and the header protection
key. An `errno=0` answer does not make the lines before it safe to publish.

`awg-dump` collects the interface, routes, UAPI, NAT and the tail of the event
log; it has no `private_key` or `preshared_key`, and `header_protection_key` is
cut to `<set, N bytes>` (before 0.5.0 it went into the dump whole: treat an old
3.x dump as secret). Labels, addresses and public keys stay in the dump, so
agree on what may be shown before publishing it.

`AWG_DUMP_REQUEST=1` writes `/tmp/uapi-set.req` with the private key. It is off
by default; do not turn it on without need and agreement, and after diagnosing
turn it off and remove the file as agreed.

The log `/var/log/awg/events.log` is copied to stderr: start, config-applied,
peer-add, client-config-issued, peer-remove, peer-quiet, peer-back,
peer-first-handshake, stop. It holds no config bodies; it rotates at 256 KiB
with one old copy. Labels, addresses, public keys and the access history are
still sensitive metadata: agree on removing or masking them before handing
them outside.

## Updating and rolling back

`awg-tool update` is a **check**, not a download and not an install. Without
`--server`/`--host` it checks the CLI version on GitHub; with them, the nodes'
images too. Requests go over HTTPS from the CLI's machine to GitHub and Docker
Hub; network errors and a local image without a RepoDigest give `Unknown`, not
proof of being current.

For a real update:

1. Find how it was deployed: Compose or install's `docker run`. Record the
   current image digest and the container description without publishing
   secrets. A floating `latest` is not good enough as the only rollback point.
2. Agree on an outage window, make a protected copy of the configs and state,
   and keep the old image reachable. Update within the current generation's
   patch line; moving between generations is a separate migration of clients
   and configs.
3. For Compose, after agreement, from the deployment directory:

   ```bash
   docker compose pull server
   docker compose up -d server
   docker compose exec -T server awg-health
   ```

   `pull` downloads, `up` recreates with the same mounts and volumes. Never add
   `down -v`, and do not restart every neighbouring service without a reason.
4. For an install made with `docker run`, rebuild the exact mounts, env,
   ports, sysctls, volumes and restart policy from `docker inspect`. Do not pass
   off a generic `docker run` with empty state as an "update", and never use a
   repeat `awg-tool install`: it changes keys and the config.
5. Check a real client, the handshake and counters, DNS and the wanted traffic.
   On failure, bring back the old pinned image and the agreed set of configs
   and state; repeat the checks. Image rollback is not automatic (only `rotate`
   rolls back by itself).

If an old node carries a manual workaround that a new image now does itself
(for example a hand-made TCPMSS rule, done by the entrypoint since 0.5.1),
remove the manual one after the update, or the rule exists twice.

## Backup and restore

The CLI has no `backup` or `restore`. Use the usual filesystem and Docker
tools; do not add new shell wrappers to the project.

Keep one consistent set:

- the server's `server.conf` and private key (`/etc/amnezia/awg<generation>`
  for install, or your own bind mounts for Compose) and the `*.bak-*` copies
  `rotate` left;
- the state volume (`peers.d`, PSKs, the start counter); while peers change
  the copy can be inconsistent, so block changes during the copy or agree on a
  stop;
- the resolver's volumes (`awg-dns-state` with the `awg-tool dns` lists) and
  the `/etc/awg-dns` directory with your lists, records, zones and
  `chain.conf`;
- the deployment file, the image digest, ports, env, sysctls, the network
  layout;
- the log volume if policy needs it, minding how sensitive the access history
  is;
- client `.conf`s and links in a separate protected store if they may need
  importing again: the server does not keep client private keys;
- `profiles.json`, `known_hosts` and, only if the user decides so,
  `secrets.json` when moving the operator's workstation.

The copy is a secret, PSKs and HeaderProtectionKey included. Never attach it
to a contribution and never keep it in the checkout. Restore with the same
permissions, the same server key and the needed volumes; an empty new container
with the same name is not a restore. Check the peers and a real client before
calling it done. Do not delete the originals before a verified restore.

## Source map and contribution checks

| Path from the root | Area |
|---|---|
| `crates/awg-cli/src/main.rs` | Commands, the hand-written parser, gen, check, sets, hosts, under |
| `crates/awg-cli/src/ops.rs` | install, status/doctor/logs/update, peer, dns, rotate, servers, target choice |
| `crates/awg-cli/src/remote.rs` | Target parsing, host key trust, password prompts |
| `crates/awg-cli/src/tui.rs`, `tui/servers.rs` | The UI and the servers screen |
| `crates/awg-core/src/versions.rs`, `engines.rs`, `presets.rs` | Generations, clients, engines, presets, generator limits |
| `crates/awg-core/src/check.rs` | Checking finished configs, client quirk warnings |
| `crates/awg-core/src/mimic/` | Mimicry profiles and the host database |
| `crates/awg-core/src/deploy/` and `deploy.rs` | Rendering `.conf`, defaults, survey, deployment |
| `crates/awg-core/src/profile.rs`, `ssh.rs` | Connection profiles, password store, SSH |
| `crates/awg-core/src/docker/` | Discovery, health, peers, dns, rotate, redaction, diagnostics |
| `crates/awg-core/src/vpn.rs`, `update/`, `under.rs` | The vpn:// link (AmneziaVPN's own import format), update checks, under |
| `containers/entrypoint.sh`, `awg-peer`, `awg-*` | Start through UAPI, network and MSS clamp, peers, node utilities |
| `containers/entrypoint-dns.sh`, `unbound.conf`, `dns-chain/` | Resolver, lists, zones, chain |
| `containers/status-www/` | The .vpn pages and their CGIs |
| `containers/docker-compose.yml`, `README.md` | Example topology and the container reference |
| `CONTRIBUTING.md`, `RU.CONTRIBUTING.MD` | Contribution and check rules |

For Rust changes, the standard checks from the root:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

For container changes use the **existing** `containers/selftest.sh`,
`utiltest.sh`, `dnstest.sh`, `paralleltest.sh`. They run real tunnels and
traffic: they need Docker, TUN, privileges and a separate safe environment
(`AWG_IMAGE_PREFIX` for your own images). The `Live tunnel tests` workflow runs
them on GitHub on every generation. Never run them on someone else's
production host, and never call them passed from reading the README. A docs-only
change needs no VPN deployment: check the links, the real commands of the safe
part of the CLI, and the agent answer scenarios.

Update the reference when public behaviour changes. Do not freeze a current
limit as a permanent contract: check the source before operating. This skill
has no extra scripts; the commands use the existing tools.
