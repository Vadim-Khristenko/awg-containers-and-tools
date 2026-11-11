# Installing the CLI and a server

## Contents

- [Choosing a path and requirements](#choosing-a-path-and-requirements)
- [Getting awg-tool](#getting-awg-tool)
- [A new server over SSH](#a-new-server-over-ssh)
- [Saved connections](#saved-connections)
- [A manual server with Compose](#a-manual-server-with-compose)
- [Several servers and building images locally](#several-servers-and-building-images-locally)

## Choosing a path and requirements

| Need | Approach |
|---|---|
| Only obfuscation parameters | `awg-tool gen`; no Docker or SSH needed |
| Check someone's `.conf` or `vpn://` | `awg-tool check`; changes nothing |
| A new remote server of any generation with a first client | `awg-tool install` over SSH, with the limits below |
| Internal DNS, the .vpn pages, an own subnet, a managed Compose | The manual container path |
| One more device on a running server | [clients.md](clients.md), not a reinstall |
| Only understand the state | [operations.md](operations.md), no reinstall |
| Check a server for holes (ports, access, versions) | the `server-audit` skill |

A container server needs a Linux host with Docker, `/dev/net/tun`,
`NET_ADMIN`, IPv4 forwarding, a **UDP** port clients can reach, and tunnel and
bridge subnets that do not overlap existing networks. Compose needs the
`docker compose` plugin. Do not assume rootless Docker, a restricted VPS or
LXC, or a missing TUN are supported: check the host's capabilities first.

Do not deploy a VPN on a development machine just to try the docs. Running on
a production server needs an explicit choice of host and agreed system
changes. Never turn off the firewall wholesale; the UDP port rule and a cloud
security group or NAT are checked separately, without risking SSH access.

## Getting awg-tool

For a published release, take the binary for the platform from the Releases
page of **this** repository. Names by platform:
`awg-tool-x86_64-unknown-linux-gnu`, `awg-tool-aarch64-unknown-linux-gnu`,
`awg-tool-aarch64-apple-darwin`, `awg-tool-x86_64-pc-windows-msvc.exe`.
Download the checksum file, check the SHA-256, then make it executable and put
it in a directory on PATH. Do not guess the URL or the latest release number.
Example check:

```bash
sha256sum -c checksums-v0.5.1.sha256
```

The checksum proves the file arrived intact, not who built it: the binaries are
not signed. If the checksum file lists several files, check the line of the
chosen one; other files being absent does not confirm the chosen one.

From source, at the checkout root:

```bash
cargo build --release -p awg-cli --locked
./target/release/awg-tool --help
```

Needs Rust 1.90+ (edition 2024), a native compiler and the dependencies' build
tools. OpenSSL is built vendored, no system OpenSSL is needed, and SSH on every
platform goes through that OpenSSL. On Windows/MSVC you need the MSVC
environment and native Strawberry Perl ahead of MSYS2/Cygwin Perl on PATH (Git
Bash's perl fails the OpenSSL build). A first vendored OpenSSL build takes a
long time; that is not a hang. Docker is not needed to build the CLI or to
generate.

Without installing the binary:

```bash
cargo run -p awg-cli -- gen --version 3.1
cargo run -p awg-cli -- clients
```

Running with no arguments opens the UI only when stdin and stdout are
terminals; otherwise it prints help. General help: `awg-tool --help` or
`awg-tool help`. `--version` is the protocol version to generate, not a way to
see the binary's version (the first line of `--help` prints it). Write flags
after the command and apart: `--flag VALUE`, not `--flag=VALUE`.

## A new server over SSH

### Decide first

Settle the SSH host, port and user, the login method (agent, key, password),
whether sudo is needed, the public address for the endpoint, a free UDP port
and the protocol generation. `--host` is the SSH address; `--endpoint` is the
address **for VPN clients**, and they can differ. Behind NAT the endpoint
cannot be reliably derived from the default route's private address.

An example for a new server; the values are documentation ones, use real ones:

```bash
awg-tool install \
  --host 203.0.113.9 \
  --user root \
  --key "$HOME/.ssh/id_ed25519" \
  --version 3.1 \
  --endpoint vpn.example.com \
  --listen-port 51820 \
  --pull
```

For a non-root user with the needed sudo add `--sudo`. For agent auth leave
out `--key`. For a password login there is `--password` with no value: the
password is asked without echo; never pass it in arguments or shell history. A
key with a passphrase: `--key PATH --key-passphrase`.

### What the command does

1. Connects over SSH (port 22, user root by default). For an unknown host key
   it shows the fingerprint and asks `[y/N]`. Check the fingerprint through a
   trusted channel before agreeing. A mismatch is a refusal, not a reason to
   delete `known_hosts` or turn the check off.
2. Checks the distribution, `docker`, `iptables`, `ip`, `curl`, Docker access,
   sudo, routes and IPv4 forwarding. No external IP lookup service is called:
   the endpoint comes from the route's `src`. That can give a private address
   or nothing; set `--endpoint` explicitly when needed.
3. For missing packages it prints the exact command and asks `[y/N]`. The
   apt/dnf/pacman/zypper/apk/xbps/emerge families are picked by OS and
   `ID_LIKE`. NixOS and unknown systems are not "fixed" with a random package
   manager.
4. Checks whether the UDP port is taken; a taken port is a refusal naming the
   owner, never killing the process. `--listen-port` picks another port.
5. With no image and no `--pull` it stops; `--pull` allows downloading it. It
   does **not** update an image already there.
6. Generates keys and parameters, writes the server config, recreates the
   container of that generation and checks the interface comes up.
7. Prints the endpoint, the container name, the full first client `.conf` and
   the `vpn://` link. Keep both as secrets. This does not yet prove a handshake
   with a real device.

### The real install contract

| Setting | Current value and options |
|---|---|
| Generation | `--version` (default 3.0); every `gen` flag works, the mimicry name is `--mimic-host` |
| Container | `awg1-server`, `awg15-server`, `awg2-server`, `awg3-server`, `awg31-server` by generation; `--name` changes it |
| Image | `vaiprog/amnezia-wg-1/15/2/3/31:latest` by generation; `--image` overrides |
| Config on the host | `/etc/amnezia/awg1`, `awg15`, `awg2`, `awg3`, `awg31`: `server.conf` and `server.key` |
| Tunnel | `awg0`, server `10.8.1.1/24`, first client `10.8.1.2/32` |
| MTU | `1420`, `1280` for 3.1 (the version preset) |
| First client DNS | `1.1.1.1, 8.8.8.8`; install does not deploy the internal resolver or the pages |
| First client AllowedIPs | `0.0.0.0/0, ::/0`; the IPv6 line does not prove IPv6 works |
| Keepalive | `25` |
| Endpoint | `--endpoint HOST` **without `:PORT`**; the port comes from `--listen-port` |
| Export | Only the shared stdout; `install --out` and `--json` do not exist |

Do not invent `--dns`, `--allowed-ips`, `--conf-dir`, `--yes` or
`--non-interactive` for install: the handler does not implement them, and the
hand-written parser can silently ignore an extra flag.

`server.conf` and `server.key` in the generation's directory are secrets: the
directory is `0700`, the config `0600`. The directory is mounted read-only into
the container. Named volumes: `<name>-state:/var/lib/awg` and
`<name>-log:/var/log/awg`. The container gets `AWG_CONF`, `AWG_IFACE`,
`AWG_ENDPOINT`, TUN, NET_ADMIN, the IPv4 sysctl and a UDP publish; no host
networking and no `--privileged`.

**Reinstalling the same generation is dangerous:** it overwrites that
generation's `server.conf`/`server.key` and runs `docker rm -f` on the
container with no final confirmation and no automatic backup. It is not adding
a client and not a safe update. New devices are `awg-tool peer add`, new
obfuscation is `awg-tool rotate`. Different generations live in different
directories and containers, so they can share a host, with different
`--listen-port`s.

`install > client.conf` saves a mix of status lines, the config and the link,
not a clean importable `.conf`. As an agent, send the whole stdout to a new
protected file outside the repository (`umask 077`), then cut the client block
out with an editor without printing secrets. Treat the output of a failed
install as sensitive too: it can hold tails of Docker logs.

### Preparation and known limits

- Needs a running Docker daemon: the CLI does no generic `enable/start` after
  installing the package. If it is not available, fix the service the usual
  way for that OS first.
- Missing packages are installed through sudo even for root. On a minimal host
  without `sudo`, install the packages beforehand, as agreed, with the right
  manager.
- Install does not set up persistent forwarding on the host. Check forwarding
  and the firewall explicitly; the container's `net.ipv4.ip_forward=1` does not
  replace the host's settings.
- On NixOS, missing tools get a declarative hint, for example
  `virtualisation.docker.enable = true;` and the packages
  `iptables iproute2 curl`. Changing the configuration and rebuilding happen
  separately, after agreement.
- SSH is a library, not the system `ssh`: aliases, ProxyJump and IdentityFile
  from `~/.ssh/config` are not read. Key paths must be expanded or absolute. A
  `.pub` next to the key is used. Do not promise it works through a bastion
  without separate setup.
- There is no unattended flag. It needs a host key trusted in advance, a
  working login, root/NOPASSWD or the sudo password, and no package manager
  questions.
- `--name`, `--image` and `--endpoint` end up in remote shell commands. Use
  simple trusted values without spaces, shell metacharacters or substitutions.

## Saved connections

`awg-tool profiles` are **mimicry** profiles, not SSH servers. Connections are
kept by `awg-tool servers`:

```bash
awg-tool servers add home --host 203.0.113.9 --user root --key ~/.ssh/id_ed25519
awg-tool servers add box --host 192.0.2.10 --user admin --password --store-password --sudo
awg-tool servers            # list
awg-tool servers rm box     # remove, together with the saved password
```

Then `--server home` works in `status`, `doctor`, `logs`, `peer`, `dns`,
`rotate` and `install`, and the servers screen in the UI lists them. The key
path is saved absolute. A password is saved **only** with `--store-password`,
into a separate unencrypted `secrets.json` (not a vault or a keyring); a key
passphrase is never saved. Never save a password without the user's explicit
decision. Install does not save the connection itself.

Directory: `$XDG_CONFIG_HOME/awg-tool`, else `$HOME/.config/awg-tool` on Unix;
on Windows without XDG, `%APPDATA%/awg-tool`. The directory is `0700`, the
files `0600`. Unknown fields in `profiles.json` are refused: a password cannot
be written there.

`--server home` picks the whole profile; `--user`, `--key` and `--sudo` do not
override it. `--server` together with `--host` is an error. With no explicit
target a single profile is picked by itself, several need a choice; with no
profiles and our containers running on this machine, the answer is local. For
local containers it is safer to always write `--local`.

The UI connects to profiles with no password or a saved one; for the others it
suggests the CLI command.

## A manual server with Compose

This path gives the internal resolver, the .vpn pages and an explicit choice
of generation, MTU and routes. Run it on a prepared server from the checkout's
`containers/` directory. The stock `docker-compose.yml` is a **server +
client** demo with the resolver and the pages, not a ready VPS config with your
keys.

1. Check `docker version`, `docker compose version`, TUN, a free UDP port
   51820, and that `10.99.0.0/24`, `172.31.99.0/24`, `172.29.172.0/24` do not
   overlap existing networks.
2. Generate one parameter block for the generation and the target client.
   After building the CLI, from `containers/`:

   ```bash
   ../target/release/awg-tool gen --version 3.1 --client amneziavpn --out params.conf
   ```

   `--out` creates an owner-only file: a 3.x block holds the secret
   `HeaderProtectionKey`.
3. Make the server key pair with the image's own tool, not a third-party
   generator. For example, after an agreed image download:

   ```bash
   umask 077
   docker run --rm --entrypoint awg vaiprog/amnezia-wg-31:latest genkey > server.key
   docker run --rm -i --entrypoint awg vaiprog/amnezia-wg-31:latest pubkey < server.key > server.pub
   ```

   Never print the private key into a shared log. Write `server.conf` with
   `[Interface]`, that `PrivateKey`, `Address = 10.99.0.1/24`,
   `ListenPort = 51820`, `MTU = 1280` and the block from `params.conf`. The
   format is in [configuration.md](configuration.md). Issuing through
   `awg-tool peer` or `awg-peer` needs no initial `[Peer]`; do not add dummy
   keys.
4. Give the server the image of the right generation
   (`vaiprog/amnezia-wg-31` for 3.1) and the mount
   `./server.conf:/etc/amnezia/awg/awg0.conf:ro`. Keep the named volumes
   (`awg-state`, `awg-log`, `awg-names`, and the resolver's `awg-dns-state`,
   `awg-dns-public`), `NET_ADMIN`, TUN, the sysctl, the UDP publish, the
   server's link to the DNS bridge, and the resolver's
   `cap_add: [NET_BIND_SERVICE]`. Another generation needs the matching image
   **and** a compatible parameter block.
5. On a real VPS do not run the demo `client`: drop it from your own file or
   start only the services you need. Keep bridge mode and the published UDP
   port unless there is a reason to change the network model. You cannot just
   turn on `network_mode: host` next to the old `networks` and assume the DNS
   bridge is still reachable.
6. Check the syntax and start the services:

   ```bash
   docker compose config --quiet
   docker compose up -d dns server status
   docker compose ps
   docker compose exec -T server awg-health
   ```

   `config --quiet` does not print the resolved config. A full
   `compose config` can expose secrets substituted from another deployment
   file.
7. Issue a separate real client with the right endpoint and routes, per
   [clients.md](clients.md). Without `AWG_ENDPOINT` or `AWG_PUBLIC_HOST` the
   issue keeps `SERVER_PUBLIC_IP` (and `awg-peer` warns); the default routes
   are a split tunnel, not all internet traffic.
8. After the import check the handshake, DNS and the wanted traffic from the
   device (`amiunder.vpn`, `leak.vpn`). Only then is the install confirmed.

The demo pair also needs a full `client.conf` with its keys, a server
`[Peer]`, matching parameters and the internal endpoint; a plain
`docker compose up -d` tries to start that client too. Do not suggest that
command when only the server file is ready.

## Several servers and building images locally

Several generations run as separate containers with unique ports, tunnel and
bridge subnets, names and state/log volumes. If the interfaces share one host
namespace, they need unique names and routing marks/tables (by default these
come from the listen port). `awg-tool install` of different generations
already keeps containers and config directories apart; reinstalling **one**
generation with another `--name` still writes to the same directory.

Building images from source, from `containers/`:

```bash
./build.sh 3.1
./build.sh dns status
./build.sh
```

The last one builds all five generations, the resolver and the pages;
`AWG_IMAGE_PREFIX` sets your own prefix. A local build publishes nothing.
Publishing to a registry is the owner's separate action, not part of an
install. Checks for container changes are in [operations.md](operations.md).
