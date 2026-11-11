# Adding, issuing and revoking clients

## Contents

- [Choosing the tool and checking first](#choosing-the-tool-and-checking-first)
- [Issuing a config](#issuing-a-config)
- [State and limits](#state-and-limits)
- [Importing and checking a device](#importing-and-checking-a-device)
- [Client quirks](#client-quirks)
- [Revoking, lost keys and rotating obfuscation](#revoking-lost-keys-and-rotating-obfuscation)

## Choosing the tool and checking first

There are two equal paths, and both call the same `awg-peer` utility inside the
node's container:

- `awg-tool peer add|list|rm` from this machine: locally (`--local`) or over
  SSH (`--server NAME`, `--host ADDRESS`), with `--container` to pick the node;
- `docker exec <container> awg-peer ...` on the server's Docker host.

Source of truth: `containers/awg-peer` and the peer restore in
`containers/entrypoint.sh`. For a non-root user on the server use the agreed
way into Docker; never add the user to the `docker` group on your own:
membership is effectively root.

Before changing anything:

1. Confirm the container, the generation and the interface
   (`awg-tool status`). The examples use `awg-server`; after `install` the name
   differs (`awg31-server` for 3.1 and so on).
2. Look at `awg-tool peer list` (or `awg-peer list`): the label must be new
   and the address free. Automatic allocation assumes a plain IPv4 `/24`.
3. Find out the app and its version on the device. Issuing takes no
   `--client` and does not fit the obfuscation block to Windows or a router.
   If the shared parameters do not suit the new client, choose a compatible app
   or an agreed change of the block for everyone (`awg-tool rotate`); never
   regenerate only the new file.
4. Find the public endpoint. For `AWG_ENDPOINT` it is **host:port**, unlike
   `awg-tool install --endpoint`, which takes a host without a port. In bridge
   mode give the published external port, even if the inner `ListenPort`
   differs. A node set up by `install` already knows its endpoint.
5. Decide full or split tunnel, and DNS. DNS `172.29.172.254` works only where
   the internal resolver is actually deployed and reachable from the server.
6. Make sure `/var/lib/awg` is on a volume, or that the agreed
   `AWG_STATE_DIR`/`AWG_PEERS_DIR` point to persistent storage. Otherwise the
   new access is lost when the container is recreated.

## Issuing a config

A label holds only `A-Z a-z 0-9 . _ -`, for example `alice-phone`. Use simple
names starting with a letter; no paths and no `..`. Create clients one at a
time: the utility does not lock against two allocations of one address.

### From this machine

```bash
awg-tool peer add alice-phone --out alice-phone.conf            # owner-only file
awg-tool peer add alice-phone --out alice-phone.conf --vpn       # plus a vpn:// link on stdout
awg-tool peer add router --mihomo                                 # plus a mihomo block
awg-tool peer list
```

Without `--out` the config goes to stdout; as an agent prefer `--out`, so the
secret stays out of the log. `--vpn` prints the link on stdout: that is a
secret too. The issued config is checked (`check`) before it is printed, and
findings go to stderr. Routes and DNS come from the node's variables (below);
for one issue with different routes use the `docker exec` path.

### On the Docker host: a full tunnel

This adds a **new** peer and saves its private config on the machine running
the Docker CLI. Put in the real endpoint.

```bash
umask 077
mkdir -p "$HOME/awg-client-configs"
chmod 700 "$HOME/awg-client-configs"
# Make sure no file with this name exists yet.
docker exec \
  -e AWG_ENDPOINT=vpn.example.com:51820 \
  -e AWG_CLIENT_DNS=172.29.172.254 \
  -e 'AWG_CLIENT_ALLOWED=0.0.0.0/0, ::/0' \
  awg-server awg-peer add alice-phone \
  > "$HOME/awg-client-configs/alice-phone.conf"
```

A full tunnel is always `0.0.0.0/0, ::/0`, both of them: see
[Client quirks](#client-quirks).

No `-t`/`-it` when redirecting: the config must reach a clean stdout, and the
diagnostic events go to stderr. Check the exit code. The shell creates and
truncates the file **before** the command runs, so never redirect a retried
failed issue into the only saved copy. An empty or partial file after an error
is not a working config.

Run on a VPS, the file stays on the VPS. Hand it to the device owner over a
private channel, or fetch it with SCP into a protected directory; never paste
it into an issue, a shared chat, a QR service or a public pastebin. The private
key is issued once: the protected copy is the operator's job, there is no
second export.

### Split tunnel with DNS and the pages

```bash
umask 077
docker exec \
  -e AWG_ENDPOINT=vpn.example.com:51820 \
  -e AWG_CLIENT_DNS=172.29.172.254 \
  -e 'AWG_CLIENT_ALLOWED=10.99.0.0/24, 172.29.172.0/24' \
  awg-server awg-peer add alice-laptop \
  > "$HOME/awg-client-configs/alice-laptop.conf"
```

`10.99.0.0/24` must match the server's real network. `AWG_CLIENT_ALLOWED`
replaces the whole list, it does not add to it. For a fixed address:
`awg-peer add alice-laptop 10.99.0.7`; check for a conflict first. A second
`add` for an existing label is refused: it is not an edit command.

`docker exec -e` variables apply to that one call; to apply them to every
future issue (and to `awg-tool peer add`), set them in the service's
`environment` and recreate the container in an agreed window, keeping the
state volume.

## State and limits

`awg-peer add`:

- reads `[Interface] Address` and looks for a free host `.2-.254` in the `/24`;
- checks what is taken against live UAPI, including peers from the original
  `.conf`;
- creates the client's key pair and PSK, and adds the peer through UAPI;
- saves `Label`, `PublicKey`, `Address`, `PresharedKey`, `Created` to
  `/var/lib/awg/peers.d/<label>.peer` (file `0600`, directory `0700`);
- puts the client's private key only into the issued `.conf`, does not keep it
  and has no second export;
- copies the obfuscation block from the server **file** whole, including 3.1's
  `RandomTrailers` and `DisableCookies`, not from live UAPI settings;
- adds `PersistentKeepalive = 25`, the MTU (from the server file, else 1280),
  DNS and routes from the variables;
- updates the names file, so the peer answers as `<label>.peer.vpn` and its
  address reads back as that name (when the `awg-names` volume is mounted).

The default `AllowedIPs` is `<tunnel>/24, <services>/24`: a **split tunnel**
with the resolver and the pages, not all internet traffic. The default endpoint
can stay the literal `SERVER_PUBLIC_IP:51820`; fix such a file before it goes
to a client. Since 0.5.1 `awg-peer` warns about it with a `!!` line on stderr,
and `awg-tool` refuses to build a `vpn://` link with the placeholder and asks
for `AWG_PUBLIC_HOST` or `AWG_ENDPOINT`.

Real limits of the current implementation:

1. Auto numbering takes the `/24` from the first three octets, not the real
   mask. With another mask, or IPv6, do not trust auto allocation.
2. An explicit IP is not fully checked against the subnet and what is taken;
   auto allocation checks exact `/32`s, not every possible `AllowedIPs`
   overlap.
3. If the server's address is not `.1`, check for a conflict with it too:
   the `.2-.254` scan does not reserve an arbitrary server address.
4. Changing parameters through raw UAPI without changing the server `.conf`
   puts future issues and the next start out of step.
5. The peer is added to the device before the file is written and the config
   printed. If the command broke off, check `list` and the persistent record:
   never repeat `add` blindly, and never leave an unknown working access.

## Importing and checking a device

1. Give the `.conf` only to the device owner. Import it into an app that
   supports the chosen AmneziaWG generation, not into plain WireGuard without
   AWG support. Menu names depend on the app and its version.
2. Make sure the endpoint is not a placeholder, the address is unique, and DNS
   and `AllowedIPs` fit the task. `awg-tool check <file>` names the known
   problems without changing anything; never copy secret lines into the chat.
3. Connect the device and make some traffic. On the server check
   `awg-tool peer list` or `awg-peer list`: expect a fresh handshake for
   exactly the new public key; `never` before the first connect is normal.
   `awg-watch` then logs `peer-first-handshake`.
4. From the client: `http://amiunder.vpn` (under the VPN or not),
   `http://leak.vpn` (does the browser resolve through the tunnel). On a
   computer `awg-tool under` checks the same without a browser and with an exit
   code. For a full tunnel check the external IPv4 on a trusted site; say
   beforehand if it is a third-party service.
5. Check system DNS, DoH and IPv6 separately. Server health does not prove a
   phone does not leak.

`vpn://` holds a private config: a compressed JSON packed into base64url,
**not encryption**. `awg-tool peer add --vpn` builds one for a new peer,
`awg-tool check vpn://...` reads and checks an existing one.

## Client quirks

Every quirk the project knows about a client is a warning in `awg-tool check`
or in `awg-peer`, never a silent fix. Pass it on to the user in plain words.

| Quirk | Effect | What the project does |
|---|---|---|
| AmneziaVPN applies its site lists ("Direct" / "Through VPN") only when `AllowedIPs` holds both `0.0.0.0/0` and `::/0` (`vpnConnection.cpp`, every platform including Android) | With one of the two the lists are dropped without a word | `check` warns (`conf.full_tunnel_one_family`) and `awg-peer` prints a `!!` line, since 0.5.5. Issue a full tunnel as `0.0.0.0/0, ::/0` |
| AmneziaVPN on Windows can bring the tunnel up with a larger MTU than the config says (1376 seen for a 1280 config) | TCP stalls on large segments: TLS to big sites hangs on 3.1 | A node with NAT clamps forwarded TCP to the tunnel's MTU since 0.5.1 (`AWG_MSS=auto`, `off` turns it off) |
| AmneziaVPN imports `vpn://` only in its own format (container `amnezia-awg`) | Links from awg-tool before 0.5.1 import with "no protocol installed" | Reissue the link with awg-tool 0.5.1 or newer. 3.x keys need client 5.0.0.2 or newer; 4.8 does not have them |
| AmneziaWG for Windows before 2.0.2, and wg-easy as a client, limit H1-H4 to under 2^31-1 | A newer block is refused | `--client-release` / `--client` when generating, and `check --client` |
| AmneziaVPN keeps `HeaderProtectionKey` to itself and does not write it into an exported file; protection is switched on in the server's protocol settings, and the client's box is read-only | An imported config without the key cannot turn protection on, and plain H1-H4 (`--disable-h`) would then go out in the clear | Say it when a 3.x config is moved between AmneziaVPN and other clients; issue 3.x configs from the node (`awg-peer`), which writes the key |
| AmneziaVPN refuses to save equal padded sizes (S4 + 32 included) | The settings will not save | The generator never emits them; `check` reports `s.size_collision` |
| mihomo reads 3.x fields only with `version: 3` | Without it mihomo silently runs the old protocol | `gen --mihomo` and `peer add --mihomo` write it |
| The kernel module (`awg setconf` over netlink) fails with "message too long" when the I1-I5 chains overflow one netlink page | The interface does not come up | The generator keeps chains inside the budget for `--server-engine kmod` |
| WireSock does not send I1-I5 chains | A block that relies on them is not mimicry on that client | Configs for `--client wiresock` leave them out |
| Every client has its own caps on S4, Jc and H | Over the cap is an error for that client only | `gen --client` stays inside them; `check --client` names the overflow |
| An endpoint left as `SERVER_PUBLIC_IP` | No client can connect | `awg-peer` warns, `check` warns (`conf.peer_endpoint_placeholder`), `vpn://` is refused |

When you meet a new quirk, name it to the user and suggest adding it to the
table and to `check` in the same change.

## Revoking, lost keys and rotating obfuscation

After explicit permission to revoke a specific client:

```bash
awg-tool peer list
awg-tool peer rm alice-phone
awg-tool peer list
```

`rm` takes a label **or a base64 public key**. Check the exact match before
running it. For a dynamic peer it removes the live peer and the `peers.d`
record. Confirm the public key is gone after the operation and, if a restart
was agreed, after that too.

`(unlabelled)` in the list can be a peer from the mounted server `.conf`.
`rm <public-key>` removes it only from the live device; the entrypoint brings
it back on start. To revoke it for good, remove exactly that `[Peer]` from the
persistent server file, check there is no copy in `peers.d`, then apply the
change in an agreed window. Never clear all peers and never delete the volume.

A lost client private key cannot be recovered from the public key or the PSK
on the server. Revoke the old peer, create a new one, hand over the new `.conf`
and check the handshake.

### Rotating obfuscation for everyone

When `HeaderProtectionKey` or the obfuscation block has leaked, or as a planned
change:

```bash
awg-tool rotate --dry-run       # what changes and which clients need the new block
awg-tool rotate --out block.conf
```

Rotation changes everything the two sides agree on and leaves the server's key,
address, port and peers alone. The config is found through the container's
mount, a backup `<file>.bak-<time>` is written next to it, the node restarts,
and if it is not up within 30 seconds the old config comes back. No private
keys travel over SSH. Before running it, name the node and warn: every client
stops connecting until it gets the new block (`--out` writes it to an
owner-only file). `--yes` skips the prompt; use it only after explicit consent.
Rotation works when the config is mounted from the host (`install` and Compose
do this). If the **server private key** has leaked, rotating obfuscation is not
enough: the server key has to change in an agreed way and every client has to
be reissued.
