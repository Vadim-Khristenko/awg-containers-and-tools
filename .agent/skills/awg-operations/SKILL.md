---
name: awg-operations
description: >-
  Installing, configuring and running awg-containers-and-tools specifically:
  awg-tool, Docker Compose, AmneziaWG 1.0/1.5/2.0/3.0/3.1, generating and
  checking parameters, SSH deployment, saved connections, issuing and revoking
  clients (awg-tool peer, awg-peer), changing obfuscation (awg-tool rotate),
  the tunnel resolver (lists, zones, chain, awg-tool dns), the .vpn pages and
  diagnostics. Use this skill for any request about installing this project,
  .conf or vpn:// configs, new devices, handshake, DNS, routing or MTU trouble,
  or updating a server, even when the user never says "skill".
---

# AmneziaWG: agent reference

Work with the project's existing tools. Do not invent new scripts, commands or
a management layer. This is an unofficial community project, not the official
AmneziaVPN installer. Answer in the user's language; this reference is in
English to keep it short in tokens, and commands and identifiers are as they
appear in the code.

## Map

`references/...` paths are relative to this `SKILL.md`; `containers/...`,
`crates/...` and `README.md` are relative to the repository root.

| Task | Read |
|---|---|
| Building the CLI, requirements, a new server, SSH, saved connections, Compose | [references/installation.md](references/installation.md) |
| Choosing a version and a client, generating, checking, `.conf`, variables, DNS, routes | [references/configuration.md](references/configuration.md) |
| A new device, keeping its config, full or split tunnel, revoking access, rotating obfuscation, client quirks | [references/clients.md](references/clients.md) |
| Status, doctor, logs, node utilities, .vpn pages, updates, backups, contributing | [references/operations.md](references/operations.md) |
| Scenarios for checking an agent's answers | [evals/evals.json](evals/evals.json) |

Read only what the task needs, but before adding a client read the issuing
limits in `clients.md`: they decide security and compatibility.

Generator switches take a value: `--random-trailers off`, `--disable-h off`,
`--header-protection on`. A flag with no value turns the switch on. Choosing
`--version` applies that version's preset first (for 3.1: MTU 1280,
`RandomTrailers` on, H1-H4 = 1..4); flags change only what they name.

## How to work

1. **Pin down the task and the context.** Instructions or execution? A new
   server or an existing one? Local Docker, a server over SSH, or an app on a
   phone? Do not run an install to answer a question.
2. **Observe first.** Find the Compose file in use, the container name and
   image, the protocol generation, the interface, the published UDP port, the
   state volume and the real endpoint. Use `awg-tool status --local`,
   `--server NAME` or `--host ADDRESS`. Never print configs with keys into the
   chat.
3. **Pick one path.** Remote install: `awg-tool install`. Manual container
   install: Compose. A new device on a running node: `awg-tool peer add` (or
   `awg-peer` inside the container), not a new `install` or `gen`. New
   obfuscation on a running node: `awg-tool rotate`.
4. **Check current behaviour.** `awg-tool --help` and the checked-out source
   beat examples in the docs. The CLI has a hand-written parser: an unknown
   flag in a command proves nothing about it working. Do not invent `export`,
   `backup`, `restore`, `install --out` or `install --dns`.
5. **Ask only for what the environment cannot tell you.** A real deployment
   needs the target host and SSH, an endpoint clients can reach, the port, the
   client app, and full or split tunnel. Never ask the user to send private
   keys.
6. **Change things only after the risk is agreed.** Installing packages or
   Docker, overwriting the server `.conf`, rotating obfuscation, opening the
   firewall, restarting, revoking a peer and deleting data all touch access.
   Name the exact node, the change and the possible outage. "How do I install"
   is not permission to run commands on a server. `rotate --yes` skips the
   prompt: pass it only after explicit consent.
7. **Verify at the right end.** `errno=0` means the daemon accepted the config;
   `healthy` means the interface and UAPI are alive. A working VPN is a
   handshake after traffic, moving rx/tx, DNS, and reaching the wanted resource
   from a real client (`awg-tool under` on that machine, the `amiunder.vpn` and
   `leak.vpn` pages). A built CLI is not a successful remote install.

## Invariants

- Match the image generation, the allowed keys and the client app. Never put
  3.1 fields into 3.0. For old client builds use `--client-release` (for
  example the H limit in AmneziaWG Windows before 2.0.2).
- One server config uses one agreed obfuscation block. Do not generate a new
  one per added device. To change it for everyone: `awg-tool rotate`, and then
  every client needs the new block.
- An issued `.conf` or `vpn://` is a secret. PrivateKey, PSK,
  HeaderProtectionKey, SSH passwords and raw UAPI never go into Git, an issue
  or an answer.
- Keep `/var/lib/awg` and the original server config: a live peer with no
  persistent source disappears when the container is recreated. For a peer
  that lives in the `.conf`, `awg-peer rm` alone is not enough: the entrypoint
  restores it on the next start.
- Do not expose the internal DNS or the pages to the outside, and do not
  promise a full kill switch: the DNS bridge isolation does not control
  fallback, DoH or IPv6 on the device. Check with `awg-tool under`,
  `awg-leak` and the `leak.vpn` page.
- Never fix a problem with `--privileged`, by turning off the firewall or SSH
  host key checks, by deleting volumes, with `curl | sh`, or by running someone
  else's installer.
- Do not change code to get around a limit when the request is operational.
  Explain the limit and choose a supported path; no new scripts.
- Every known client quirk is a warning, not a surprise. `awg-tool check` and
  `awg-peer` name the ones the project knows (see "Client quirks" in
  `clients.md`); pass them on to the user.

## Answer format

For instructions: the chosen path and its prerequisites, then the commands with
where to run them, the result to check, and what to do on the typical error.
Keep examples apart from commands meant to run; never leave dummy keys in a
file you suggest running right away.

After acting: name the node or container, what changed, where the secret
artefact is stored (not its content), which checks actually ran and what could
not be checked. For a fault: what was observed, the confirmed cause or the
hypotheses, the smallest next check. Missing data is not a confident
diagnosis.
