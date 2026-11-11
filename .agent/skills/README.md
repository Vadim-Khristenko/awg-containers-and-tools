# Skills for AI agents

This directory holds project reference material in the Agent Skills format:
a `SKILL.md` with `name` and `description` in YAML, and more material in
`references/`. There are no executables or new scripts here; the instructions
use the existing `awg-tool`, `awg-peer` and Docker Compose.

The skills are written in English on purpose: the same instructions cost a
language model noticeably fewer tokens in English than in Russian, so more of
the agent's context is left for the actual task. An agent still answers in the
user's language.

## Available skills

| Skill | Scope |
|---|---|
| [awg-operations](awg-operations/SKILL.md) | Installing the CLI and servers over SSH and with Compose, AWG 1.0-3.1 configs, issuing and revoking clients, rotating obfuscation, the tunnel resolver and the .vpn pages, client quirks, diagnostics, updates and backups |
| [server-audit](server-audit/SKILL.md) | A fast read-only security check of a server: listening and published ports, firewall, SSH, users and sudo, container privileges, secrets on disk, outdated or vulnerable versions; a ranked report, fixes only with consent |
| [plain-talk](plain-talk/SKILL.md) | How an agent talks to the user: answer first, no filler, one recommendation, copyable commands, risks before actions, honest status |

## How to use

If your agent discovers `.agent/skills`, it picks a skill by the description in
`SKILL.md`. Discovery depends on the tool: the directory being there does not
guarantee it is loaded. To attach it by hand, ask the agent:

> Read `.agent/skills/awg-operations/SKILL.md` and use the reference sections
> it points to. Check the current state first, do not change the server
> without permission, and do not print secret configs into the chat.

For example:

- "Prepare an AWG 3.1 install on a VPS over SSH; Docker is not installed yet."
- "Add a phone to the existing server; all traffic should go through the VPN."
- "There is a handshake, but DNS and `amiunder.vpn` do not open; diagnose first."
- "Route `.geek` domains through the tunnel, leave the rest as it was."

## Keeping it current

When the CLI, the images or the config format change, update the matching part
of the skill in the same change as the code. The sources of truth are listed in
the reference; the most important are `crates/awg-cli/src/main.rs`,
`crates/awg-cli/src/ops.rs`, `crates/awg-core/src/versions.rs`,
`crates/awg-core/src/check.rs`, `crates/awg-core/src/vpn.rs`,
`crates/awg-core/src/deploy/`, `crates/awg-core/src/docker/`,
`containers/entrypoint.sh`, `containers/entrypoint-dns.sh`,
`containers/awg-peer` and `containers/docker-compose.yml`.

`awg-operations/evals/evals.json` holds scenarios for checking an agent's
answers. They do not start a VPN, need no secrets and do not replace the
project's live tunnel tests. To check the skill, give an agent the same request
with and without it and compare the commands, the safety and the completeness.
Keep run results and HTML reports outside the working tree and out of
contributions.

Developer guide: [CONTRIBUTING.md](../../CONTRIBUTING.md)
([по-русски](../../RU.CONTRIBUTING.MD)).
