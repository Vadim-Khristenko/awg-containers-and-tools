---
name: server-audit
description: >-
  A fast, read-only security check of a server running awg-containers-and-tools:
  open and published ports, firewall, SSH access, users and sudo, Docker
  exposure, container privileges, secret files and their permissions, outdated
  kernel, Docker and images with known CVEs. Use it when the user asks whether
  a server is safe, what is open, who can get in, after an install, before
  handing a server to someone, or when something looks wrong. It finds and
  reports; it fixes nothing without consent.
---

# Server audit

Find what should not be there, prove each finding with output, and hand the
user a short list ordered by danger. Read-only: no command here changes the
server. Fixes are proposed, never applied without an explicit yes, and a
firewall or sshd change needs its own yes each time.

Talk to the user the way the `plain-talk` skill says. For operations of the
VPN itself use `awg-operations`.

## Before you start

- Confirm the host and how you reach it (`awg-tool servers`, or SSH the user
  gave you). Run as the user you were given; use `sudo -n` only where noted
  and only if it is already allowed. Never ask for the root password in chat.
- Say up front that the check is read-only and takes a few minutes.
- Do not install scanners on the server without consent. If `trivy` or
  `grype` is already there, use it; otherwise scan images from the user's own
  machine or CI.
- Output from these commands can hold addresses, user names and keys' public
  parts. Summarise; do not paste whole dumps into an issue.

## What to run

Run the blocks in order. Each line is read-only.

### 1. What listens and what is published

```bash
ss -tulpn                                   # every listening socket, with the process
docker ps --format '{{.Names}}\t{{.Image}}\t{{.Ports}}'
```

Expected for this project: the AWG UDP port(s) published, SSH, and nothing
else of ours. **Findings:**

| Seen | Why it matters |
|---|---|
| `:53` published (TCP or UDP) on `0.0.0.0` or a public address | The tunnel resolver is open to the internet: an open resolver for amplification, and it leaks that a VPN runs here |
| The pages container (`amnezia-wg-status`) with a published port | The .vpn pages are meant for tunnel clients only |
| `:2375` or `:2376` listening | Docker API over TCP: whoever reaches it is root |
| Databases, admin panels, `:8080`, `:3000` and similar on `0.0.0.0` | Check each one is meant to be public |
| A service bound to `0.0.0.0` that only needs `127.0.0.1` | Reduce the exposure |

Docker-published ports bypass a host firewall like `ufw` (Docker writes its
own iptables rules first). A port "closed in ufw" but published by Docker is
open.

### 2. Firewall

```bash
sudo -n nft list ruleset 2>/dev/null | head -100 || sudo -n iptables -S | head -100
sudo -n iptables -S DOCKER-USER 2>/dev/null
```

Look for: a default `ACCEPT` policy on `INPUT` with no rules, rules that open
more than the AWG port and SSH, an empty `DOCKER-USER` chain when Docker
publishes ports. Also remind the user about the cloud provider's firewall or
security group, which you cannot see from inside.

### 3. SSH

```bash
sudo -n sshd -T 2>/dev/null | grep -Ei '^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitemptypasswords|x11forwarding|allowtcpforwarding|maxauthtries|allowusers|allowgroups)\b'
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do [ -r "$f" ] && echo "$f: $(grep -cv '^\s*\(#\|$\)' "$f") keys"; done
sudo -n awk '{print $NF}' /root/.ssh/authorized_keys 2>/dev/null   # key comments only
last -n 20 -a 2>/dev/null; sudo -n lastb -n 20 2>/dev/null | head -20
```

**Findings:** `passwordauthentication yes` (brute force target),
`permitrootlogin yes` (prefer `prohibit-password` or a sudo user),
`permitemptypasswords yes` (critical), keys whose comment the user does not
recognise, logins from addresses the user does not recognise, heavy `lastb`
traffic with password auth on.

### 4. Users and privileges

```bash
awk -F: '$7 !~ /(nologin|false)$/ {print $1, $3, $7}' /etc/passwd
awk -F: '$3 == 0 {print $1}' /etc/passwd
getent group sudo wheel docker
sudo -n grep -rhv '^\s*\(#\|$\)' /etc/sudoers /etc/sudoers.d 2>/dev/null
```

**Findings:** more than one UID 0 account, users with a shell nobody can
explain, `NOPASSWD: ALL` for an account that logs in with a password, members
of the `docker` group (that is root, said plainly).

### 5. Containers

```bash
docker ps -q | xargs -r docker inspect --format \
  '{{.Name}} priv={{.HostConfig.Privileged}} net={{.HostConfig.NetworkMode}} caps={{.HostConfig.CapAdd}} drop={{.HostConfig.CapDrop}} sock={{range .Mounts}}{{if eq .Source "/var/run/docker.sock"}}MOUNTED{{end}}{{end}} restart={{.HostConfig.RestartPolicy.Name}}'
```

Expected for this project: AWG nodes with `NET_ADMIN` and `/dev/net/tun`, not
privileged, bridge networking; the resolver with `cap_drop ALL` and only
`NET_BIND_SERVICE`; the pages container unprivileged. **Findings:**
`priv=true` on anything, `docker.sock` mounted into a container that does not
need it (whoever controls that container is root), `net=host` on a container
that does not need it, extra capabilities like `SYS_ADMIN`.

### 6. Secrets on disk

```bash
sudo -n find /etc/amnezia -maxdepth 2 \( -name '*.conf' -o -name '*.key' -o -name '*.bak-*' \) -printf '%m %u %p\n' 2>/dev/null
docker ps -q --filter label=space.vai-rice.awg.protocol | xargs -r -I{} docker exec {} sh -c 'ls -l /tmp/uapi-set.req 2>/dev/null; echo "AWG_DUMP_REQUEST=${AWG_DUMP_REQUEST:-0}"'
ls -la ~/.config/awg-tool 2>/dev/null
```

**Findings:** a server config or key readable by group or others (anything
other than `600`, directory `700`), `AWG_DUMP_REQUEST=1` left on, or a
`/tmp/uapi-set.req` lying around (it holds the private key), `secrets.json`
present on a shared machine, old `*.bak-*` copies after a leak-driven rotation
(they hold the old block).

### 7. Versions and known vulnerabilities

```bash
uname -r; cat /etc/os-release | grep -E '^(PRETTY_NAME|VERSION_ID)='
docker version --format '{{.Server.Version}}'
docker ps --format '{{.Image}}' | sort -u
awg-tool update --server NAME        # from the user's machine: are our images current
```

Pending security updates, by family (read-only):

```bash
apt list --upgradable 2>/dev/null | grep -i securi   # Debian, Ubuntu
dnf -q updateinfo list --security 2>/dev/null        # Fedora, RHEL family
```

With a scanner already present: `trivy image --severity HIGH,CRITICAL <image>`
for each image in use. **Findings:** an end-of-life OS release, pending
security updates (above all the kernel and OpenSSH), a kernel older than the
distribution's current one with no reboot since the update (`needrestart -b`
if installed), images behind the current release, scanner hits with a fix
available. Report a CVE only with its ID and where it was found; never guess
that a version is vulnerable.

### 8. This project's own checks

```bash
awg-tool doctor --server NAME
awg-tool status --server NAME
```

Plus, from a tunnel client: `awg-leak` / `awg-tool under` and the `leak.vpn`
page. An AWG node whose `doctor` reports a refused config, or a resolver
answering from outside the tunnel, is a finding.

## Report

One table, most dangerous first, then one line on what was not checked.

| # | Severity | Finding | Evidence | Fix | Needs |
|---|---|---|---|---|---|
| 1 | critical | Docker API on `0.0.0.0:2375` | `ss -tlpn` line | Bind to the socket only, remove `-H tcp://` | restart of Docker, yes |
| 2 | high | Password SSH on, 3000 failed logins today | `sshd -T`, `lastb` | Keys only, `PasswordAuthentication no`, keep a second session open while testing | sshd change, yes |

Severity: **critical** gives control of the server or the tunnel to anyone who
finds it; **high** is likely to be found and abused; **medium** needs a second
mistake to hurt; **low** is hygiene. Do not inflate: a published AWG UDP port
is the product, not a finding.

## Fixing, when the user says yes

- One change at a time, with a way back stated before you start.
- Firewall and SSH: keep the current session open, open a second one to test,
  and never close the last way in. Add the allow rule for SSH before any
  default-drop policy.
- Never "fix" by deleting volumes, turning the firewall off, using
  `--privileged`, or killing a process you did not identify.
- After the fix, rerun the block that found the problem and show the clean
  output.
