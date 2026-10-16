# AmneziaWG DNS: a resolver that only answers through the tunnel

> **Unofficial community build.** Not affiliated with, endorsed by or supported by AmneziaVPN. Report problems at [the project repository](https://github.com/Vadim-Khristenko/awg-containers-and-tools/issues), not upstream.

A small `unbound` image meant to sit beside an [AmneziaWG server](https://hub.docker.com/u/vaiprog) on a private bridge, at the address AmneziaVPN's own clients already expect, with lists, your own records, forwarded zones and a resolver chain.

| | |
|---|---|
| Resolver | unbound, plus awg-dns-chain |
| Base | Alpine |
| Size | ~20 MB |
| Address | `172.29.172.254` |
| Platforms | `linux/amd64`, `linux/arm64` |
| Source | [Vadim-Khristenko/awg-containers-and-tools](https://github.com/Vadim-Khristenko/awg-containers-and-tools) |
| Licence | MIT |

## The point

Most "DNS leak protection" means the tunnel's resolver is *preferred*. That still leaves a failure mode where a query slips past the tunnel and is answered by the network you were trying to avoid: quietly, correctly, and invisibly.

This container is placed so that cannot happen. It lives on a dedicated bridge network. It publishes no port. Nothing else joins that bridge except the AmneziaWG server. So a client configured with `DNS = 172.29.172.254` can only reach it through the tunnel, and a query that escapes reaches nothing at all and fails visibly.

Failing loudly beats leaking silently.

## Use it

It is not meant to run alone. Take the `docker-compose.yml` from the repository, which wires the resolver, the server, the pages and the networks together. The resolver's part:

```yaml
services:
  dns:
    image: vaiprog/amnezia-wg-dns:latest
    cap_drop: [ALL]
    read_only: true
    tmpfs:
      - /var/log/unbound
      - /run/awg-dns:uid=100,gid=101
    volumes:
      # - ./dns:/etc/awg-dns:ro                 # lists, records, zones, the chain
      - awg-names:/var/lib/awg-names:ro          # the node's peer names
      - awg-dns-state:/var/lib/awg-dns           # what `awg-tool dns block|allow` writes
      - awg-dns-public:/var/lib/awg-dns-public   # counters for the dns.vpn page
    networks:
      dns:
        ipv4_address: 172.29.172.254

networks:
  dns:
    ipam:
      config:
        - subnet: 172.29.172.0/24
```

It answers UDP/53 and needs no privileges to do it, so it drops every capability, runs as its own user and keeps a read-only root filesystem.

Then point clients at it:

```
DNS = 172.29.172.254
```

## What it does

- Resolves from the root itself when the root answers from your network, over DoT to Cloudflare and Quad9 when it does not (`AWG_DNS_MODE=auto`), with DNSSEC validated.
- Blocks names from lists you mount or name by URL, lets an allowlist through, and answers your own records and names in the tunnel's `.vpn` zone, including every peer as `<label>.peer.vpn`.
- Sends single zones to resolvers you name (`forward.d`), the router's `home.arpa.` or another root's `.geek` alike.
- With a `chain.conf`, asks resolvers in order and moves on when one says nothing, SERVFAIL, REFUSED, NXDOMAIN, or only `0.0.0.0` and `127.0.0.1`: `default` first and OpenNIC second resolves everything as before and also what the real root does not have.
- Keeps Firefox (and, if you ask, iCloud Private Relay) from resolving around it.
- Picks up every change within seconds without a restart, and checks every generated config before using it, so a bad file cannot take it down.

Every directory, file and variable is described in the repository's [containers/README.md](https://github.com/Vadim-Khristenko/awg-containers-and-tools/blob/main/containers/README.md#dns).

## Verifying the isolation

The repository ships `containers/dnstest.sh`, which checks the claim from three directions rather than one: that a query through the tunnel is answered, that the same query times out from a neighbouring network, and that a bystander container can still reach the server's transport address, so a pass means isolation rather than a network that is simply dead. It then checks the lists, records, pages and the chain from inside the tunnel.

## Tags

`latest` tracks the newest release. Version tags such as `v0.5.0` are immutable: pin one if you want reproducible deployments.
