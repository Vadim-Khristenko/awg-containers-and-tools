# AmneziaWG DNS — a resolver that only answers through the tunnel

> **Unofficial community build.** Not affiliated with, endorsed by or supported by AmneziaVPN. Report problems at [the project repository](https://github.com/Vadim-Khristenko/awg-containers-and-tools/issues), not upstream.

A small `unbound` image meant to sit beside an [AmneziaWG server](https://hub.docker.com/u/vaiprog) on a private bridge, at the address AmneziaVPN's own clients already expect.

| | |
|---|---|
| Resolver | unbound |
| Base | Alpine |
| Size | ~20 MB |
| Address | `172.29.172.254` |
| Platforms | `linux/amd64`, `linux/arm64` |
| Source | [Vadim-Khristenko/awg-containers-and-tools](https://github.com/Vadim-Khristenko/awg-containers-and-tools) |
| Licence | MIT |

## The point

Most "DNS leak protection" means the tunnel's resolver is *preferred*. That still leaves a failure mode where a query slips past the tunnel and is answered by the network you were trying to avoid — quietly, correctly, and invisibly.

This container is placed so that cannot happen. It lives on a dedicated bridge network. It publishes no port. Nothing else joins that bridge except the AmneziaWG server. So a client configured with `DNS = 172.29.172.254` can only reach it through the tunnel — and a query that escapes reaches nothing at all and fails visibly.

Failing loudly beats leaking silently.

## Use it

It is not meant to run alone. Take the `docker-compose.yml` from the repository, which wires the resolver, the server and the two networks together:

```yaml
services:
  dns:
    image: vaiprog/amnezia-wg-dns:latest
    cap_drop: [ALL]
    read_only: true
    tmpfs: ["/var/log/unbound"]
    networks:
      dns:
        ipv4_address: 172.29.172.254

networks:
  dns:
    ipam:
      config:
        - subnet: 172.29.172.0/24
```

It answers UDP/53 and needs no privileges to do it, so it drops every capability and runs with a read-only root filesystem.

Then point clients at it:

```
DNS = 172.29.172.254
```

## Verifying the isolation

The repository ships `containers/dnstest.sh`, which checks the claim from three directions rather than one: that a query through the tunnel is answered, that the same query times out from a neighbouring network, and that a bystander container can still reach the server's transport address — so a pass means isolation rather than a network that is simply dead.

## Tags

`latest` tracks the newest release. Version tags such as `v0.1.0` are immutable — pin one if you want reproducible deployments.
