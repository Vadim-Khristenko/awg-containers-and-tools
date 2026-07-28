# AmneziaWG server/client — unofficial, one image per protocol generation.
#
# Upstream ships no self-hosted 3.0: their server pipeline drives awg-quick, and
# amneziawg-tools (released tags *and* master) still parses only the 2.0 keys.
# The daemon does support 3.0 — header_protection_key, content_padding_addition
# and the timer ranges are all accepted over UAPI — so this image configures the
# device through the UAPI socket instead of writing a .conf the tools cannot
# read. The same entrypoint then serves every generation, which is why there is
# one Dockerfile and a build arg rather than four near-identical files: the only
# thing that actually differs between the four images is the daemon tag.
#
#   AWG 1.0  -> amneziawg-go v0.2.12                 Jc/Jmin/Jmax, S1/S2, fixed H1-H4
#   AWG 1.5  -> amneziawg-go v0.2.14-beta-awg-1.5-1  + I1-I5 special junk, Itime
#   AWG 2.0  -> amneziawg-go v0.2.19                 + S3/S4, H1-H4 as ranges, tagged I chains
#   AWG 3.0  -> amneziawg-go v3.0.2                  + HeaderProtectionKey, ContentPaddingAddition, timer ranges
#
# Tags verified against `git ls-remote` and the `case "..."` list in
# device/uapi.go at each tag; see containers/README.md.
ARG AWG_GO_VERSION=v3.0.2
ARG AWG_TOOLS_VERSION=v1.0.20260618-2

# 1.25 is the floor: amneziawg-go v3.0.2's go.mod still says `go 1.25.0`, and
# the Makefile builds with GOTOOLCHAIN=local, so a 1.24 image fails outright.
# 1.26 is what is actually used — it satisfies the floor and also builds the
# older tags, whose go.mod ask for 1.22/1.24.
FROM golang:1.26-alpine AS build
ARG AWG_GO_VERSION
RUN apk add --no-cache git make bash gcc musl-dev linux-headers
WORKDIR /src
RUN git clone --depth 1 --branch ${AWG_GO_VERSION} https://github.com/amnezia-vpn/amneziawg-go.git . \
 && make \
 && install -m 0755 amneziawg-go /out-awg-go

# awg is carried only for key material (curve25519 + psk), which no AWG
# generation changed. It is deliberately NOT used to bring the interface up.
FROM alpine:3.24 AS tools
ARG AWG_TOOLS_VERSION
RUN apk add --no-cache git make gcc musl-dev linux-headers bash
WORKDIR /t
RUN git clone --depth 1 --branch ${AWG_TOOLS_VERSION} https://github.com/amnezia-vpn/amneziawg-tools.git . \
 && make -C src \
 && install -m 0755 src/wg /out-awg

FROM alpine:3.24
ARG AWG_GO_VERSION
ARG AWG_TOOLS_VERSION
ARG AWG_VERSION=3.0
# Stamped by build.sh. The default is the epoch rather than "now", because a
# Dockerfile that reads the clock is a Dockerfile whose output can never be
# reproduced — an honest zero is better than a plausible lie.
ARG BUILD_DATE=1970-01-01T00:00:00Z
# image.version is the amneziawg-go tag, not the protocol generation: it is the
# only thing that actually differs between these four images, and it is what
# someone comparing a running container against a CVE needs to see.
LABEL org.opencontainers.image.title="AmneziaWG ${AWG_VERSION} node (unofficial)" \
      org.opencontainers.image.description="Self-hosted AmneziaWG ${AWG_VERSION} server/client on amneziawg-go ${AWG_GO_VERSION}. UNOFFICIAL community build — not affiliated with, endorsed by or supported by AmneziaVPN; report problems to this project, not to them." \
      org.opencontainers.image.authors="Vadim Khristenko (VAI_PROG)" \
      org.opencontainers.image.vendor="Vadim Khristenko (VAI_PROG)" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/Vadim-Khristenko/awg-containers-and-tools" \
      org.opencontainers.image.url="https://github.com/Vadim-Khristenko/awg-containers-and-tools" \
      org.opencontainers.image.documentation="https://architect.vai-rice.space" \
      org.opencontainers.image.version="${AWG_GO_VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.base.name="docker.io/library/alpine:3.24" \
      space.vai-rice.awg.protocol="${AWG_VERSION}" \
      space.vai-rice.awg.go-version="${AWG_GO_VERSION}" \
      space.vai-rice.awg.tools-version="${AWG_TOOLS_VERSION}"
RUN apk add --no-cache bash iptables ip6tables iproute2 conntrack-tools socat dumb-init
COPY --from=build /out-awg-go /usr/bin/amneziawg-go
COPY --from=tools /out-awg    /usr/bin/awg
COPY entrypoint.sh /usr/bin/entrypoint.sh
COPY awg-uapi      /usr/bin/awg-uapi
COPY awg-peer      /usr/bin/awg-peer
COPY awg-log.sh    /usr/lib/awg/log.sh
RUN chmod +x /usr/bin/entrypoint.sh /usr/bin/awg-uapi /usr/bin/awg-peer
ENV AWG_IFACE=awg0
# So the event log can say which generation is running without the operator
# having to map an image name back to a protocol.
ENV AWG_PROTOCOL=${AWG_VERSION}
ENTRYPOINT ["dumb-init", "--", "/usr/bin/entrypoint.sh"]
