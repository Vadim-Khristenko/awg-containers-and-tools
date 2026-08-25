#!/usr/bin/env bash
# Builds one image per AmneziaWG protocol generation from the single Dockerfile,
# plus the tunnel-only resolver.
#
#   ./build.sh               all five, plus dns
#   ./build.sh 3.1 3.0 2.0   just those
#   ./build.sh dns           just the resolver
set -euo pipefail
cd "$(dirname "$0")"

# protocol : amneziawg-go tag
declare -A GO_TAG=(
    [1.0]=v0.2.12
    [1.5]=v0.2.14-beta-awg-1.5-1
    [2.0]=v0.2.19
    [3.0]=v3.0.2
    [3.1]=v3.1.20260814
)
# Docker Hub names. The major number is spelled without its dot: a repository
# path segment containing one reads as a registry host, so `amnezia-wg-1.5`
# would be ambiguous where `amnezia-wg-15` is not.
declare -A IMAGE=(
    [1.0]=amnezia-wg-1
    [1.5]=amnezia-wg-15
    [2.0]=amnezia-wg-2
    [3.0]=amnezia-wg-3
    [3.1]=amnezia-wg-31
    [dns]=amnezia-wg-dns
)

REGISTRY="${AWG_IMAGE_PREFIX:-vaiprog/}"
TOOLS_TAG="${AWG_TOOLS_VERSION:-v1.0.20260618-2}"
# One timestamp for the whole run, so images built together agree on when they
# were built. RFC 3339, which is what org.opencontainers.image.created wants.
BUILD_DATE="${SOURCE_DATE_EPOCH:+$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

# See inputs-digest.sh: the same fingerprint the release pipeline compares
# against, computed in one place so local builds and CI cannot disagree.
inputs_digest() { ./inputs-digest.sh "$1" "${GO_TAG[$1]:--}"; }

targets=("$@")
if [ "${#targets[@]}" -eq 0 ]; then targets=(1.0 1.5 2.0 3.0 3.1 dns); fi

for v in "${targets[@]}"; do
    name="${REGISTRY}${IMAGE[$v]:-}:latest"
    if [ "$v" = dns ]; then
        echo "==> $name  (unbound)"
        docker build -f Dockerfile.dns \
            --build-arg "BUILD_DATE=$BUILD_DATE" \
            --build-arg "INPUTS_DIGEST=$(inputs_digest dns)" \
            -t "$name" .
        continue
    fi
    tag=${GO_TAG[$v]:-}
    [ -n "$tag" ] || { echo "unknown target: $v (want 1.0 1.5 2.0 3.0 3.1 dns)" >&2; exit 1; }
    echo "==> $name  (amneziawg-go $tag)"
    docker build \
        --build-arg "AWG_GO_VERSION=$tag" \
        --build-arg "AWG_TOOLS_VERSION=$TOOLS_TAG" \
        --build-arg "AWG_VERSION=$v" \
        --build-arg "BUILD_DATE=$BUILD_DATE" \
        --build-arg "INPUTS_DIGEST=$(inputs_digest "$v")" \
        -t "$name" .
done
