#!/usr/bin/env bash
# Push the Docker Hub descriptions.
#
# A pushed image with an empty overview page is the container equivalent of a
# repository with no README: people land on it, cannot tell what it is or
# whether it is trustworthy, and leave. Docker Hub has no way to take this from
# the git repository, so it has to be sent over the API.
#
#   DOCKERHUB_USERNAME=vaiprog DOCKERHUB_TOKEN=... ./sync.sh
#   ./sync.sh --dry-run          render everything, send nothing
#
# The token needs write access to the repositories. Nothing here reads the
# images themselves — it only writes text.
set -euo pipefail
cd "$(dirname "$0")"

DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

NS="${DOCKERHUB_USERNAME:-vaiprog}"

# image : protocol : amneziawg-go tag
IMAGES=(
    "amnezia-wg-1:1.0:v0.2.12"
    "amnezia-wg-15:1.5:v0.2.14-beta-awg-1.5-1"
    "amnezia-wg-2:2.0:v0.2.19"
    "amnezia-wg-3:3.0:v3.0.2"
)

need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 1; }; }
need curl
need jq

render_wg() {
    local image=$1 awg=$2 gotag=$3
    sed -e "s|__IMAGE__|$image|g" -e "s|__AWG__|$awg|g" -e "s|__GOTAG__|$gotag|g" wg.md.tmpl
}

token() {
    # The short-lived JWT, exchanged for the access token. Kept in a variable
    # and never echoed: it grants writes to every repository in the namespace.
    curl -fsS -H "Content-Type: application/json" \
        -d "$(jq -n --arg u "$NS" --arg p "$DOCKERHUB_TOKEN" \
              '{username:$u, password:$p}')" \
        https://hub.docker.com/v2/users/login/ | jq -r .token
}

push() {
    local repo=$1 short=$2 body=$3
    if [ "$DRY" = 1 ]; then
        printf '── %s/%s ── %s chars\n   %s\n' "$NS" "$repo" "${#body}" "$short"
        return
    fi
    local code
    code=$(jq -n --arg d "$short" --arg f "$body" '{description:$d, full_description:$f}' \
        | curl -fsS -o /dev/null -w '%{http_code}' -X PATCH \
            -H "Content-Type: application/json" \
            -H "Authorization: JWT $JWT" \
            -d @- "https://hub.docker.com/v2/repositories/$NS/$repo/")
    echo "  $repo -> HTTP $code"
}

if [ "$DRY" = 0 ]; then
    : "${DOCKERHUB_TOKEN:?set DOCKERHUB_TOKEN}"
    JWT=$(token)
    [ -n "$JWT" ] && [ "$JWT" != "null" ] || { echo "login failed" >&2; exit 1; }
fi

for entry in "${IMAGES[@]}"; do
    IFS=: read -r image awg gotag <<<"$entry"
    push "$image" \
        "Unofficial self-hosted AmneziaWG $awg server on amneziawg-go $gotag" \
        "$(render_wg "$image" "$awg" "$gotag")"
done

push "amnezia-wg-dns" \
    "Tunnel-only DNS resolver for self-hosted AmneziaWG — answers nothing from outside the tunnel" \
    "$(cat dns.md)"

echo "done"
