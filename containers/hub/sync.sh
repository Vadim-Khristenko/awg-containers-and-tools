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
# The token must be scoped **Read, Write & Delete**. Editing repository
# metadata is not covered by "Read & Write", which authenticates happily and
# then answers 403 "insufficient scope" — a failure that looks like a wrong
# password and is not one. Nothing here reads or writes an image; it only
# writes text.
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

# The bearer token, kept in a variable and never echoed: it grants writes to
# every repository in the namespace.
#
# Note the endpoint. The older /v2/users/login/ now sits behind a bot challenge
# and answers a non-browser POST with 403 and an HTML interstitial — which is
# what broke the first release that tried this. /v2/auth/token is the documented
# route for access tokens and is not challenged.
token() {
    local body code
    body=$(jq -n --arg i "$NS" --arg s "$DOCKERHUB_TOKEN" '{identifier:$i, secret:$s}')
    code=$(curl -sS -o /tmp/hub-token.$$ -w '%{http_code}' \
        -H "Content-Type: application/json" -d "$body" \
        https://hub.docker.com/v2/auth/token)
    if [ "$code" != "200" ]; then
        # Print the status and a short excerpt, never the request body.
        echo "login failed: HTTP $code" >&2
        head -c 200 "/tmp/hub-token.$$" >&2; echo >&2
        rm -f "/tmp/hub-token.$$"
        return 1
    fi
    jq -r .access_token < "/tmp/hub-token.$$"
    rm -f "/tmp/hub-token.$$"
}

push() {
    local repo=$1 short=$2 body=$3
    if [ "$DRY" = 1 ]; then
        printf '── %s/%s ── %s chars\n   %s\n' "$NS" "$repo" "${#body}" "$short"
        return
    fi
    local code
    code=$(jq -n --arg d "$short" --arg f "$body" '{description:$d, full_description:$f}' \
        | curl -sS -o /tmp/hub-patch.$$ -w '%{http_code}' -X PATCH \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $JWT" \
            -d @- "https://hub.docker.com/v2/repositories/$NS/$repo/")
    echo "  $repo -> HTTP $code"
    if [ "$code" != "200" ]; then
        head -c 200 "/tmp/hub-patch.$$" >&2; echo >&2
        # Worth naming, because the message alone sends people looking at the
        # wrong thing: the token authenticated fine, it simply is not allowed
        # to edit repository metadata. Docker Hub grants that only to a token
        # scoped Read, Write & Delete — "Read & Write" is not enough.
        if [ "$code" = "403" ]; then
            echo "  the token authenticated but may not edit repository metadata." >&2
            echo "  Docker Hub needs a token scoped 'Read, Write & Delete' for this." >&2
        fi
        rm -f "/tmp/hub-patch.$$"
        return 1
    fi
    rm -f "/tmp/hub-patch.$$"
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
