#!/usr/bin/env sh
# Fingerprint of everything that decides what ends up inside one image.
#
#   ./inputs-digest.sh <target> <amneziawg-go tag>
#   ./inputs-digest.sh 3.0 v3.0.2   -> 16 hex characters
#   ./inputs-digest.sh dns -
#
# The result is stamped into the image as `space.vai-rice.awg.inputs`. The
# release pipeline reads it back off the published image to tell "identical
# image under a new tag" from "actually rebuilt", and skips the rebuild when
# they match — a release that only touched the Rust side should not hand users
# five new digests containing nothing new.
#
# This lives in its own file because both `build.sh` and the release workflow
# need it. Two copies of the same hash would agree right up until someone edited
# one of them, and then every image would look changed forever — which is the
# quiet, expensive failure mode where the feature still "works".
set -eu
cd "$(dirname "$0")"

target="${1:?usage: inputs-digest.sh <target> <go-tag>}"
gotag="${2:--}"

if [ "$target" = dns ]; then
    files="Dockerfile.dns unbound.conf"
else
    files="Dockerfile entrypoint.sh awg-uapi awg-peer awg-log.sh"
fi

# The build args are part of the fingerprint too: the same Dockerfile with a
# different amneziawg-go tag produces a different image.
{
    # shellcheck disable=SC2086  # word splitting is the point
    cat $files
    echo "awg=$target go=$gotag"
} | sha256sum | cut -c1-16
