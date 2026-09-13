#!/usr/bin/env bash
#
# Build a custom-docker/<name> overlay and push it to the private registry.
# Shared across overlays (unlike souspike/custom-docker's one-script-per-
# overlay copies) so /picket-review can call it right after writing a
# Dockerfile without also having to generate boilerplate shell.
#
# Usage: ./build-and-push.sh <name> <version> [base-tag]
#   name      - subfolder under custom-docker/ (custom-docker/<name>/Dockerfile)
#   version   - registry tag to push, e.g. 4.4-1 (not :latest - image-tag
#               checks need a real version to compare against)
#   base-tag  - value for the Dockerfile's ARG BASE_TAG; defaults to whatever
#               ARG BASE_TAG=... already says in the Dockerfile
#
# Requires docker logged in to the registry already (this script doesn't
# handle credentials) and a docker daemon reachable from wherever it runs -
# neither is true inside a sandboxed coding session, only on a real host.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY="${PICKET_REGISTRY:-docker.souspike.com.br}"

NAME="${1:?Usage: ./build-and-push.sh <name> <version> [base-tag]}"
VERSION="${2:?Usage: ./build-and-push.sh <name> <version> [base-tag]}"
BASE_TAG="${3:-}"

DIR="$SCRIPT_DIR/$NAME"
[ -f "$DIR/Dockerfile" ] || { echo "No $DIR/Dockerfile" >&2; exit 1; }

if [ -z "$BASE_TAG" ]; then
  BASE_TAG="$(grep -oE '^ARG BASE_TAG=\S+' "$DIR/Dockerfile" | head -1 | cut -d= -f2)"
fi
[ -n "$BASE_TAG" ] || { echo "Couldn't determine BASE_TAG for $NAME (pass it as \$3 or set 'ARG BASE_TAG=...' in the Dockerfile)" >&2; exit 1; }

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "No usable docker daemon here - run this from a host that has one" \
       "and registry access, not from a sandboxed session." >&2
  exit 1
fi

TAG="$REGISTRY/$NAME:$VERSION"
echo "Building $TAG from base $BASE_TAG ..."
docker build --build-arg "BASE_TAG=$BASE_TAG" -t "$TAG" "$DIR"

push_with_retry() {
  local tag=$1 max_attempts=5 attempt=1
  while [ $attempt -le $max_attempts ]; do
    echo "Pushing $tag (attempt $attempt/$max_attempts) ..."
    output=$(docker push "$tag" 2>&1)
    exit_code=$?
    echo "$output"
    [ $exit_code -eq 0 ] && return 0
    if echo "$output" | grep -q "429 Too Many Requests"; then
      [ $attempt -lt $max_attempts ] && { echo "Rate limited, waiting 10s..."; sleep 10; }
    else
      return 1
    fi
    attempt=$((attempt + 1))
  done
  return 1
}

push_with_retry "$TAG" || {
  echo "Push failed - image built locally as $TAG; push it yourself from a" \
       "host with registry access, or fix auth and re-run this script." >&2
  exit 1
}

echo "Done: $TAG"
echo "This is inert until something points at it. Update whichever" \
     "docker-compose.yml pins $REGISTRY/$NAME (souspike/monitoring/ or" \
     "wherever this image is used) to image: $TAG, then on that server:" \
     "docker compose pull <service> && docker compose up -d --force-recreate <service>"
