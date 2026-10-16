#!/bin/bash
# PATCH 3b: pull the OSS-Fuzz base images ONCE before a pilot/campaign and print what was pinned.
# With oss_fuzz_pull_images: false (default) every later build reuses these local images.
# Usage: bash scripts/pin_base_images.sh [out_file]
set -euo pipefail
OUT="${1:-/tmp/pinned_base_images.txt}"
IMAGES="gcr.io/oss-fuzz-base/base-builder gcr.io/oss-fuzz-base/base-runner"
for img in $IMAGES; do docker pull -q "$img" > /dev/null; done
{
  echo "pinned_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for img in $IMAGES; do
    echo "$img id=$(docker image inspect --format '{{.Id}}' "$img") digests=$(docker image inspect --format '{{json .RepoDigests}}' "$img")"
  done
  echo "clang: $(docker run --rm gcr.io/oss-fuzz-base/base-builder clang --version | head -1)"
} | tee "$OUT"
