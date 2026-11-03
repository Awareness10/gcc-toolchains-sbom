#!/usr/bin/env bash
# tcw: generic GCC toolchains with SPDX SBOMs.
#
#   ./build.sh                 build image, run unit tests, build all toolchains, validate SBOMs
#   ./build.sh image           build the builder image only
#   ./build.sh unittest        SBOM generator unit tests + config checks
#   ./build.sh <triplet>...    build specific toolchains
#   ./build.sh validate        validate out/*.spdx.json with pyspdxtools
#
# Env: OFFLINE=1 (no downloads, use src/), TCW_VOLUME (default tcw-build).
set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(cat VERSION)
IMAGE=tcw-builder:$VERSION
VALIDATOR=tcw-spdx-validate:$VERSION
VOLUME=${TCW_VOLUME:-tcw-build}
TARGETS=(x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu)
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)}

image() { docker build -t "$IMAGE" docker/; }

unittest() {
  docker run --rm -v "$PWD:/work" -w /work "$IMAGE" python3 -m unittest discover -s tests/sbom
  for t in "${TARGETS[@]}"; do
    docker run --rm -v "$PWD:/work" "$IMAGE" tests/check-config.sh "$t"
  done
}

build_target() {
  [[ -f configs/$1.defconfig ]] || { echo "unknown target: $1" >&2; exit 1; }
  docker run --rm --user 0 -v "$PWD:/work" -v "$VOLUME:/build" \
    -e OFFLINE="${OFFLINE:-0}" -e SKIP_CTNG="${SKIP_CTNG:-0}" \
    -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    "$IMAGE" /work/scripts/build-target.sh "$1"
}

validate() {
  docker build -q -t "$VALIDATOR" -f docker/Dockerfile.validate docker/ > /dev/null
  local f found=0
  for f in out/*.spdx.json; do
    [[ -e $f ]] || continue
    found=1
    echo "==> validating $f"
    docker run --rm -v "$PWD/out:/out:ro" "$VALIDATOR" -i "/out/$(basename "$f")"
  done
  (( found )) || { echo "no SBOMs in out/" >&2; exit 1; }
  (cd out && sha256sum -c ./*.sha256)
}

case ${1:-all} in
  all)      image; unittest; for t in "${TARGETS[@]}"; do build_target "$t"; done; validate ;;
  image)    image ;;
  unittest) unittest ;;
  validate) validate ;;
  *)        image; for t in "$@"; do build_target "$t"; done ;;
esac
