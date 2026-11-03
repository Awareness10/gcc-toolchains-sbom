#!/usr/bin/env bash
# tcw: generic GCC toolchains with SPDX SBOMs.
#
#   ./build.sh                 build image, run unit tests, build all toolchains, validate SBOMs
#   ./build.sh image           build the builder image only
#   ./build.sh unittest        SBOM generator unit tests + config checks
#   ./build.sh <triplet>...    build specific toolchains
#   ./build.sh validate        validate out/*.spdx.json with pyspdxtools
#   ./build.sh help            show this help
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

NEED_GB=35

die() { printf '\nbuild.sh: %s\n\n' "$*" >&2; exit 1; }

# Fail early, with a fix, when Docker or the machine can't run the build.
preflight() {
  local arch err
  arch=$(uname -m)
  [[ $arch == x86_64 ]] || die "this build needs an x86_64 Linux machine (found: $arch).
  The builder image is linux/amd64 and the toolchains are built to run on x86_64 hosts."

  command -v docker > /dev/null || die "Docker is not installed.
  Install Docker Engine: https://docs.docker.com/engine/install/
  (Rootless Docker also works: https://docs.docker.com/engine/security/rootless/)
  Then check it with: docker run --rm hello-world"

  if ! err=$(docker info 2>&1 > /dev/null); then
    if grep -qi 'permission denied' <<< "$err"; then
      die "Docker is installed, but you are not allowed to use it.
  Add yourself to the docker group, then log out and back in:
    sudo usermod -aG docker \"\$USER\"
  Details: https://docs.docker.com/engine/install/linux-postinstall/"
    fi
    die "Docker is installed, but the Docker daemon is not reachable.
  Start it with:  sudo systemctl start docker
  (rootless:      systemctl --user start docker)
  Docker said: $(head -n 3 <<< "$err")"
  fi
}

# Warn (don't fail) when the Docker data directory looks too small for a toolchain build.
check_disk() {
  local root free_gb
  root=$(docker info --format '{{.DockerRootDir}}' 2> /dev/null) || return 0
  free_gb=$(df -P -BG "$root" 2> /dev/null | awk 'NR == 2 { sub("G", "", $4); print $4 }') || return 0
  [[ -n $free_gb ]] || return 0
  if (( free_gb < NEED_GB )); then
    printf 'build.sh: warning: only %s GB free in %s; a full build needs about %s GB.\n' \
      "$free_gb" "$root" "$NEED_GB" >&2
  fi
}

usage() { sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0"; }

image() { docker build -t "$IMAGE" docker/; }

unittest() {
  docker run --rm -v "$PWD:/work" -w /work "$IMAGE" python3 -m unittest discover -s tests/sbom
  for t in "${TARGETS[@]}"; do
    docker run --rm -v "$PWD:/work" "$IMAGE" tests/check-config.sh "$t"
  done
}

build_target() {
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
  help|-h|--help) usage; exit 0 ;;
  all|image|unittest|validate) ;;
  *) for t in "$@"; do
       [[ -f configs/$t.defconfig ]] || die "unknown command or target: $t (try ./build.sh help)"
     done ;;
esac

preflight
case ${1:-all} in
  all)      check_disk; image; unittest; for t in "${TARGETS[@]}"; do build_target "$t"; done; validate ;;
  image)    image ;;
  unittest) image; unittest ;;
  validate) validate ;;
  *)        check_disk; image; for t in "$@"; do build_target "$t"; done ;;
esac
