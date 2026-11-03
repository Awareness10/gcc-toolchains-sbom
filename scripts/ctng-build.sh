#!/usr/bin/env bash
# Build, test, pack and SBOM one toolchain. Runs inside the container as 'builder'.
#   scripts/ctng-build.sh <triplet>
# Env: OFFLINE=1 forbids downloads (sources must be in /build/src),
#      SKIP_CTNG=1 reuses an existing /build/x-tools/<triplet>,
#      SOURCE_DATE_EPOCH.
set -euo pipefail
T=${1:?usage: ctng-build.sh <triplet>}
ROOT=/work
VERSION=$(cat "$ROOT/VERSION")
WORK=/build/$T
PREFIX=/build/x-tools/$T
OUT=/build/out
: "${SOURCE_DATE_EPOCH:=$(date +%s)}"
export SOURCE_DATE_EPOCH

mkdir -p "$WORK" "$OUT"
cd "$WORK"

if [[ ${SKIP_CTNG:-0} != 1 ]]; then
  echo "==> [$T] crosstool-NG build"
  ct-ng defconfig DEFCONFIG="$ROOT/configs/$T.defconfig"
  if [[ ${OFFLINE:-0} == 1 ]]; then
    echo 'CT_FORBID_DOWNLOAD=y' >> .config
    ct-ng olddefconfig
  fi
  ct-ng "build.$(nproc)"
fi

echo "==> [$T] smoke tests"
"$ROOT/tests/test.sh" "$T" "$PREFIX"

echo "==> [$T] packing"
rm -f "$OUT/$T".*
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
    --format=gnu -C "$(dirname "$PREFIX")" -cf - "$T" | xz -9 -T0 > "$OUT/$T.tar.xz"

echo "==> [$T] SBOM"
python3 "$ROOT/sbom/generate_spdx.py" --target "$T" --version "$VERSION" \
  --config "$WORK/.config" --src-dir /build/src --prefix "$PREFIX" \
  --tarball "$OUT/$T.tar.xz" --out "$OUT/$T.spdx.json"

(cd "$OUT" && sha256sum "$T.tar.xz" "$T.spdx.json" > "$T.sha256")
echo "==> [$T] done"
