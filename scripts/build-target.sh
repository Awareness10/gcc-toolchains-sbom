#!/usr/bin/env bash
# Container entrypoint, runs as root. crosstool-NG must not run as root and, with
# rootless Docker, 'builder' cannot write bind mounts. So: stage the source cache into
# the builder-owned /build volume, build as 'builder', then export the results to /work
# owned by whoever owns the /work checkout.
#   scripts/build-target.sh <triplet>
set -euo pipefail
T=${1:?usage: build-target.sh <triplet>}
owner=$(stat -c %u:%g /work)

install -d -o builder -g builder /build /build/src /build/out
if compgen -G '/work/src/*' > /dev/null; then
  cp -n /work/src/* /build/src/
  chown builder:builder /build/src/*
fi

runuser -u builder -- env \
  OFFLINE="${OFFLINE:-0}" SKIP_CTNG="${SKIP_CTNG:-0}" \
  SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-}" \
  /work/scripts/ctng-build.sh "$T"

install -d /work/out /work/src
cp "/build/out/$T.tar.xz" "/build/out/$T.spdx.json" "/build/out/$T.config" "/build/out/$T.sha256" /work/out/
cp -n /build/src/* /work/src/
chown "$owner" /work/out /work/src "/work/out/$T".* /work/src/*
