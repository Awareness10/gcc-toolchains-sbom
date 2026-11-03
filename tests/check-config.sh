#!/usr/bin/env bash
# Resolve configs/<triplet>.defconfig with ct-ng and assert the pinned choices.
# Runs inside the builder container.
set -euo pipefail
T=${1:?usage: check-config.sh <triplet>}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEF="$ROOT/configs/$T.defconfig"
[[ -f $DEF ]] || { echo "FAIL: $DEF missing"; exit 1; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
ct-ng defconfig DEFCONFIG="$DEF" >/dev/null

fail=0
expect() {
  if grep -qxF -- "$1" .config; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi
}
case $T in
  x86_64-*)  expect 'CT_ARCH_X86=y' ;;
  aarch64-*) expect 'CT_ARCH_ARM=y' ;;
  *) echo "FAIL unknown triplet $T"; exit 1 ;;
esac
expect 'CT_ARCH_64=y'
expect 'CT_TARGET_VENDOR="unknown"'
expect 'CT_KERNEL_LINUX=y'
expect 'CT_LIBC_GLIBC=y'
expect 'CT_GCC_VERSION="14.4.0"'
expect 'CT_GLIBC_VERSION="2.36"'
expect 'CT_LINUX_VERSION="6.1.175"'
expect 'CT_BINUTILS_VERSION="2.43.1"'
expect 'CT_GDB_VERSION="16.3"'
expect 'CT_GMP_VERSION="6.3.0"'
expect 'CT_MPFR_VERSION="4.2.2"'
expect 'CT_MPC_VERSION="1.3.1"'
expect 'CT_ISL_VERSION="0.27"'
expect 'CT_ZLIB_VERSION="1.3.1"'
expect 'CT_ZSTD_VERSION="1.5.7"'
expect 'CT_NCURSES_VERSION="6.5"'
expect 'CT_EXPAT_VERSION="2.7.1"'
expect 'CT_LIBICONV_VERSION="1.18"'
expect 'CT_GETTEXT_VERSION="0.26"'
expect 'CT_CC_LANG_CXX=y'
expect 'CT_GDB_CROSS=y'
expect 'CT_GDB_GDBSERVER=y'
expect '# CT_GDB_CROSS_PYTHON is not set'
expect 'CT_VERIFY_DOWNLOAD_DIGEST=y'
expect 'CT_VERIFY_DOWNLOAD_DIGEST_SHA512=y'
expect 'CT_LOCAL_TARBALLS_DIR="/work/src"'
expect 'CT_SAVE_TARBALLS=y'
expect 'CT_PREFIX_DIR="/work/build/x-tools/${CT_TARGET}"'
expect 'CT_INSTALL_LICENSES=y'
exit $fail
