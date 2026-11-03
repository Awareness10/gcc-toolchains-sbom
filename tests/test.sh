#!/usr/bin/env bash
# Smoke-test an installed toolchain. Runs inside the builder container.
#   tests/test.sh <triplet> <prefix>
set -euo pipefail
T=${1:?usage: test.sh <triplet> <prefix>}
P=${2:?usage: test.sh <triplet> <prefix>}
HERE=$(cd "$(dirname "$0")" && pwd)
HOST_GLIBC_MAX=2.28
TARGET_GLIBC_MAX=2.36
SYSROOT="$P/$T/sysroot"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok   $*"; }

# Newest GLIBC_x.y symbol version an ELF file needs (empty if none).
max_glibc() {
  readelf -V --wide "$1" 2>/dev/null | grep -o 'Name: GLIBC_[0-9.]*' | sed 's/.*GLIBC_//' \
    | sort -V | tail -1
}
ver_le() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$1" ]]; }
is_elf() { [[ "$(head -c4 "$1" | od -An -c | tr -d ' ')" == '177ELF' ]]; }

case $T in
  x86_64-*)  MACHINE='Advanced Micro Devices X86-64'; INTERP=/lib64/ld-linux-x86-64.so.2 ;;
  aarch64-*) MACHINE='AArch64';                       INTERP=/lib/ld-linux-aarch64.so.1 ;;
  *) fail "unknown triplet $T" ;;
esac

# 1. Host compatibility: host executables need at most glibc 2.28 and only glibc's libraries.
n=0
while IFS= read -r -d '' f; do
  is_elf "$f" || continue
  [[ "$(readelf -h "$f" | sed -n 's/.*Machine: *//p')" == 'Advanced Micro Devices X86-64' ]] || continue
  v=$(max_glibc "$f")
  [[ -z $v ]] || ver_le "$v" "$HOST_GLIBC_MAX" || fail "$f needs GLIBC_$v > $HOST_GLIBC_MAX"
  while read -r lib; do
    [[ $lib =~ ^(libc|libm|libdl|libpthread|librt|libutil|ld-linux-x86-64)\.so\.[0-9]+$ ]] \
      || fail "$f needs non-glibc host library $lib"
  done < <(readelf -d "$f" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p')
  n=$((n + 1))
done < <(find "$P/bin" "$P/libexec" "$P/$T/bin" "$P/lib/bfd-plugins" -type f -print0 2>/dev/null)
(( n > 20 )) || fail "only $n host executables found under $P"
ok "$n host executables need <= GLIBC_$HOST_GLIBC_MAX and only glibc libraries"

# 2. Build test programs for the target.
cd "$work"
"$P/bin/$T-gcc" -O2 -g -o hello-c "$HERE/hello.c"
"$P/bin/$T-gcc" -O2 -static -o hello-c-static "$HERE/hello.c"
"$P/bin/$T-g++" -O2 -g -o hello-cpp "$HERE/hello.cpp"
"$P/bin/$T-g++" -O2 -static -o hello-cpp-static "$HERE/hello.cpp"
ok "compiled C/C++ test programs (dynamic and static)"

for b in hello-c hello-c-static hello-cpp hello-cpp-static; do
  [[ "$(readelf -h $b | sed -n 's/.*Machine: *//p')" == "$MACHINE" ]] || fail "$b: wrong machine"
  if [[ $b == *-static ]]; then
    ! readelf -l $b | grep -q 'program interpreter' || fail "$b: static binary has an interpreter"
  else
    readelf -l $b | grep -qF "[Requesting program interpreter: $INTERP]" || fail "$b: wrong interpreter"
    v=$(max_glibc $b)
    ver_le "$v" "$TARGET_GLIBC_MAX" || fail "$b needs GLIBC_$v > $TARGET_GLIBC_MAX"
  fi
done
ok "target ELF machine, interpreter and GLIBC <= $TARGET_GLIBC_MAX"

# 3. Run them.
LIBPATH=$(find "$SYSROOT" -name 'libstdc++.so.6' -printf '%h\n' | sort -u | paste -sd:)
LIBPATH="$LIBPATH:$SYSROOT/lib64:$SYSROOT/usr/lib64:$SYSROOT/lib:$SYSROOT/usr/lib"
run() {
  case $T in
    x86_64-*)
      if [[ $1 == *-static ]]; then ./$1; else "$SYSROOT$INTERP" --library-path "$LIBPATH" ./$1; fi ;;
    aarch64-*)
      qemu-aarch64-static -L "$SYSROOT" -E LD_LIBRARY_PATH="$LIBPATH" ./$1 ;;
  esac
}
for b in hello-c hello-c-static; do
  [[ "$(run $b)" == "hello from C" ]] || fail "$b: unexpected output"
done
for b in hello-cpp hello-cpp-static; do
  [[ "$(run $b)" == "hello from C++" ]] || fail "$b: unexpected output"
done
ok "test programs run and print the expected output"

# 4. Debugger.
"$P/bin/$T-gdb" --batch -ex 'file hello-c' -ex 'info line main' 2>&1 | grep -q 'Line .* of ".*hello.c"' \
  || fail "gdb cannot read debug info"
gs=$(find "$P/$T" -name gdbserver -type f | head -1)
[[ -n $gs ]] || fail "gdbserver not found"
[[ "$(readelf -h "$gs" | sed -n 's/.*Machine: *//p')" == "$MACHINE" ]] || fail "gdbserver: wrong machine"
ok "gdb reads debug info; gdbserver present for target (${gs#$P/})"

echo "PASS: $T"
