# GCC Toolchains Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` GCC 14 / glibc 2.36
toolchains with crosstool-NG 1.29.0 in a Debian 10 container, each shipped with a validated
SPDX 2.3 SBOM.

**Architecture:** A pinned Debian 10 image holds pinned apt packages plus a checksum-verified
crosstool-NG. `build.sh` runs one container per target. Inside it, `scripts/build-target.sh`
runs ct-ng, tests the toolchain, packs it, and calls `sbom/generate_spdx.py`. That script
(stdlib only, Python 3.7) builds the SPDX document from the resolved `.config`, the cached
source tarballs, ct-ng's patch and `chksum` files, the ELF files in the toolchain, and
`dpkg-query`. A separate pinned container validates the result with `pyspdxtools`.

**Tech Stack:** Docker, Debian 10 (buster, archive.debian.org), crosstool-NG 1.29.0, bash,
Python 3.7 stdlib + unittest, qemu-user-static, spdx-tools (validation only).

Design: `docs/plans/2026-11-03-gcc-toolchains-design.md`

---

### Task 1: Builder image

**Files:**
- Create: `VERSION` (`1.0.0`)
- Create: `docker/Dockerfile`
- Create: `docker/packages.lock` (one `name=version` per line)

**Steps**
1. Write `docker/Dockerfile`:
   - `ARG BASE_IMAGE=debian:10@sha256:2a0c1b9175adf759420fe0fbd7f5b449038319171eb76554bb76cbe172b62b42`, then `FROM ${BASE_IMAGE}`.
   - Point apt at `archive.debian.org` (`buster`, `buster/updates`) with `Check-Valid-Until false`.
   - Install `packages.lock` as `apt-get install name=version …`.
   - Download `crosstool-ng-1.29.0.tar.xz`, check SHA-512
     `04cd24c8…82acee`, build it, install to `/opt/ctng`, and keep the tarball under `/opt/ctng/src/`.
   - Write `/etc/tcw-build-info.json` with the base image, ct-ng version, URL and SHA-512.
   - Create user `builder` (uid 1000).
2. Produce the lock: install unpinned once, run `dpkg-query` for the requested names, and write `packages.lock`.
3. Build: `docker build -t tcw-builder:1.0.0 docker/` → succeeds.
4. Verify: `docker run --rm tcw-builder:1.0.0 sh -c 'ldd --version | head -1; ct-ng version | head -1'`.
   Expected: `ldd (Debian GLIBC 2.28-10…) 2.28` and `crosstool-NG 1.29.0`.
5. Commit: `feat: pinned Debian 10 builder image with crosstool-NG 1.29.0`.

### Task 2: crosstool-NG defconfigs

**Files:**
- Create: `configs/x86_64-unknown-linux-gnu.defconfig`, `configs/aarch64-unknown-linux-gnu.defconfig`
- Create: `tests/check-config.sh`

**Steps**
1. Write `tests/check-config.sh <triplet>`. It runs `ct-ng defconfig` in a temp dir and asserts the
   resolved `.config` contains:
   - `CT_GCC_VERSION="14.4.0"`, `CT_GLIBC_VERSION="2.36"`, `CT_LINUX_VERSION="6.1.175"`,
     `CT_BINUTILS_VERSION="2.43.1"`, `CT_GDB_VERSION="16.3"`
   - `CT_CC_LANG_CXX=y`, `CT_GDB_CROSS=y`, `CT_GDB_GDBSERVER=y`, `# CT_GDB_CROSS_PYTHON is not set`
   - `CT_VERIFY_DOWNLOAD_DIGEST=y`, `CT_LOCAL_TARBALLS_DIR="/work/src"`, `CT_SAVE_TARBALLS=y`, `CT_TARGET` matching the triplet
2. Run it with no defconfig → FAIL.
3. Write the defconfigs:
   - start from the ct-ng samples; drop gold (deprecated upstream)
   - set the version symbols (`CT_GCC_V_14`, `CT_GLIBC_V_2_36`, `CT_LINUX_V_6_1`, `CT_BINUTILS_V_2_43`, `CT_GDB_V_16`)
   - set the companion lib versions (gmp 6.3.0, mpfr 4.2.2, mpc 1.3.1, isl 0.27, zlib 1.3.1, zstd 1.5.7, ncurses 6.5, expat 2.7.1, libiconv 1.18, gettext 0.26)
   - set `CT_PREFIX_DIR="/work/build/x-tools/${CT_TARGET}"` and `CT_TARGET_VENDOR="unknown"`
   - use `CT_LOG_FILE_COMPRESS=y` and `CT_INSTALL_LICENSES=y`
4. Run `docker run … tests/check-config.sh <triplet>` for both targets → PASS.
5. Commit: `feat: crosstool-NG defconfigs for x86_64 and aarch64`.

### Task 3: SBOM generator (TDD)

**Files:**
- Create: `sbom/components.json`. It maps each ct-ng package → `name`, `license` (SPDX expression), `supplier`, `homepage`, `download` (URL template with `{version}`/`{file}`), `cpe` (vendor:product), `relationship` (`CONTAINS`|`STATIC_LINK`).
- Create: `sbom/generate_spdx.py`
- Test: `tests/sbom/test_generate_spdx.py` (unittest + a fixture tree in `tests/sbom/fixtures/`)

Functions, each written test-first (red → green → commit):
1. `parse_config(path) -> dict`: `CT_X="v"` / `CT_X=y`; ignores comments.
2. `enabled_components(cfg, meta) -> [(pkg, version)]`: every `CT_<P>_VERSION` whose
   package is enabled. A package the build uses that has no `components.json` entry → `SbomError`.
3. `resolve_tarball(pkg, version, src_dir, ctng_pkg_dir) -> (path, sha256)`: picks the cached
   archive listed in ct-ng's `chksum`. It computes SHA-256 and raises `SbomError` if the file is missing or the
   digest differs from `chksum`.
4. `bundled_patches(pkg, version, ctng_pkg_dir) -> [(relpath, sha256)]`.
5. `attribute(relpath, target) -> pkg`: path rules that assign each ELF/ar file in the prefix to
   gcc/binutils/glibc/gdb. An unmatched file → `SbomError`.
6. `dpkg_packages(text) -> [dict]`: parses `dpkg-query -W -f '${Package}\t${Version}\t${Architecture}\t${source:Package}\n'`.
7. `verification_code(sha1s) -> str`: SPDX package verification code.
8. `build_document(...) -> dict`: the full SPDX 2.3 JSON. Test it against the fixture, checking:
   - the document `DESCRIBES` the root
   - each component has the right relationship (`CONTAINS` or `STATIC_LINK`), and patches use `PATCH_APPLIED`
   - files are `GENERATED_FROM` their component
   - every dpkg package and ct-ng are `BUILD_TOOL_OF` the root, and the root `DYNAMIC_LINK`s to the build-time `libc6`
   - every SPDXID is unique and every relationship target exists

Run: `docker run --rm -v $PWD:/work -w /work tcw-builder:1.0.0 python3 -m unittest discover -s tests/sbom -v`
(Python 3.7, the same interpreter as in the real build).

### Task 4: Toolchain smoke test

**Files:** Create `tests/test.sh`, `tests/hello.c`, `tests/hello.cpp`

`tests/test.sh <triplet> <prefix>` fails if any of these checks fails:
1. Host compatibility:
   - every ELF under `bin/`, `libexec/` and `<triplet>/bin/` needs at most `GLIBC_2.28`
   - their `NEEDED` libraries are limited to glibc's (libc, libm, libdl, libpthread, librt, libutil, ld-linux)
2. Target build: build C and C++ test programs, both dynamic and `-static`. For each, check:
   - the ELF machine type
   - the interpreter (`/lib64/ld-linux-x86-64.so.2` or `/lib/ld-linux-aarch64.so.1`)
   - the newest required `GLIBC_` version is at most 2.36
3. Run each program and check its expected output:
   - x86_64: through the sysroot's dynamic loader (static programs run directly)
   - aarch64: under `qemu-aarch64-static -L <sysroot>`
4. Debugger:
   - `<triplet>-gdb --batch -ex 'file hello-c' -ex 'info line main'` succeeds
   - gdbserver exists and is built for the target architecture

Verified in Task 6, against real toolchains.

### Task 5: Orchestration

**Files:** Create `scripts/build-target.sh`, `build.sh`

- `scripts/build-target.sh <triplet>` (runs in the container):
  1. defconfig, with `OFFLINE=1` → `CT_FORBID_DOWNLOAD=y`
  2. `ct-ng build.$(nproc)`
  3. `tests/test.sh`
  4. a reproducible tar (`--sort=name --mtime=@$SOURCE_DATE_EPOCH --owner=0 --group=0 --numeric-owner`), compressed with `xz -9 -T0`
  5. `generate_spdx.py`
  6. write `out/<triplet>.sha256`
- `build.sh [image|unittest|validate|<triplet>…|all]` (runs on the host): builds the image, then runs the
  container as the invoking user with `/work` bind-mounted.
- Commit.

### Task 6: Real builds

1. `./build.sh x86_64-unknown-linux-gnu`. Fix any problems, using superpowers:systematic-debugging, and adjust the
   attribution rules and the enabled-component detection to what ct-ng actually produces.
2. `./build.sh aarch64-unknown-linux-gnu`.
3. Commit the fixes.

### Task 7: SBOM validation container

**Files:** Create `docker/Dockerfile.validate`, a pinned `python:3.12-slim` digest with a pinned `spdx-tools` version.

`./build.sh validate` runs `pyspdxtools -i out/<triplet>.spdx.json` for each SBOM. Expected: no errors.
Commit.

### Task 8: README

Create `README.md` covering usage, outputs, what the SBOM contains, how to audit it (`jq` examples),
offline rebuild, and the known limits (Debian package licenses are `NOASSERTION`). Commit.
