# Generic GCC toolchains (x86_64, aarch64) with SPDX traceability

Date: 2026-11-03
Status: approved

## Goal

Build two generic GNU/Linux cross toolchains with crosstool-NG, inside a
Debian 10 container, and ship each with an SPDX 2.3 SBOM that traces every
library and binary included in, and used to build, the toolchain.

## Decisions

| Topic | Decision |
|---|---|
| Build host | `debian:10` (glibc 2.28) pinned by digest `sha256:2a0c1b9175adf759420fe0fbd7f5b449038319171eb76554bb76cbe172b62b42` (linux/amd64) |
| Host compatibility | Toolchain executables require at most `GLIBC_2.28` |
| Targets | `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` (both built on x86_64) |
| Builder | crosstool-NG 1.29.0, tarball verified by SHA-512 |
| Install prefix | `x-tools/<triplet>` |
| Components | GCC 14.4.0, glibc 2.36, Linux headers 6.1.175, binutils 2.43.1, gdb 16.3 (cross gdb + target gdbserver) |
| Companion libs (static) | gmp 6.3.0, mpfr 4.2.2, mpc 1.3.1, isl 0.27, zlib 1.3.1, zstd 1.5.7, ncurses 6.5, expat 2.7.1, libiconv 1.18, gettext 0.26 |
| Languages | C, C++ |
| gdb Python | Disabled (it would dynamically link the host's libpython3.7, which ties the toolchain to that host) |
| SBOM | SPDX 2.3 JSON, one per toolchain |
| SBOM approach | Built from the exact inputs (option A), not a post-hoc scanner |

Debian 10 is end of life, so apt uses `archive.debian.org`. The archive is
frozen, which makes the pinned package set reproducible.

## Layout

```
tcw/
├── VERSION                    # toolchain release version
├── docker/Dockerfile          # pinned base, pinned apt deps, verified ct-ng
├── configs/<triplet>.defconfig
├── sbom/generate_spdx.py      # stdlib-only, Python 3.7 compatible
├── sbom/licenses.json         # curated component -> SPDX license expression
├── tests/                     # hello.c, hello.cpp, test.sh
├── build.sh                   # host entrypoint
└── out/                       # <triplet>.tar.xz, .spdx.json, .sha256
```

## Build flow (per target)

1. `build.sh` builds the image (or reuses it) and runs the container as the
   invoking user, with `src/` (download cache) and `out/` mounted.
2. Inside the container: `ct-ng defconfig` → `ct-ng build`. crosstool-NG
   verifies every downloaded tarball against its bundled digests
   (`CT_VERIFY_DOWNLOAD_DIGEST`). `OFFLINE=1` sets `CT_FORBID_DOWNLOAD`, so an
   air-gapped rebuild uses only the `src/` cache.
3. `tests/test.sh` checks the toolchain (see Verification).
4. `x-tools/<triplet>` is packed into `out/<triplet>.tar.xz`.
5. `generate_spdx.py` writes `out/<triplet>.spdx.json`.
6. The SBOM is validated with `pyspdxtools` in a separate, pinned verification
   container, so the validator never enters the build environment.

## SBOM content

- **Document:** SPDX 2.3, a unique namespace, creators (`Tool: generate_spdx.py`,
  `Tool: crosstool-ng-1.29.0`, organization), and a creation timestamp.
- **Root package:** the toolchain tarball, with SHA-256 and the version from
  `VERSION`. The document `DESCRIBES` it.
- **Shipped components** (gcc incl. libstdc++/libgcc, binutils, glibc,
  linux-headers, gdb, gdbserver):
  - version, download URL, and SHA-256 computed from the cached tarball,
    cross-checked against crosstool-NG's `chksum` file
  - declared license from `licenses.json`
  - purl (`pkg:generic/...`) and CPE 2.3 (for vulnerability matching)
  - each crosstool-NG patch applied, as an SPDX file with its SHA-256
  - relationship: root `CONTAINS` the component
- **Companion libraries:** the static libraries listed above, recorded the same
  way, with relationship `STATIC_LINK`.
- **Build tools:** crosstool-NG (release + SHA-512), the base image (by
  digest), and every installed dpkg package (purl
  `pkg:deb/debian/<name>@<version>?arch=<arch>&distro=debian-10`, license
  `NOASSERTION`). Each one is `BUILD_TOOL_OF` the root.

The generator **fails** if any `CT_*_VERSION` in the final `.config` that is
built has no matching cached tarball, or if a checksum disagrees with
crosstool-NG's `chksum` file. An incomplete SBOM is never produced.

## Verification

1. **Host compatibility:** no ELF under `bin/` or `libexec/` requires a glibc
   symbol version newer than `GLIBC_2.28`.
2. **Target ABI:** C and C++ hello-world programs (dynamic and static) are
   built. `readelf` checks the machine type and interpreter, and that no
   required glibc symbol is newer than `GLIBC_2.36`.
3. **Execution:** x86_64 test programs run through the sysroot's
   `ld-linux-x86-64.so.2`. aarch64 test programs run under
   `qemu-aarch64 -L <sysroot>`.
4. **SBOM:** validated by `pyspdxtools`, plus the completeness check above.

## Error handling

All scripts use `set -euo pipefail`. A checksum mismatch, a missing tarball,
a failed test, or an incomplete SBOM stops the build with a non-zero exit
status.
