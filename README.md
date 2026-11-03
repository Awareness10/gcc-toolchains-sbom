# tcw: generic GCC toolchains with SPDX traceability

Builds two GNU/Linux cross toolchains with [crosstool-NG](https://crosstool-ng.github.io/)
in a pinned Debian 10 container, and ships each with an SPDX 2.3 SBOM.

| | |
|---|---|
| Targets | `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` |
| Runs on | any x86_64 Linux with glibc ≥ 2.28 (built on Debian 10) |
| Produces code for | Linux with glibc ≥ 2.36 |
| Contents | GCC 14.4.0 (C, C++), binutils 2.43.1, glibc 2.36, Linux 6.1.175 headers, gdb 16.3 + gdbserver |
| Builder | crosstool-NG 1.29.0 |

## Usage

Requires Docker (rootless Docker works).

```sh
./build.sh                            # everything: image, unit tests, both toolchains, SBOM validation
./build.sh x86_64-unknown-linux-gnu   # one toolchain
./build.sh validate                   # validate out/*.spdx.json and check out/*.sha256
./build.sh unittest                   # SBOM generator tests + config checks
```

Settings (environment variables):

| Variable | Effect |
|---|---|
| `OFFLINE=1` | Forbid downloads; build only from the source archives in `src/` |
| `SOURCE_DATE_EPOCH` | Timestamp for the archive and SBOM (default: last commit time) |

Each toolchain takes about 10 minutes on a 16-thread machine.

## Outputs

```
out/<triplet>.tar.xz      the toolchain (unpack anywhere; it is relocatable)
out/<triplet>.spdx.json   SPDX 2.3 SBOM for that archive
out/<triplet>.config      the resolved crosstool-NG configuration used for the build
out/<triplet>.sha256      checksums of the three files above
src/                      every upstream source archive used (enables offline rebuilds)
```

Use a toolchain:

```sh
tar xf out/aarch64-unknown-linux-gnu.tar.xz -C /opt
/opt/aarch64-unknown-linux-gnu/bin/aarch64-unknown-linux-gnu-gcc hello.c -o hello
```

The archive also contains crosstool-NG's full build log (`build.log.bz2`) and the upstream
license texts (`share/licenses/`).

## What the SBOM traces

Everything is derived from the build inputs, not by scanning afterwards.

**Shipped in the toolchain**
- **Components:** gcc, binutils, glibc, linux (headers), gdb. Each records its version, upstream
  URL, SHA-256 and SHA-512 of the exact source archive, declared license, supplier, purl and CPE.
  The toolchain package `CONTAINS` each component.
- **Patches:** every crosstool-NG patch applied, as an SPDX file with checksums, linked with
  `PATCH_APPLIED`. The SBOM shows exactly how the build differs from upstream source.
- **Statically linked libraries:** gmp, mpfr, mpc, isl, zlib, zstd, ncurses, expat, libiconv and
  gettext, built by crosstool-NG and linked into the host tools (`STATIC_LINK`).
- **Every file** in the archive, with SHA-1 and SHA-256 (`CONTAINS`). Each binary (ELF or `ar`) is
  linked to the component it was built from (`GENERATED_FROM`).

**Used to build it**
- crosstool-NG itself (release URL and checksums), the Debian 10 base image (by digest), and
  every installed Debian package (purl `pkg:deb/...`, `snapshot.debian.org` source link), all
  `BUILD_TOOL_OF` the toolchain.
- Packages installed only to compile crosstool-NG are `BUILD_DEPENDENCY_OF` crosstool-NG.
- The toolchain `DYNAMIC_LINK`s to the build host's `libc6`. This is the only shared library the
  host tools need, and `tests/test.sh` enforces it.
- The toolchain `STATIC_LINK`s to the Debian packages whose static objects are inside every host
  executable: `libc6-dev` (startup files), `libgcc-8-dev` and `libstdc++-8-dev` (host tools use
  `-static-libgcc -static-libstdc++`).

**The build fails instead of writing an incomplete SBOM when:**
- a component enabled in the crosstool-NG configuration is missing from `sbom/components.json`
- a source archive is missing, or doesn't match crosstool-NG's checksums
- any binary in the toolchain can't be linked to a source component

### Auditing with jq

```sh
S=out/x86_64-unknown-linux-gnu.spdx.json
# shipped components with versions and licenses
jq -r '.packages[] | select(.primaryPackagePurpose != null and .supplier != "Organization: Debian")
       | [.name, .versionInfo, .licenseDeclared] | @tsv' $S
# patches applied to glibc
jq -r --arg id "$(jq -r '.packages[]|select(.name=="glibc").SPDXID' $S)" \
   '.relationships[]|select(.relationshipType=="PATCH_APPLIED" and .relatedSpdxElement==$id).spdxElementId' $S
# which component a binary comes from
jq -r '. as $d | .files[] | select(.fileName|endswith("bin/x86_64-unknown-linux-gnu-ld.bfd")) | .SPDXID as $f
       | $d.relationships[] | select(.spdxElementId==$f and .relationshipType=="GENERATED_FROM").relatedSpdxElement' $S
```

## Verification

Each build runs `tests/test.sh` against the installed toolchain. It checks that:
- host executables need at most `GLIBC_2.28` and no shared libraries outside glibc
- C and C++ programs build (dynamic and static), with the correct ELF machine type and interpreter,
  and need at most `GLIBC_2.36`
- the programs run and print the expected output: x86_64 through the sysroot's dynamic loader,
  aarch64 under qemu-user
- gdb reads the debug info, and gdbserver is built for the target architecture

`./build.sh validate` checks each SBOM with `pyspdxtools` (spdx-tools 0.8.5), which runs in its
own pinned container so it never enters the build environment.

## Layout

```
VERSION                       toolchain release version
docker/Dockerfile             builder: debian:10@sha256:…, pinned apt packages, verified crosstool-NG
docker/packages.lock          exact Debian package versions in the builder
docker/ctng-build-deps.lock   packages present only while compiling crosstool-NG
docker/Dockerfile.validate    SBOM validator image (pinned)
configs/<triplet>.defconfig   crosstool-NG configuration
sbom/generate_spdx.py         SBOM generator (Python 3.7 stdlib)
sbom/components.json          per-component license, supplier, URL, CPE
scripts/                      container entrypoints
tests/                        smoke test, config checks, SBOM unit tests
docs/plans/                   design and implementation plan
```

## Known limits

- Licenses are the **declared** upstream licenses, curated in `sbom/components.json`.
  `licenseConcluded` is `NOASSERTION`: no file-level license scan is done.
- Debian build packages have license `NOASSERTION`, because Debian copyright files aren't
  reliably machine-readable. Their `snapshot.debian.org` links lead to the exact sources.
- libiconv and gettext are built by crosstool-NG as host companion libraries. They are recorded as
  `STATIC_LINK` to be safe, even though on a glibc host the tools may not use them.
- Debian 10 is end of life. Its packages come from the frozen `archive.debian.org`, which also
  keeps the build environment reproducible. It only builds the toolchain; nothing from it ships
  except the glibc 2.28 compatibility requirement.
