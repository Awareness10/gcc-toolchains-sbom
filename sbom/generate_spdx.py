#!/usr/bin/env python3
"""Generate an SPDX 2.3 SBOM for a crosstool-NG toolchain.

Inputs are the exact build inputs: the resolved crosstool-NG .config, the cached
source archives (verified against crosstool-NG's chksum files), the bundled patches,
every file in the installed toolchain, and the dpkg database of the build container.

Python 3.7 (Debian 10), standard library only. Fails with SbomError rather than
producing an incomplete SBOM.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from urllib.parse import quote

TOOL_NAME = "tcw-generate_spdx"
TOOL_VERSION = "1.0.0"


class SbomError(Exception):
    pass


# ---------------------------------------------------------------- inputs

def parse_config(path):
    """Parse a crosstool-NG/kconfig .config into {symbol: value}."""
    cfg = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = re.match(r"^(CT_[A-Za-z0-9_]+)=(.*)$", line.strip())
            if not m:
                continue
            value = m.group(2)
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = re.sub(r'\\(.)', r"\1", value[1:-1])
            cfg[m.group(1)] = value
    return cfg


def enabled_components(cfg, meta):
    """Every package crosstool-NG will build, as sorted [(pkg_dir, version)].

    crosstool-NG marks each selected package with CT_<FAMILY>_<PKG>=y plus
    CT_<FAMILY>_<PKG>_PKG_KSYM="<PKG>"; its version is CT_<PKG>_VERSION.
    """
    out = []
    for key, ksym in cfg.items():
        if not key.endswith("_PKG_KSYM") or not ksym:
            continue
        if cfg.get(key[: -len("_PKG_KSYM")]) != "y":
            continue
        pkg = ksym.lower().replace("_", "-")
        version = cfg.get("CT_%s_VERSION" % ksym)
        if not version:
            raise SbomError("enabled package %s has no CT_%s_VERSION" % (pkg, ksym))
        if cfg.get("CT_%s_SRC_RELEASE" % ksym) != "y":
            raise SbomError("package %s is not built from a release archive; "
                            "only release sources are traceable" % pkg)
        if pkg not in meta:
            raise SbomError("package %s has no entry in components.json" % pkg)
        out.append((pkg, version))
    return sorted(out)


def file_digests(path, algs=("sha1", "sha256")):
    hashes = {a: hashlib.new(a) for a in algs}
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            for h in hashes.values():
                h.update(chunk)
    return {a: h.hexdigest() for a, h in hashes.items()}


def _read_chksum(path):
    sums = {}
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 3:
                alg, name, digest = parts
                sums.setdefault(name, {})[alg] = digest
    return sums


def _archive_formats(ctng_pkg_dir, pkg):
    desc = os.path.join(ctng_pkg_dir, pkg, "package.desc")
    if os.path.isfile(desc):
        with open(desc) as f:
            m = re.search(r"^archive_formats='([^']*)'", f.read(), re.M)
            if m:
                return m.group(1).split()
    return []


def resolve_tarball(pkg, version, src_dir, ctng_pkg_dir):
    """Find the cached source archive and verify it against crosstool-NG's chksum."""
    chksum = os.path.join(ctng_pkg_dir, pkg, version, "chksum")
    if not os.path.isfile(chksum):
        raise SbomError("no crosstool-NG chksum file for %s %s (%s)" % (pkg, version, chksum))
    sums = _read_chksum(chksum)
    formats = _archive_formats(ctng_pkg_dir, pkg)

    def rank(name):
        for i, ext in enumerate(formats):
            if name.endswith(ext):
                return (i, name)
        return (len(formats), name)

    for name in sorted(sums, key=rank):
        path = os.path.join(src_dir, name)
        if not os.path.isfile(path):
            continue
        expected = sums[name]
        if "sha256" not in expected or "sha512" not in expected:
            raise SbomError("chksum for %s lacks sha256/sha512" % name)
        got = file_digests(path, ("sha256", "sha512"))
        if got["sha256"] != expected["sha256"] or got["sha512"] != expected["sha512"]:
            raise SbomError("checksum mismatch for %s" % path)
        return {"file": name, "path": path, "sha256": got["sha256"], "sha512": got["sha512"]}
    raise SbomError("no cached source archive for %s %s in %s (expected one of: %s)"
                    % (pkg, version, src_dir, ", ".join(sorted(sums))))


def bundled_patches(pkg, version, ctng_pkg_dir):
    """crosstool-NG's bundled patches for a package version (top level only)."""
    d = os.path.join(ctng_pkg_dir, pkg, version)
    out = []
    for name in sorted(os.listdir(d)):
        path = os.path.join(d, name)
        if name.endswith(".patch") and os.path.isfile(path):
            dg = file_digests(path)
            out.append({"path": "%s/%s/%s" % (pkg, version, name),
                        "sha1": dg["sha1"], "sha256": dg["sha256"]})
    return out


GCC_RUNTIME = (r"lib(?:stdc\+\+(?:fs|exp)?|supc\+\+|gcc(?:_s|_eh)?|atomic|gomp|itm|quadmath"
               r"|ssp(?:_nonshared)?|(?:a|hwa|l|t)san(?:_preinit)?|ubsan|cc1)(?:\.[^/]*)?")
LINUX_UAPI_DIRS = r"(?:linux|asm|asm-generic|drm|misc|mtd|rdma|scsi|sound|video|xen)"

# Ordered (regex, package) rules. "{t}" is the escaped target triplet.
ATTRIBUTION_RULES = [
    (r"^bin/{t}-gdb(?:-add-index)?$", "gdb"),
    (r"(?:^|/)gdbserver$", "gdb"),
    (r"(?:^|/)libinproctrace\.so$", "gdb"),
    (r"^share/gdb/", "gdb"),
    (r"^bin/{t}-(?:gcc(?:-[0-9.]+|-ar|-nm|-ranlib)?|g\+\+|c\+\+|cpp|gcov(?:-dump|-tool)?"
     r"|lto-dump)$", "gcc"),
    (r"^(?:libexec|lib)/gcc/", "gcc"),
    (r"^lib/bfd-plugins/", "gcc"),
    (r"^{t}/include/c\+\+/", "gcc"),
    (r"^bin/{t}-(?:addr2line|ar|as|c\+\+filt|elfedit|gprof|ld(?:\.bfd)?|nm|objcopy|objdump"
     r"|ranlib|readelf|size|strings|strip)$", "binutils"),
    (r"^{t}/bin/", "binutils"),
    (r"^{t}/lib/ldscripts/", "binutils"),
    (r"^{t}/(?:sysroot/)?(?:usr/)?lib(?:32|64)?/" + GCC_RUNTIME + "$", "gcc"),
    (r"^{t}/sysroot/usr/include/" + LINUX_UAPI_DIRS + "/", "linux"),
    (r"^{t}/sysroot/", "glibc"),
    (r"^share/licenses/([a-z0-9.+_-]+)/", r"\1"),
]


def attribute(relpath, target):
    """Component a toolchain file was built from, or None."""
    t = re.escape(target)
    for pattern, pkg in ATTRIBUTION_RULES:
        m = re.search(pattern.replace("{t}", t), relpath)
        if m:
            return m.expand(pkg)
    return None


def scan_prefix(prefix):
    """All regular files under the toolchain prefix, sorted, with digests and kind."""
    out = []
    for root, dirs, files in os.walk(prefix):
        dirs.sort()
        for name in files:
            path = os.path.join(root, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            with open(path, "rb") as f:
                head = f.read(8)
            kind = ("BINARY" if head[:4] == b"\x7fELF"
                    else "ARCHIVE" if head == b"!<arch>\n" else None)
            dg = file_digests(path)
            out.append({"path": os.path.relpath(path, prefix), "kind": kind,
                        "sha1": dg["sha1"], "sha256": dg["sha256"]})
    out.sort(key=lambda f: f["path"])
    return out


def dpkg_packages(text):
    """Parse dpkg-query output (status, name, version, arch, source, source version)."""
    pkgs = []
    for line in text.splitlines():
        if not line.strip():
            continue
        status, name, version, arch, source, source_version = line.split("\t")
        if status != "installed":
            continue
        pkgs.append({"name": name, "version": version, "arch": arch,
                     "source": source or name, "source_version": source_version or version})
    return pkgs


# dpkg-query expands the \t and \n escapes itself.
DPKG_FORMAT = (r"${db:Status-Status}\t${Package}\t${Version}\t${Architecture}"
               r"\t${source:Package}\t${source:Version}\n")


def deb_purl(p):
    return "pkg:deb/debian/%s@%s?arch=%s&distro=debian-10" % (
        quote(p["name"], safe=".-_~"), quote(p["version"], safe=".-_~"), p["arch"])


# Debian packages whose static objects end up inside the toolchain's host executables:
# glibc startup files (crt1.o, crti.o, libc_nonshared.a) and the host compiler's
# libgcc / libstdc++ (linked with -static-libgcc -static-libstdc++).
HOST_STATIC_DEBS = ("libc6-dev", "libgcc-8-dev", "libstdc++-8-dev")


def verification_code(sha1s):
    return hashlib.sha1("".join(sorted(sha1s)).encode()).hexdigest()


# ---------------------------------------------------------------- document

def _sid(*parts):
    return "SPDXRef-" + "-".join(re.sub(r"[^A-Za-z0-9.]+", "-", p).strip("-") for p in parts)


class _Ids:
    def __init__(self):
        self.used = set()

    def new(self, *parts):
        base = _sid(*parts)
        sid, n = base, 1
        while sid in self.used:
            n += 1
            sid = "%s-%d" % (base, n)
        self.used.add(sid)
        return sid


def _expand(template, version, filename):
    return template.format(version=version, major=version.split(".")[0],
                           version_us=version.replace(".", "_"), file=filename)


def _component_package(sid, c):
    meta, arc = c["meta"], c["archive"]
    url = _expand(meta["download"], c["version"], arc["file"])
    refs = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
             "referenceLocator": "pkg:generic/%s@%s?checksum=sha256:%s&download_url=%s" % (
                 meta["name"], c["version"], arc["sha256"], quote(url, safe=""))}]
    if meta.get("cpe"):
        refs.append({"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
                     "referenceLocator": "cpe:2.3:a:%s:%s:*:*:*:*:*:*:*" % (
                         meta["cpe"], c["version"])})
    n = len(c["patches"])
    return {
        "SPDXID": sid,
        "name": meta["name"],
        "versionInfo": c["version"],
        "packageFileName": arc["file"],
        "supplier": meta["supplier"],
        "downloadLocation": url,
        "homepage": meta["homepage"],
        "filesAnalyzed": False,
        "checksums": [{"algorithm": "SHA256", "checksumValue": arc["sha256"]},
                      {"algorithm": "SHA512", "checksumValue": arc["sha512"]}],
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": meta["license"],
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": meta["purpose"],
        "description": meta["description"],
        "comment": ("Built from the upstream release archive with %d crosstool-NG patch(es) "
                    "applied (see PATCH_APPLIED relationships)." % n) if n else
                   "Built from the unmodified upstream release archive.",
        "externalRefs": refs,
    }


def build_document(inp):
    """Assemble the SPDX 2.3 document (pure function of its inputs)."""
    target, ids = inp["target"], _Ids()
    packages, files, rels = [], [], []

    def rel(a, kind, b):
        rels.append({"spdxElementId": a, "relationshipType": kind, "relatedSpdxElement": b})

    root = ids.new("Package", target, "toolchain")
    comp_ids = {}
    for c in inp["components"]:
        comp_ids[c["pkg"]] = ids.new("Package", c["pkg"])

    # Toolchain files (root CONTAINS each; attributed ones GENERATED_FROM a component).
    for f in inp["files"]:
        fid = ids.new("File", target, f["path"])
        entry = {
            "SPDXID": fid,
            "fileName": "./%s/%s" % (target, f["path"]),
            "checksums": [{"algorithm": "SHA1", "checksumValue": f["sha1"]},
                          {"algorithm": "SHA256", "checksumValue": f["sha256"]}],
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        if f["kind"]:
            entry["fileTypes"] = [f["kind"]]
        files.append(entry)
        rel(root, "CONTAINS", fid)
        if f.get("pkg"):
            if f["pkg"] not in comp_ids:
                raise SbomError("%s attributed to unknown component %s" % (f["path"], f["pkg"]))
            rel(fid, "GENERATED_FROM", comp_ids[f["pkg"]])

    meta = inp["components"]
    names = ", ".join("%s %s" % (c["meta"]["name"], c["version"]) for c in meta
                      if c["meta"]["relationship"] == "CONTAINS")
    packages.append({
        "SPDXID": root,
        "name": "%s-toolchain" % target,
        "versionInfo": inp["version"],
        "packageFileName": inp["tarball"]["file"],
        "supplier": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": True,
        "packageVerificationCode": {
            "packageVerificationCodeValue": verification_code(f["sha1"] for f in inp["files"])},
        "checksums": [{"algorithm": "SHA256", "checksumValue": inp["tarball"]["sha256"]}],
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
        "description": "GNU cross toolchain for %s (%s), built with crosstool-NG %s on %s."
                       % (target, names, inp["ctng"]["version"], inp["base_image"]),
    })
    rel("SPDXRef-DOCUMENT", "DESCRIBES", root)

    # Source components and the crosstool-NG patches applied to them.
    for c in inp["components"]:
        sid = comp_ids[c["pkg"]]
        packages.append(_component_package(sid, c))
        rel(root, c["meta"]["relationship"], sid)
        for p in c["patches"]:
            pid = ids.new("File", "patch", p["path"])
            files.append({
                "SPDXID": pid,
                "fileName": "./crosstool-ng/packages/%s" % p["path"],
                "checksums": [{"algorithm": "SHA1", "checksumValue": p["sha1"]},
                              {"algorithm": "SHA256", "checksumValue": p["sha256"]}],
                "fileTypes": ["SOURCE"],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "comment": "Patch bundled with crosstool-NG %s." % inp["ctng"]["version"],
            })
            rel(pid, "PATCH_APPLIED", sid)

    # Build environment: crosstool-NG, the base image and every installed Debian package.
    ctng = inp["ctng"]
    ctng_id = ids.new("Package", "crosstool-ng")
    packages.append({
        "SPDXID": ctng_id,
        "name": "crosstool-ng",
        "versionInfo": ctng["version"],
        "packageFileName": ctng["url"].rsplit("/", 1)[-1],
        "supplier": "Organization: crosstool-NG project",
        "downloadLocation": ctng["url"],
        "homepage": "https://crosstool-ng.github.io/",
        "filesAnalyzed": False,
        "checksums": [{"algorithm": "SHA256", "checksumValue": ctng["sha256"]},
                      {"algorithm": "SHA512", "checksumValue": ctng["sha512"]}],
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "GPL-2.0-only AND CC-BY-SA-2.5",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
        "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                          "referenceLocator": "pkg:github/crosstool-ng/crosstool-ng@crosstool-ng-%s"
                                              % ctng["version"]}],
    })
    rel(ctng_id, "BUILD_TOOL_OF", root)

    image, _, digest = inp["base_image"].partition("@")
    repo, _, tag = image.partition(":")
    img_id = ids.new("Package", "image", image)
    alg, _, hexd = digest.partition(":")
    packages.append({
        "SPDXID": img_id,
        "name": repo,
        "versionInfo": tag or digest,
        "supplier": "Organization: Debian",
        "downloadLocation": "https://hub.docker.com/_/%s" % repo,
        "filesAnalyzed": False,
        "checksums": [{"algorithm": alg.upper(), "checksumValue": hexd}] if hexd else [],
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "CONTAINER",
        "description": "Build container base image %s." % inp["base_image"],
        "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                          "referenceLocator": "pkg:oci/%s@%s?repository_url=docker.io/library/%s&tag=%s"
                                              % (repo, quote(digest, safe=""), repo, tag)}],
    })
    rel(img_id, "BUILD_TOOL_OF", root)

    def deb_package(d, comment=None):
        did = ids.new("Package", "deb", d["name"], d["arch"])
        entry = {
            "SPDXID": did,
            "name": d["name"],
            "versionInfo": d["version"],
            "supplier": "Organization: Debian",
            "downloadLocation": "https://snapshot.debian.org/package/%s/%s/"
                                % (d["source"], quote(d["source_version"], safe=".-_~+:")),
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "sourceInfo": "Debian source package %s %s" % (d["source"], d["source_version"]),
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": deb_purl(d)}],
        }
        if comment:
            entry["comment"] = comment
        packages.append(entry)
        return did

    missing = set(HOST_STATIC_DEBS) - {d["name"] for d in inp["dpkg"]}
    if missing:
        raise SbomError("build environment lacks %s" % ", ".join(sorted(missing)))
    for d in inp["dpkg"]:
        did = deb_package(d)
        rel(did, "BUILD_TOOL_OF", root)
        if d["name"] == "libc6":
            # Toolchain host executables are linked against the build host's glibc 2.28.
            rel(root, "DYNAMIC_LINK", did)
        if d["name"] in HOST_STATIC_DEBS:
            rel(root, "STATIC_LINK", did)

    # Installed only while compiling crosstool-NG, then purged so they cannot leak
    # into the toolchain (e.g. host ncurses into gdb).
    for d in inp.get("ctng_build_deps", []):
        did = deb_package(d, "Installed only to compile crosstool-NG; removed from the "
                             "build environment before any toolchain was built.")
        rel(did, "BUILD_DEPENDENCY_OF", ctng_id)

    creators = ["Tool: %s-%s" % (TOOL_NAME, TOOL_VERSION),
                "Tool: crosstool-NG-%s" % ctng["version"]]
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "%s-toolchain-%s" % (target, inp["version"]),
        "documentNamespace": inp["namespace"],
        "creationInfo": {"created": inp["created"], "creators": creators},
        "packages": packages,
        "files": files,
        "relationships": rels,
    }


# ---------------------------------------------------------------- CLI

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--target", required=True)
    ap.add_argument("--version", required=True, help="toolchain release version")
    ap.add_argument("--config", required=True, help="resolved crosstool-NG .config")
    ap.add_argument("--src-dir", required=True, help="crosstool-NG local tarballs dir")
    ap.add_argument("--prefix", required=True, help="installed toolchain directory")
    ap.add_argument("--tarball", required=True, help="packed toolchain archive")
    ap.add_argument("--out", required=True)
    ap.add_argument("--components", default=os.path.join(os.path.dirname(__file__), "components.json"))
    ap.add_argument("--ctng-pkg-dir", default="/opt/ctng/share/crosstool-ng/packages")
    ap.add_argument("--build-info", default="/etc/tcw/build-info.json")
    ap.add_argument("--ctng-tarball", default=None,
                    help="crosstool-NG source archive (default: /opt/ctng/src/<url basename>)")
    ap.add_argument("--ctng-build-deps", default="/etc/tcw/ctng-build-deps.dpkg",
                    help="dpkg-query output for packages used only to compile crosstool-NG")
    ap.add_argument("--dpkg-file", default=None, help="dpkg-query output (default: run dpkg-query)")
    a = ap.parse_args(argv)

    with open(a.components) as f:
        meta = {k: v for k, v in json.load(f).items() if not k.startswith("_")}
    with open(a.build_info) as f:
        info = json.load(f)
    cfg = parse_config(a.config)
    if cfg.get("CT_PATCH_BUNDLED") != "y" or any(
            v == "y" for k, v in cfg.items() if k.startswith("CT_PATCH_") and "LOCAL" in k):
        raise SbomError("only CT_PATCH_BUNDLED without local patches is supported")

    components = []
    for pkg, version in enabled_components(cfg, meta):
        components.append({
            "pkg": pkg, "version": version, "meta": meta[pkg],
            "archive": resolve_tarball(pkg, version, a.src_dir, a.ctng_pkg_dir),
            "patches": bundled_patches(pkg, version, a.ctng_pkg_dir),
        })
    known = {c["pkg"] for c in components}

    files = scan_prefix(a.prefix)
    unattributed = []
    for f in files:
        pkg = attribute(f["path"], a.target)
        f["pkg"] = pkg if pkg in known else None
        if f["kind"] and not f["pkg"]:
            unattributed.append(f["path"])
    if unattributed:
        raise SbomError("binaries with no source component:\n  " + "\n  ".join(unattributed))

    ctng_tar = a.ctng_tarball or os.path.join("/opt/ctng/src", info["ctng_url"].rsplit("/", 1)[-1])
    ctng_dg = file_digests(ctng_tar, ("sha256", "sha512"))
    if ctng_dg["sha512"] != info["ctng_sha512"]:
        raise SbomError("crosstool-NG archive %s does not match the pinned SHA-512" % ctng_tar)

    if a.dpkg_file:
        with open(a.dpkg_file) as f:
            dpkg_text = f.read()
    else:
        dpkg_text = subprocess.check_output(
            ["dpkg-query", "-W", "-f", DPKG_FORMAT],
            universal_newlines=True)

    ctng_build_deps = []
    if os.path.isfile(a.ctng_build_deps):
        with open(a.ctng_build_deps) as f:
            ctng_build_deps = dpkg_packages(f.read())

    tar_sha256 = file_digests(a.tarball, ("sha256",))["sha256"]
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    now = (datetime.datetime.utcfromtimestamp(int(epoch)) if epoch
           else datetime.datetime.utcnow()).replace(microsecond=0)
    doc = build_document({
        "target": a.target,
        "version": a.version,
        "created": now.isoformat() + "Z",
        "namespace": "%s/%s-toolchain-%s-%s" % (
            "https://spdx.org/spdxdocs", a.target, a.version,
            uuid.uuid5(uuid.NAMESPACE_URL, "sha256:" + tar_sha256)),
        "tarball": {"file": os.path.basename(a.tarball), "sha256": tar_sha256},
        "components": components,
        "files": files,
        "ctng": {"version": info["ctng_version"], "url": info["ctng_url"],
                 "sha512": info["ctng_sha512"], "sha256": ctng_dg["sha256"]},
        "base_image": info["base_image"],
        "dpkg": dpkg_packages(dpkg_text),
        "ctng_build_deps": ctng_build_deps,
    })
    with open(a.out, "w") as f:
        json.dump(doc, f, indent=1, sort_keys=False)
        f.write("\n")
    print("SBOM: %s (%d components, %d files, %d build packages)" % (
        a.out, len(components), len(files), len(doc["packages"]) - len(components) - 1))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SbomError as e:
        print("generate_spdx: error: %s" % e, file=sys.stderr)
        sys.exit(1)
