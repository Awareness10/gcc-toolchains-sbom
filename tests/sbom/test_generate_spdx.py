"""Unit tests for sbom/generate_spdx.py. Python 3.7, stdlib only.

Run: python3 -m unittest discover -s tests/sbom -v
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "sbom"))

import generate_spdx as g  # noqa: E402

T = "x86_64-unknown-linux-gnu"


def sha(data, alg="sha256"):
    return hashlib.new(alg, data).hexdigest()


def write(path, data=b""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


class TmpDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def p(self, *parts):
        return os.path.join(self.tmp, *parts)


class ParseConfigTest(TmpDirTest):
    def test_parses_strings_bools_and_ignores_comments(self):
        write(self.p(".config"), b'# comment\nCT_GCC_VERSION="14.4.0"\nCT_CC_GCC=y\n'
                                 b'# CT_GDB_CROSS_PYTHON is not set\nCT_JOBS=4\n\n')
        cfg = g.parse_config(self.p(".config"))
        self.assertEqual(cfg, {"CT_GCC_VERSION": "14.4.0", "CT_CC_GCC": "y", "CT_JOBS": "4"})

    def test_unescapes_quoted_values(self):
        write(self.p(".config"), b'CT_X="a \\"b\\" \\\\c"\n')
        self.assertEqual(g.parse_config(self.p(".config"))["CT_X"], 'a "b" \\c')


class EnabledComponentsTest(unittest.TestCase):
    META = {"gcc": {}, "gmp": {}, "binutils-linaro": {}}

    def cfg(self, **extra):
        cfg = {
            "CT_CC_GCC": "y", "CT_CC_GCC_PKG_KSYM": "GCC", "CT_GCC_VERSION": "14.4.0",
            "CT_GCC_SRC_RELEASE": "y",
            "CT_COMP_LIBS_GMP": "y", "CT_COMP_LIBS_GMP_PKG_KSYM": "GMP",
            "CT_GMP_VERSION": "6.3.0", "CT_GMP_SRC_RELEASE": "y",
            "CT_ARCH_X86_PKG_KSYM": "",
        }
        cfg.update(extra)
        return cfg

    def test_returns_enabled_packages_sorted(self):
        self.assertEqual(g.enabled_components(self.cfg(), self.META),
                         [("gcc", "14.4.0"), ("gmp", "6.3.0")])

    def test_skips_disabled_packages(self):
        cfg = self.cfg(CT_COMP_LIBS_GMP="n")
        self.assertEqual(g.enabled_components(cfg, self.META), [("gcc", "14.4.0")])

    def test_maps_ksym_underscores_to_dashes(self):
        cfg = self.cfg(CT_BINUTILS_BINUTILS_LINARO="y",
                       CT_BINUTILS_BINUTILS_LINARO_PKG_KSYM="BINUTILS_LINARO",
                       CT_BINUTILS_LINARO_VERSION="2.30", CT_BINUTILS_LINARO_SRC_RELEASE="y")
        self.assertIn(("binutils-linaro", "2.30"), g.enabled_components(cfg, self.META))

    def test_unknown_package_is_an_error(self):
        cfg = self.cfg(CT_COMP_LIBS_ISL="y", CT_COMP_LIBS_ISL_PKG_KSYM="ISL",
                       CT_ISL_VERSION="0.27", CT_ISL_SRC_RELEASE="y")
        with self.assertRaisesRegex(g.SbomError, "isl.*components.json"):
            g.enabled_components(cfg, self.META)

    def test_missing_version_is_an_error(self):
        cfg = self.cfg()
        del cfg["CT_GMP_VERSION"]
        with self.assertRaisesRegex(g.SbomError, "CT_GMP_VERSION"):
            g.enabled_components(cfg, self.META)

    def test_non_release_source_is_an_error(self):
        cfg = self.cfg(CT_GCC_SRC_RELEASE="n", CT_GCC_SRC_DEVEL="y")
        with self.assertRaisesRegex(g.SbomError, "gcc.*release"):
            g.enabled_components(cfg, self.META)


class TarballTest(TmpDirTest):
    def setUp(self):
        super().setUp()
        self.data = b"gcc source"
        self.pkgdir = self.p("packages")
        write(self.p("packages", "gcc", "package.desc"), b"archive_formats='.tar.xz .tar.gz'\n")
        lines = []
        for name in ("gcc-14.4.0.tar.xz", "gcc-14.4.0.tar.gz"):
            for alg in ("md5", "sha1", "sha256", "sha512"):
                lines.append("%s %s %s" % (alg, name, sha(self.data, alg)))
        write(self.p("packages", "gcc", "14.4.0", "chksum"), "\n".join(lines).encode() + b"\n")
        write(self.p("packages", "gcc", "14.4.0", "0001-b.patch"), b"patch b")
        write(self.p("packages", "gcc", "14.4.0", "0000-a.patch"), b"patch a")
        write(self.p("packages", "gcc", "14.4.0", "experimental", "0002-x.patch"), b"x")

    def test_resolves_cached_archive_and_verifies_digests(self):
        write(self.p("src", "gcc-14.4.0.tar.xz"), self.data)
        info = g.resolve_tarball("gcc", "14.4.0", self.p("src"), self.pkgdir)
        self.assertEqual(info["file"], "gcc-14.4.0.tar.xz")
        self.assertEqual(info["sha256"], sha(self.data))
        self.assertEqual(info["sha512"], sha(self.data, "sha512"))

    def test_prefers_first_archive_format_when_several_cached(self):
        write(self.p("src", "gcc-14.4.0.tar.gz"), self.data)
        write(self.p("src", "gcc-14.4.0.tar.xz"), self.data)
        info = g.resolve_tarball("gcc", "14.4.0", self.p("src"), self.pkgdir)
        self.assertEqual(info["file"], "gcc-14.4.0.tar.xz")

    def test_missing_archive_is_an_error(self):
        os.makedirs(self.p("src"))
        with self.assertRaisesRegex(g.SbomError, "no cached source archive for gcc 14.4.0"):
            g.resolve_tarball("gcc", "14.4.0", self.p("src"), self.pkgdir)

    def test_digest_mismatch_is_an_error(self):
        write(self.p("src", "gcc-14.4.0.tar.xz"), b"tampered")
        with self.assertRaisesRegex(g.SbomError, "checksum mismatch"):
            g.resolve_tarball("gcc", "14.4.0", self.p("src"), self.pkgdir)

    def test_missing_chksum_file_is_an_error(self):
        with self.assertRaisesRegex(g.SbomError, "chksum"):
            g.resolve_tarball("gcc", "9.9.9", self.p("src"), self.pkgdir)

    def test_bundled_patches_are_top_level_only_and_sorted(self):
        patches = g.bundled_patches("gcc", "14.4.0", self.pkgdir)
        self.assertEqual([p["path"] for p in patches],
                         ["gcc/14.4.0/0000-a.patch", "gcc/14.4.0/0001-b.patch"])
        self.assertEqual(patches[0]["sha256"], sha(b"patch a"))
        self.assertEqual(patches[0]["sha1"], sha(b"patch a", "sha1"))


class AttributeTest(unittest.TestCase):
    CASES = [
        ("bin/%s-gcc" % T, "gcc"),
        ("bin/%s-g++" % T, "gcc"),
        ("bin/%s-gcc-14.4.0" % T, "gcc"),
        ("bin/%s-lto-dump" % T, "gcc"),
        ("libexec/gcc/%s/14.4.0/cc1plus" % T, "gcc"),
        ("lib/gcc/%s/14.4.0/crtbegin.o" % T, "gcc"),
        ("lib/bfd-plugins/liblto_plugin.so" % (), "gcc"),
        ("%s/sysroot/lib64/libstdc++.so.6.0.33" % T, "gcc"),
        ("%s/sysroot/lib64/libgcc_s.so.1" % T, "gcc"),
        ("%s/sysroot/lib64/libasan_preinit.o" % T, "gcc"),
        ("%s/sysroot/usr/lib64/libstdc++fs.a" % T, "gcc"),
        ("%s/lib64/libstdc++.a" % T, "gcc"),
        ("%s/include/c++/14.4.0/vector" % T, "gcc"),
        ("bin/%s-ld.bfd" % T, "binutils"),
        ("bin/%s-objdump" % T, "binutils"),
        ("%s/bin/as" % T, "binutils"),
        ("bin/%s-gdb" % T, "gdb"),
        ("%s/debug-root/usr/bin/gdbserver" % T, "gdb"),
        ("%s/sysroot/lib64/libc.so.6" % T, "glibc"),
        ("%s/sysroot/usr/lib64/libc.a" % T, "glibc"),
        ("%s/sysroot/sbin/ldconfig" % T, "glibc"),
        ("%s/sysroot/usr/include/stdio.h" % T, "glibc"),
        ("%s/sysroot/usr/include/linux/types.h" % T, "linux"),
        ("%s/sysroot/usr/include/asm-generic/int-ll64.h" % T, "linux"),
        ("share/licenses/gmp/COPYING" % (), "gmp"),
    ]

    def test_known_paths(self):
        for path, pkg in self.CASES:
            with self.subTest(path=path):
                self.assertEqual(g.attribute(path, T), pkg)

    def test_unknown_path_returns_none(self):
        self.assertIsNone(g.attribute("bin/%s-mystery" % T, T))


class DpkgTest(unittest.TestCase):
    def test_parses_installed_packages_only(self):
        text = ("installed\tlibc6\t2.28-10+deb10u4\tamd64\tglibc\t2.28-10+deb10u4\n"
                "config-files\told\t1.0\tamd64\told\t1.0\n"
                "installed\tg++\t4:8.3.0-1\tamd64\tgcc-defaults\t1.181\n")
        self.assertEqual(g.dpkg_packages(text), [
            {"name": "libc6", "version": "2.28-10+deb10u4", "arch": "amd64",
             "source": "glibc", "source_version": "2.28-10+deb10u4"},
            {"name": "g++", "version": "4:8.3.0-1", "arch": "amd64",
             "source": "gcc-defaults", "source_version": "1.181"},
        ])

    def test_deb_purl_percent_encodes_version(self):
        self.assertEqual(
            g.deb_purl({"name": "g++", "version": "4:8.3.0-1+b1", "arch": "amd64"}),
            "pkg:deb/debian/g%2B%2B@4%3A8.3.0-1%2Bb1?arch=amd64&distro=debian-10")


class VerificationCodeTest(unittest.TestCase):
    def test_matches_spdx_algorithm(self):
        a, b = sha(b"a", "sha1"), sha(b"b", "sha1")
        expected = hashlib.sha1((min(a, b) + max(a, b)).encode()).hexdigest()
        self.assertEqual(g.verification_code([b, a]), expected)


class ScanTest(TmpDirTest):
    def test_lists_regular_files_skips_symlinks_and_classifies(self):
        write(self.p("p", "bin", "tool"), b"\x7fELF" + b"\0" * 12)
        write(self.p("p", "lib", "libx.a"), b"!<arch>\nrest")
        write(self.p("p", "include", "x.h"), b"int x;")
        os.symlink("tool", self.p("p", "bin", "alias"))
        files = g.scan_prefix(self.p("p"))
        self.assertEqual([(f["path"], f["kind"]) for f in files],
                         [("bin/tool", "BINARY"), ("include/x.h", None), ("lib/libx.a", "ARCHIVE")])
        self.assertEqual(files[2]["sha1"], sha(b"!<arch>\nrest", "sha1"))


class BuildDocumentTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, "sbom", "components.json")) as f:
            self.meta = json.load(f)
        self.doc = g.build_document(self.inputs())

    def inputs(self):
        return {
            "target": T,
            "version": "1.0.0",
            "created": "2026-11-03T00:00:00Z",
            "namespace": "https://spdx.org/spdxdocs/tcw-test",
            "tarball": {"file": "%s.tar.xz" % T, "sha256": "a" * 64},
            "components": [
                {"pkg": "gcc", "version": "14.4.0", "meta": self.meta["gcc"],
                 "archive": {"file": "gcc-14.4.0.tar.xz", "sha256": "1" * 64, "sha512": "2" * 128},
                 "patches": [{"path": "gcc/14.4.0/0000-a.patch", "sha1": "3" * 40, "sha256": "4" * 64}]},
                {"pkg": "gmp", "version": "6.3.0", "meta": self.meta["gmp"],
                 "archive": {"file": "gmp-6.3.0.tar.xz", "sha256": "5" * 64, "sha512": "6" * 128},
                 "patches": []},
                {"pkg": "linux", "version": "6.1.175", "meta": self.meta["linux"],
                 "archive": {"file": "linux-6.1.175.tar.xz", "sha256": "e" * 64, "sha512": "f" * 128},
                 "patches": []},
            ],
            "files": [
                {"path": "bin/%s-gcc" % T, "sha1": "7" * 40, "sha256": "8" * 64,
                 "kind": "BINARY", "pkg": "gcc"},
                {"path": "include/readme", "sha1": "9" * 40, "sha256": "b" * 64,
                 "kind": None, "pkg": None},
            ],
            "ctng": {"version": "1.29.0", "url": "https://example.org/ct.tar.xz",
                     "sha512": "c" * 128, "sha256": "d" * 64},
            "base_image": "debian:10@sha256:" + "0" * 64,
            "dpkg": [
                {"name": "libc6", "version": "2.28-10+deb10u4", "arch": "amd64",
                 "source": "glibc", "source_version": "2.28-10+deb10u4"},
                {"name": "make", "version": "4.2.1-1.2", "arch": "amd64",
                 "source": "make-dfsg", "source_version": "4.2.1-1.2"},
                {"name": "libc6-dev", "version": "2.28-10+deb10u4", "arch": "amd64",
                 "source": "glibc", "source_version": "2.28-10+deb10u4"},
                {"name": "libgcc-8-dev", "version": "8.3.0-6", "arch": "amd64",
                 "source": "gcc-8", "source_version": "8.3.0-6"},
                {"name": "libstdc++-8-dev", "version": "8.3.0-6", "arch": "amd64",
                 "source": "gcc-8", "source_version": "8.3.0-6"},
            ],
            "ctng_build_deps": [
                {"name": "libncurses-dev", "version": "6.1+20181013-2+deb10u5", "arch": "amd64",
                 "source": "ncurses", "source_version": "6.1+20181013-2+deb10u5"},
            ],
        }

    def test_host_runtime_debs_are_static_links(self):
        root = self.pkg("%s-toolchain" % T)["SPDXID"]
        for name in ("libc6-dev", "libgcc-8-dev", "libstdc++-8-dev"):
            with self.subTest(name=name):
                self.assertTrue(self.rel(root, "STATIC_LINK", self.pkg(name)["SPDXID"]))
        self.assertFalse(self.rel(root, "STATIC_LINK", self.pkg("make")["SPDXID"]))

    def test_missing_host_runtime_deb_is_an_error(self):
        inp = self.inputs()
        inp["dpkg"] = [d for d in inp["dpkg"] if d["name"] != "libstdc++-8-dev"]
        with self.assertRaisesRegex(g.SbomError, "libstdc\\+\\+-8-dev"):
            g.build_document(inp)

    def test_ctng_build_only_dependencies(self):
        dev = self.pkg("libncurses-dev")
        self.assertTrue(self.rel(dev["SPDXID"], "BUILD_DEPENDENCY_OF",
                                 self.pkg("crosstool-ng")["SPDXID"]))
        root = self.pkg("%s-toolchain" % T)["SPDXID"]
        self.assertFalse(self.rel(dev["SPDXID"], "BUILD_TOOL_OF", root))

    def pkg(self, name):
        return next(p for p in self.doc["packages"] if p["name"] == name)

    def rel(self, a, kind, b):
        return {"spdxElementId": a, "relationshipType": kind, "relatedSpdxElement": b} \
            in self.doc["relationships"]

    def test_document_header(self):
        d = self.doc
        self.assertEqual(d["spdxVersion"], "SPDX-2.3")
        self.assertEqual(d["dataLicense"], "CC0-1.0")
        self.assertEqual(d["SPDXID"], "SPDXRef-DOCUMENT")
        self.assertEqual(d["documentNamespace"], "https://spdx.org/spdxdocs/tcw-test")
        self.assertFalse(any(c.startswith("Organization:") for c in d["creationInfo"]["creators"]))
        self.assertIn("Tool: crosstool-NG-1.29.0", d["creationInfo"]["creators"])

    def test_root_package(self):
        root = self.pkg("%s-toolchain" % T)
        self.assertEqual(root["supplier"], "NOASSERTION")
        self.assertEqual(root["versionInfo"], "1.0.0")
        self.assertEqual(root["packageFileName"], "%s.tar.xz" % T)
        self.assertEqual(root["checksums"], [{"algorithm": "SHA256", "checksumValue": "a" * 64}])
        self.assertTrue(root["filesAnalyzed"])
        self.assertEqual(root["packageVerificationCode"]["packageVerificationCodeValue"],
                         g.verification_code(["7" * 40, "9" * 40]))
        self.assertTrue(self.rel("SPDXRef-DOCUMENT", "DESCRIBES", root["SPDXID"]))

    def test_component_package_fields(self):
        gcc = self.pkg("gcc")
        self.assertEqual(gcc["versionInfo"], "14.4.0")
        self.assertEqual(gcc["licenseDeclared"], self.meta["gcc"]["license"])
        self.assertEqual(gcc["downloadLocation"],
                         "https://ftp.gnu.org/gnu/gcc/gcc-14.4.0/gcc-14.4.0.tar.xz")
        self.assertIn({"algorithm": "SHA512", "checksumValue": "2" * 128}, gcc["checksums"])
        refs = {r["referenceType"]: r["referenceLocator"] for r in gcc["externalRefs"]}
        self.assertEqual(refs["cpe23Type"], "cpe:2.3:a:gnu:gcc:14.4.0:*:*:*:*:*:*:*")
        self.assertTrue(refs["purl"].startswith("pkg:generic/gcc@14.4.0?"))
        self.assertEqual(self.pkg("linux")["downloadLocation"],
                         "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.1.175.tar.xz")

    def test_component_relationships(self):
        root = self.pkg("%s-toolchain" % T)["SPDXID"]
        self.assertTrue(self.rel(root, "CONTAINS", self.pkg("gcc")["SPDXID"]))
        self.assertTrue(self.rel(root, "STATIC_LINK", self.pkg("gmp")["SPDXID"]))

    def test_patches_are_files_applied_to_component(self):
        patch = next(f for f in self.doc["files"] if f["fileName"].endswith("0000-a.patch"))
        self.assertEqual(patch["fileName"], "./crosstool-ng/packages/gcc/14.4.0/0000-a.patch")
        self.assertTrue(self.rel(patch["SPDXID"], "PATCH_APPLIED", self.pkg("gcc")["SPDXID"]))

    def test_toolchain_files_contained_and_attributed(self):
        root = self.pkg("%s-toolchain" % T)["SPDXID"]
        f = next(x for x in self.doc["files"] if x["fileName"] == "./%s/bin/%s-gcc" % (T, T))
        self.assertEqual(f["fileTypes"], ["BINARY"])
        self.assertIn({"algorithm": "SHA1", "checksumValue": "7" * 40}, f["checksums"])
        self.assertTrue(self.rel(root, "CONTAINS", f["SPDXID"]))
        self.assertTrue(self.rel(f["SPDXID"], "GENERATED_FROM", self.pkg("gcc")["SPDXID"]))
        other = next(x for x in self.doc["files"] if x["fileName"].endswith("include/readme"))
        self.assertFalse(any(r["spdxElementId"] == other["SPDXID"]
                             for r in self.doc["relationships"]))

    def test_build_tools(self):
        root = self.pkg("%s-toolchain" % T)["SPDXID"]
        ctng = self.pkg("crosstool-ng")
        self.assertTrue(self.rel(ctng["SPDXID"], "BUILD_TOOL_OF", root))
        image = self.pkg("debian")
        self.assertTrue(self.rel(image["SPDXID"], "BUILD_TOOL_OF", root))
        make = self.pkg("make")
        refs = {r["referenceType"]: r["referenceLocator"] for r in make["externalRefs"]}
        self.assertEqual(refs["purl"], "pkg:deb/debian/make@4.2.1-1.2?arch=amd64&distro=debian-10")
        self.assertEqual(make["downloadLocation"],
                         "https://snapshot.debian.org/package/make-dfsg/4.2.1-1.2/")
        self.assertTrue(self.rel(make["SPDXID"], "BUILD_TOOL_OF", root))
        self.assertTrue(self.rel(root, "DYNAMIC_LINK", self.pkg("libc6")["SPDXID"]))

    def test_ids_unique_and_relationships_resolve(self):
        ids = [p["SPDXID"] for p in self.doc["packages"]] + [f["SPDXID"] for f in self.doc["files"]]
        self.assertEqual(len(ids), len(set(ids)))
        known = set(ids) | {"SPDXRef-DOCUMENT"}
        for r in self.doc["relationships"]:
            self.assertIn(r["spdxElementId"], known)
            self.assertIn(r["relatedSpdxElement"], known)
        import re
        for i in ids:
            self.assertRegex(i, r"^SPDXRef-[A-Za-z0-9.\-]+$")

    def test_output_is_deterministic(self):
        self.assertEqual(json.dumps(self.doc, sort_keys=True),
                         json.dumps(g.build_document(self.inputs()), sort_keys=True))


if __name__ == "__main__":
    unittest.main()
