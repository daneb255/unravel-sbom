"""Tests for each individual scanner and the SPDX reporter."""

from __future__ import annotations

import json
from pathlib import Path


FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------


class TestPackageJsonScanner:
    def _scan(self, path: Path):
        from unravel_sbom.scanners.npm import PackageJsonScanner

        return PackageJsonScanner().scan(path)

    def test_finds_direct_dependencies(self):
        result = self._scan(FIXTURES / "npm" / "package.json")
        names = {p.name for p in result.packages}
        assert "express" in names
        assert "lodash" in names
        assert "jest" in names
        assert "@types/node" in names

    def test_strips_range_prefix(self):
        result = self._scan(FIXTURES / "npm" / "package.json")
        express = next(p for p in result.packages if p.name == "express")
        assert express.version == "4.18.2"

    def test_scoped_package_purl(self):
        result = self._scan(FIXTURES / "npm" / "package.json")
        types_node = next(p for p in result.packages if p.name == "@types/node")
        assert types_node.purl.startswith("pkg:npm/types/node@")


class TestPackageLockScanner:
    def _scan(self, path: Path):
        from unravel_sbom.scanners.npm import PackageLockScanner

        return PackageLockScanner().scan(path)

    def test_finds_resolved_packages(self):
        result = self._scan(FIXTURES / "npm" / "package-lock.json")
        names = {p.name for p in result.packages}
        assert "express" in names
        assert "lodash" in names
        assert "jest" in names

    def test_resolved_version(self):
        result = self._scan(FIXTURES / "npm" / "package-lock.json")
        express = next(p for p in result.packages if p.name == "express")
        assert express.version == "4.18.2"

    def test_license_populated(self):
        result = self._scan(FIXTURES / "npm" / "package-lock.json")
        express = next(p for p in result.packages if p.name == "express")
        assert express.license_id == "MIT"


# ---------------------------------------------------------------------------
# PyPI
# ---------------------------------------------------------------------------


class TestRequirementsTxtScanner:
    def _scan(self, path: Path):
        from unravel_sbom.scanners.pypi import RequirementsTxtScanner

        return RequirementsTxtScanner().scan(path)

    def test_finds_pinned_package(self):
        result = self._scan(FIXTURES / "pypi" / "requirements.txt")
        names = {p.name for p in result.packages}
        assert "requests" in names

    def test_exact_version_extracted(self):
        result = self._scan(FIXTURES / "pypi" / "requirements.txt")
        req = next(p for p in result.packages if p.name == "requests")
        assert req.version == "2.31.0"

    def test_unpinned_package_present(self):
        result = self._scan(FIXTURES / "pypi" / "requirements.txt")
        names = {p.name for p in result.packages}
        assert "numpy" in names

    def test_comment_lines_skipped(self):
        result = self._scan(FIXTURES / "pypi" / "requirements.txt")
        # No package named '#' or starting with '#'
        for pkg in result.packages:
            assert not pkg.name.startswith("#")

    def test_purl_format(self):
        result = self._scan(FIXTURES / "pypi" / "requirements.txt")
        req = next(p for p in result.packages if p.name == "requests")
        assert req.purl == "pkg:pypi/requests@2.31.0"


class TestPyprojectTomlScanner:
    def _scan(self, path: Path):
        from unravel_sbom.scanners.pypi import PyprojectTomlScanner

        return PyprojectTomlScanner().scan(path)

    def test_pep621_deps(self):
        result = self._scan(FIXTURES / "pypi" / "pyproject.toml")
        names = {p.name for p in result.packages}
        assert "fastapi" in names
        assert "sqlalchemy" in names

    def test_poetry_deps(self):
        result = self._scan(FIXTURES / "pypi" / "pyproject.toml")
        names = {p.name for p in result.packages}
        assert "httpx" in names
        assert "pydantic" in names

    def test_python_itself_excluded(self):
        result = self._scan(FIXTURES / "pypi" / "pyproject.toml")
        assert all(p.name.lower() != "python" for p in result.packages)


class TestPoetryLockScanner:
    def _scan(self, path: Path):
        from unravel_sbom.scanners.pypi import PoetryLockScanner

        return PoetryLockScanner().scan(path)

    def test_finds_locked_packages(self):
        result = self._scan(FIXTURES / "pypi" / "poetry.lock")
        names = {p.name for p in result.packages}
        assert "httpx" in names
        assert "anyio" in names

    def test_exact_version(self):
        result = self._scan(FIXTURES / "pypi" / "poetry.lock")
        httpx = next(p for p in result.packages if p.name == "httpx")
        assert httpx.version == "0.25.2"


# ---------------------------------------------------------------------------
# Conan
# ---------------------------------------------------------------------------


class TestConanfileTxtScanner:
    def _scan(self, path: Path):
        from unravel_sbom.scanners.conan import ConanfileTxtScanner

        return ConanfileTxtScanner().scan(path)

    def test_finds_requires(self):
        result = self._scan(FIXTURES / "conan" / "conanfile.txt")
        names = {p.name for p in result.packages}
        assert "zlib" in names
        assert "boost" in names
        assert "openssl" in names

    def test_version_parsed(self):
        result = self._scan(FIXTURES / "conan" / "conanfile.txt")
        zlib = next(p for p in result.packages if p.name == "zlib")
        assert zlib.version == "1.2.13"

    def test_channel_stripped_from_version(self):
        result = self._scan(FIXTURES / "conan" / "conanfile.txt")
        boost = next(p for p in result.packages if p.name == "boost")
        assert boost.version == "1.83.0"  # @conan/stable not in version


class TestConanfilePyScanner:
    def _scan(self, path: Path):
        from unravel_sbom.scanners.conan import ConanfilePyScanner

        return ConanfilePyScanner().scan(path)

    def test_finds_requires_list(self):
        result = self._scan(FIXTURES / "conan" / "conanfile.py")
        names = {p.name for p in result.packages}
        assert "zlib" in names
        assert "fmt" in names

    def test_finds_build_requires(self):
        result = self._scan(FIXTURES / "conan" / "conanfile.py")
        names = {p.name for p in result.packages}
        assert "cmake" in names

    def test_finds_method_call_requires(self):
        result = self._scan(FIXTURES / "conan" / "conanfile.py")
        names = {p.name for p in result.packages}
        assert "nlohmann_json" in names


# ---------------------------------------------------------------------------
# Makefile
# ---------------------------------------------------------------------------


class TestMakefileScanner:
    def _scan(self, path: Path):
        from unravel_sbom.scanners.makefile import MakefileScanner

        return MakefileScanner().scan(path)

    def test_ldflags_libs(self):
        result = self._scan(FIXTURES / "makefile" / "Makefile")
        names = {p.name for p in result.packages}
        assert "ssl" in names
        assert "crypto" in names
        assert "z" in names

    def test_ldlibs(self):
        result = self._scan(FIXTURES / "makefile" / "Makefile")
        names = {p.name for p in result.packages}
        assert "pthread" in names
        assert "m" in names

    def test_pkg_config(self):
        result = self._scan(FIXTURES / "makefile" / "Makefile")
        names = {p.name for p in result.packages}
        assert "openssl" in names
        assert "libpng16" in names

    def test_git_clone_packages_found(self):
        result = self._scan(FIXTURES / "makefile" / "Makefile.yocto")
        names = {p.name for p in result.packages}
        assert "poky" in names
        assert "meta-openembedded" in names
        assert "meta-raspberrypi" in names
        assert "meta-96boards" in names

    def test_git_clone_version_from_branch_variable(self):
        result = self._scan(FIXTURES / "makefile" / "Makefile.yocto")
        versions = {p.name: p.version for p in result.packages}
        assert versions["poky"] == "kirkstone"
        assert versions["meta-openembedded"] == "kirkstone"

    def test_git_clone_no_duplicates(self):
        result = self._scan(FIXTURES / "makefile" / "Makefile.yocto")
        names = [p.name for p in result.packages]
        assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# Walker integration
# ---------------------------------------------------------------------------


class TestWalker:
    def test_full_fixture_scan(self, tmp_path):
        """Walk the entire fixtures directory and collect all packages."""
        from unravel_sbom.scanners import ALL_SCANNERS
        from unravel_sbom.walker import walk

        result = walk(FIXTURES, ALL_SCANNERS)
        assert len(result.packages) > 10
        assert len(result.errors) == 0

    def test_skips_git_dir(self, tmp_path):
        from unravel_sbom.scanners import ALL_SCANNERS
        from unravel_sbom.walker import walk

        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "package.json").write_text('{"dependencies": {"evil": "1.0.0"}}')
        result = walk(tmp_path, ALL_SCANNERS)
        assert all(p.name != "evil" for p in result.packages)

    def test_error_isolation(self, tmp_path):
        """A broken file must not abort the walk; other files are still scanned."""
        from unravel_sbom.scanners import ALL_SCANNERS
        from unravel_sbom.walker import walk

        (tmp_path / "package.json").write_text("NOT JSON {{{{")
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        result = walk(tmp_path, ALL_SCANNERS)
        names = {p.name for p in result.packages}
        assert "requests" in names
        assert len(result.errors) == 1


# ---------------------------------------------------------------------------
# SPDX reporter
# ---------------------------------------------------------------------------


class TestSpdxReporter:
    def test_valid_spdx_version(self):
        from unravel_sbom.reporters.spdx import generate
        from unravel_sbom.scanners import ALL_SCANNERS
        from unravel_sbom.walker import walk

        result = walk(FIXTURES, ALL_SCANNERS)
        doc = generate(result, scan_root=FIXTURES)
        assert doc["spdxVersion"] == "SPDX-2.3"
        assert doc["dataLicense"] == "CC0-1.0"

    def test_packages_have_required_fields(self):
        from unravel_sbom.reporters.spdx import generate
        from unravel_sbom.scanners import ALL_SCANNERS
        from unravel_sbom.walker import walk

        result = walk(FIXTURES, ALL_SCANNERS)
        doc = generate(result, scan_root=FIXTURES)
        required = {
            "SPDXID",
            "name",
            "versionInfo",
            "downloadLocation",
            "filesAnalyzed",
            "licenseConcluded",
            "licenseDeclared",
            "copyrightText",
        }
        for pkg in doc["packages"]:
            for field in required:
                assert field in pkg, (
                    f"Missing field {field!r} in package {pkg.get('name')}"
                )

    def test_packages_have_purl(self):
        from unravel_sbom.reporters.spdx import generate
        from unravel_sbom.scanners import ALL_SCANNERS
        from unravel_sbom.walker import walk

        result = walk(FIXTURES, ALL_SCANNERS)
        doc = generate(result, scan_root=FIXTURES)
        for pkg in doc["packages"]:
            ext_refs = pkg.get("externalRefs", [])
            purls = [r for r in ext_refs if r.get("referenceType") == "purl"]
            assert purls, f"No PURL for {pkg['name']}"
            assert purls[0]["referenceLocator"].startswith("pkg:")

    def test_deduplication(self):
        from unravel_sbom.models import Ecosystem, Package, ScanResult
        from unravel_sbom.reporters.spdx import generate
        from pathlib import Path

        result = ScanResult()
        result.packages = [
            Package("requests", "2.31.0", Ecosystem.PYPI),
            Package("requests", "2.31.0", Ecosystem.PYPI),  # duplicate
        ]
        doc = generate(result, scan_root=Path("/tmp"))
        assert len(doc["packages"]) == 1

    def test_relationships_describe_all_packages(self):
        from unravel_sbom.reporters.spdx import generate
        from unravel_sbom.scanners import ALL_SCANNERS
        from unravel_sbom.walker import walk

        result = walk(FIXTURES, ALL_SCANNERS)
        doc = generate(result, scan_root=FIXTURES)
        described = {
            r["relatedSpdxElement"]
            for r in doc["relationships"]
            if r["relationshipType"] == "DESCRIBES"
        }
        for pkg in doc["packages"]:
            assert pkg["SPDXID"] in described

    def test_write_produces_valid_json(self, tmp_path):
        from unravel_sbom.reporters.spdx import generate, write
        from unravel_sbom.scanners import ALL_SCANNERS
        from unravel_sbom.walker import walk

        result = walk(FIXTURES, ALL_SCANNERS)
        doc = generate(result, scan_root=FIXTURES)
        out = tmp_path / "sbom.spdx.json"
        write(doc, out)
        loaded = json.loads(out.read_text())
        assert loaded["spdxVersion"] == "SPDX-2.3"


# ---------------------------------------------------------------------------
# CycloneDX reporter
# ---------------------------------------------------------------------------


class TestCycloneDxReporter:
    def _generate(self):
        from unravel_sbom.reporters.cyclonedx import generate
        from unravel_sbom.scanners import ALL_SCANNERS
        from unravel_sbom.walker import walk

        result = walk(FIXTURES, ALL_SCANNERS)
        return generate(result, scan_root=FIXTURES)

    def test_bom_format_and_spec_version(self):
        doc = self._generate()
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.6"

    def test_serial_number_is_urn_uuid(self):
        import re

        doc = self._generate()
        assert re.match(
            r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            doc["serialNumber"],
        )

    def test_metadata_has_timestamp_and_tool(self):
        doc = self._generate()
        meta = doc["metadata"]
        assert "timestamp" in meta
        tools = meta["tools"]["components"]
        assert any(t["name"] == "unravel-sbom" for t in tools)

    def test_components_have_required_fields(self):
        doc = self._generate()
        for comp in doc["components"]:
            assert "type" in comp
            assert "name" in comp
            assert "version" in comp
            assert "purl" in comp
            assert comp["purl"].startswith("pkg:")

    def test_component_type_is_library(self):
        doc = self._generate()
        for comp in doc["components"]:
            assert comp["type"] == "library"

    def test_bom_ref_is_stable(self):
        doc = self._generate()
        refs = [c["bom-ref"] for c in doc["components"]]
        assert len(refs) == len(set(refs)), "bom-ref values must be unique"

    def test_license_spdx_id_structure(self):
        from unravel_sbom.models import Ecosystem, Package, ScanResult
        from unravel_sbom.reporters.cyclonedx import generate

        result = ScanResult()
        result.packages = [
            Package("requests", "2.31.0", Ecosystem.PYPI, license_id="Apache-2.0"),
        ]
        doc = generate(result, scan_root=Path("/tmp"))
        lic = doc["components"][0]["licenses"][0]
        assert lic == {"license": {"id": "Apache-2.0", "acknowledgement": "declared"}}

    def test_compound_license_uses_expression(self):
        from unravel_sbom.models import Ecosystem, Package, ScanResult
        from unravel_sbom.reporters.cyclonedx import generate

        result = ScanResult()
        result.packages = [
            Package("dual", "1.0.0", Ecosystem.NPM, license_id="MIT OR Apache-2.0"),
        ]
        doc = generate(result, scan_root=Path("/tmp"))
        lic = doc["components"][0]["licenses"][0]
        assert "expression" in lic

    def test_noassertion_license_omitted(self):
        from unravel_sbom.models import Ecosystem, Package, ScanResult
        from unravel_sbom.reporters.cyclonedx import generate

        result = ScanResult()
        result.packages = [Package("unknown-lic", "1.0", Ecosystem.PYPI)]
        doc = generate(result, scan_root=Path("/tmp"))
        assert "licenses" not in doc["components"][0]

    def test_deduplication(self):
        from unravel_sbom.models import Ecosystem, Package, ScanResult
        from unravel_sbom.reporters.cyclonedx import generate

        result = ScanResult()
        result.packages = [
            Package("lodash", "4.17.21", Ecosystem.NPM),
            Package("lodash", "4.17.21", Ecosystem.NPM),
        ]
        doc = generate(result, scan_root=Path("/tmp"))
        assert len(doc["components"]) == 1

    def test_write_produces_valid_json(self, tmp_path):
        from unravel_sbom.reporters.cyclonedx import generate, write
        from unravel_sbom.scanners import ALL_SCANNERS
        from unravel_sbom.walker import walk

        result = walk(FIXTURES, ALL_SCANNERS)
        doc = generate(result, scan_root=FIXTURES)
        out = tmp_path / "sbom.cdx.json"
        write(doc, out)
        loaded = json.loads(out.read_text())
        assert loaded["bomFormat"] == "CycloneDX"
        assert loaded["specVersion"] == "1.6"
        assert len(loaded["components"]) > 0
