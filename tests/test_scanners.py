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

    def test_dependencies_populated(self):
        result = self._scan(FIXTURES / "npm" / "package-lock.json")
        express = next(p for p in result.packages if p.name == "express")
        assert express.depends_on == ["lodash"]


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

    def test_dependencies_populated(self):
        result = self._scan(FIXTURES / "pypi" / "poetry.lock")
        httpx = next(p for p in result.packages if p.name == "httpx")
        assert httpx.depends_on == ["anyio"]
        anyio = next(p for p in result.packages if p.name == "anyio")
        assert anyio.depends_on == []


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
# Go
# ---------------------------------------------------------------------------


class TestGoSumScanner:
    def _scan(self, path: Path):
        from unravel_sbom.scanners.golang import GoSumScanner

        return GoSumScanner().scan(path)

    def test_finds_locked_packages(self):
        result = self._scan(FIXTURES / "golang" / "go.sum")
        names = {p.name for p in result.packages}
        assert "github.com/gin-gonic/gin" in names
        assert "github.com/google/uuid" in names
        assert "golang.org/x/crypto" in names

    def test_strips_gomod_suffix_and_deduplicates(self):
        result = self._scan(FIXTURES / "golang" / "go.sum")
        gin = [p for p in result.packages if p.name == "github.com/gin-gonic/gin"]
        assert len(gin) == 1
        assert gin[0].version == "v1.9.1"

    def test_purl_format(self):
        result = self._scan(FIXTURES / "golang" / "go.sum")
        gin = next(p for p in result.packages if p.name == "github.com/gin-gonic/gin")
        assert gin.purl == "pkg:golang/github.com/gin-gonic/gin@v1.9.1"


class TestGoModScanner:
    def _scan(self, path: Path):
        from unravel_sbom.scanners.golang import GoModScanner

        return GoModScanner().scan(path)

    def test_finds_require_block(self):
        result = self._scan(FIXTURES / "golang" / "go.mod")
        names = {p.name for p in result.packages}
        assert "github.com/gin-gonic/gin" in names
        assert "github.com/google/uuid" in names
        assert "golang.org/x/crypto" in names

    def test_skips_root_module(self):
        result = self._scan(FIXTURES / "golang" / "go.mod")
        names = {p.name for p in result.packages}
        assert "github.com/example/my-go-app" not in names


# ---------------------------------------------------------------------------
# Cargo (Rust)
# ---------------------------------------------------------------------------


class TestCargoLockScanner:
    def _scan(self, path: Path):
        from unravel_sbom.scanners.cargo import CargoLockScanner

        return CargoLockScanner().scan(path)

    def test_finds_packages(self):
        result = self._scan(FIXTURES / "cargo" / "Cargo.lock")
        names = {p.name for p in result.packages}
        assert "anyhow" in names
        assert "serde" in names
        assert "serde_derive" in names
        assert "tokio" in names

    def test_depends_on_populated(self):
        result = self._scan(FIXTURES / "cargo" / "Cargo.lock")
        app = next(p for p in result.packages if p.name == "my-rust-app")
        assert "anyhow" in app.depends_on
        assert "serde" in app.depends_on
        assert "tokio" in app.depends_on

    def test_purl_format(self):
        result = self._scan(FIXTURES / "cargo" / "Cargo.lock")
        serde = next(p for p in result.packages if p.name == "serde")
        assert serde.purl == "pkg:cargo/serde@1.0.197"


class TestCargoTomlScanner:
    def _scan(self, path: Path):
        from unravel_sbom.scanners.cargo import CargoTomlScanner

        return CargoTomlScanner().scan(path)

    def test_finds_dependencies(self):
        result = self._scan(FIXTURES / "cargo" / "Cargo.toml")
        names = {p.name for p in result.packages}
        assert "serde" in names
        assert "tokio" in names
        assert "anyhow" in names
        assert "tempfile" in names

    def test_inline_table_version(self):
        result = self._scan(FIXTURES / "cargo" / "Cargo.toml")
        serde = next(p for p in result.packages if p.name == "serde")
        assert serde.version == "1.0.197"


# ---------------------------------------------------------------------------
# Maven (Java)
# ---------------------------------------------------------------------------


class TestMavenScanner:
    def _scan(self, path: Path):
        from unravel_sbom.scanners.maven import PomXmlScanner

        return PomXmlScanner().scan(path)

    def test_finds_dependencies(self):
        result = self._scan(FIXTURES / "maven" / "pom.xml")
        names = {p.name for p in result.packages}
        assert "org.springframework:spring-core" in names
        assert "com.fasterxml.jackson.core:jackson-databind" in names
        assert "org.slf4j:slf4j-api" in names

    def test_resolves_properties(self):
        result = self._scan(FIXTURES / "maven" / "pom.xml")
        spring = next(p for p in result.packages if p.name == "org.springframework:spring-core")
        assert spring.version == "6.1.2"
        jackson = next(p for p in result.packages if p.name == "com.fasterxml.jackson.core:jackson-databind")
        assert jackson.version == "2.16.0"

    def test_purl_format(self):
        result = self._scan(FIXTURES / "maven" / "pom.xml")
        spring = next(p for p in result.packages if p.name == "org.springframework:spring-core")
        assert spring.purl == "pkg:maven/org.springframework/spring-core@6.1.2"


# ---------------------------------------------------------------------------
# Gradle (Java / Kotlin)
# ---------------------------------------------------------------------------


class TestGradleScanner:
    def _scan(self, path: Path):
        from unravel_sbom.scanners.gradle import GradleScanner

        return GradleScanner().scan(path)

    def test_build_gradle_string_and_map_notation(self):
        result = self._scan(FIXTURES / "gradle" / "build.gradle")
        names = {p.name for p in result.packages}
        assert "org.springframework.boot:spring-boot-starter-web" in names
        assert "com.google.guava:guava" in names
        assert "org.junit.jupiter:junit-jupiter" in names

        guava = next(p for p in result.packages if p.name == "com.google.guava:guava")
        assert guava.version == "32.1.3-jre"
        assert guava.purl == "pkg:maven/com.google.guava/guava@32.1.3-jre"

    def test_build_gradle_kts(self):
        result = self._scan(FIXTURES / "gradle" / "build.gradle.kts")
        names = {p.name for p in result.packages}
        assert "org.jetbrains.kotlinx:kotlinx-coroutines-core" in names
        assert "io.ktor:ktor-server-core" in names


# ---------------------------------------------------------------------------
# RubyGems (Ruby)
# ---------------------------------------------------------------------------


class TestRubyGemsScanners:
    def test_gemfile_lock_scanner(self):
        from unravel_sbom.scanners.rubygems import GemfileLockScanner

        result = GemfileLockScanner().scan(FIXTURES / "rubygems" / "Gemfile.lock")
        names = {p.name for p in result.packages}
        assert "rails" in names
        assert "actioncable" in names
        assert "puma" in names
        assert "rack" in names

        rails = next(p for p in result.packages if p.name == "rails")
        assert rails.version == "7.1.3"
        assert rails.purl == "pkg:gem/rails@7.1.3"
        assert "actioncable" in rails.depends_on
        assert "actionpack" in rails.depends_on

    def test_gemfile_scanner(self):
        from unravel_sbom.scanners.rubygems import GemfileScanner

        result = GemfileScanner().scan(FIXTURES / "rubygems" / "Gemfile")
        names = {p.name for p in result.packages}
        assert "rails" in names
        assert "puma" in names
        assert "redis" in names

        rails = next(p for p in result.packages if p.name == "rails")
        assert rails.version == "7.1.3"


# ---------------------------------------------------------------------------
# NuGet (.NET)
# ---------------------------------------------------------------------------


class TestNuGetScanner:
    def _scan(self, path: Path):
        from unravel_sbom.scanners.nuget import NuGetScanner

        return NuGetScanner().scan(path)

    def test_csproj_packagereference(self):
        result = self._scan(FIXTURES / "nuget" / "sample.csproj")
        names = {p.name for p in result.packages}
        assert "Newtonsoft.Json" in names
        assert "Serilog" in names

        json_pkg = next(p for p in result.packages if p.name == "Newtonsoft.Json")
        assert json_pkg.version == "13.0.3"
        assert json_pkg.purl == "pkg:nuget/Newtonsoft.Json@13.0.3"

    def test_packages_config(self):
        result = self._scan(FIXTURES / "nuget" / "packages.config")
        names = {p.name for p in result.packages}
        assert "EntityFramework" in names
        assert "NUnit" in names

    def test_packages_lock_json(self):
        result = self._scan(FIXTURES / "nuget" / "packages.lock.json")
        names = {p.name for p in result.packages}
        assert "Newtonsoft.Json" in names
        json_pkg = next(p for p in result.packages if p.name == "Newtonsoft.Json")
        assert json_pkg.version == "13.0.3"
        assert "Microsoft.CSharp" in json_pkg.depends_on


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
    def test_valid_spdx_version_and_context(self):
        from unravel_sbom.reporters.spdx import generate
        from unravel_sbom.scanners import ALL_SCANNERS
        from unravel_sbom.walker import walk

        result = walk(FIXTURES, ALL_SCANNERS)
        doc = generate(result, scan_root=FIXTURES)
        assert doc["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

        doc_node = next(n for n in doc["@graph"] if n.get("type") == "SpdxDocument")
        assert doc_node["dataLicense"] == "https://spdx.org/licenses/CC0-1.0"

        creation_node = next(
            n for n in doc["@graph"] if n.get("type") == "CreationInfo"
        )
        assert creation_node["specVersion"] == "3.0.1"

    def test_packages_have_required_fields(self):
        from unravel_sbom.reporters.spdx import generate
        from unravel_sbom.scanners import ALL_SCANNERS
        from unravel_sbom.walker import walk

        result = walk(FIXTURES, ALL_SCANNERS)
        doc = generate(result, scan_root=FIXTURES)
        pkgs = [n for n in doc["@graph"] if n.get("type") == "software_Package"]
        assert len(pkgs) > 0

        required = {
            "spdxId",
            "name",
            "software_packageVersion",
            "originatedBy",
            "creationInfo",
            "externalIdentifiers",
        }
        for pkg in pkgs:
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
        pkgs = [n for n in doc["@graph"] if n.get("type") == "software_Package"]
        for pkg in pkgs:
            ext_refs = pkg.get("externalIdentifiers", [])
            purls = [
                r for r in ext_refs if r.get("externalIdentifierType") == "packageUrl"
            ]
            assert purls, f"No PURL for {pkg['name']}"
            assert purls[0]["identifier"].startswith("pkg:")

    def test_deduplication(self):
        from pathlib import Path

        from unravel_sbom.models import Ecosystem, Package, ScanResult
        from unravel_sbom.reporters.spdx import generate, package_count

        result = ScanResult()
        result.packages = [
            Package("requests", "2.31.0", Ecosystem.PYPI),
            Package("requests", "2.31.0", Ecosystem.PYPI),  # duplicate
        ]
        doc = generate(result, scan_root=Path("/tmp"))
        assert package_count(doc) == 1

    def test_root_elements_cover_all_packages(self):
        from unravel_sbom.reporters.spdx import generate
        from unravel_sbom.scanners import ALL_SCANNERS
        from unravel_sbom.walker import walk

        result = walk(FIXTURES, ALL_SCANNERS)
        doc = generate(result, scan_root=FIXTURES)
        doc_node = next(n for n in doc["@graph"] if n.get("type") == "SpdxDocument")
        pkgs = [n for n in doc["@graph"] if n.get("type") == "software_Package"]
        pkg_ids = {p["spdxId"] for p in pkgs}
        root_elements = set(doc_node.get("rootElement", []))
        assert pkg_ids.issubset(root_elements)

    def test_write_produces_valid_json(self, tmp_path):
        from unravel_sbom.reporters.spdx import generate, package_count, write
        from unravel_sbom.scanners import ALL_SCANNERS
        from unravel_sbom.walker import walk

        result = walk(FIXTURES, ALL_SCANNERS)
        doc = generate(result, scan_root=FIXTURES)
        out = tmp_path / "sbom.spdx.json"
        write(doc, out)
        loaded = json.loads(out.read_text())
        assert loaded["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
        assert package_count(loaded) > 0

    def test_creator_email_and_fallback(self):
        from pathlib import Path

        from unravel_sbom.models import Ecosystem, Package, ScanResult
        from unravel_sbom.reporters.spdx import generate

        result = ScanResult(packages=[Package("requests", "2.31.0", Ecosystem.PYPI)])
        # With email
        doc_email = generate(
            result, scan_root=Path("/tmp"), creator_email="dev@example.com"
        )
        person_node = next(
            n for n in doc_email["@graph"] if n.get("type") == "Person"
        )
        assert (
            person_node["externalIdentifiers"][0]["externalIdentifierType"]
            == "email"
        )
        assert (
            person_node["externalIdentifiers"][0]["identifier"]
            == "dev@example.com"
        )

        # Fallback (URL)
        doc_fallback = generate(result, scan_root=Path("/tmp"))
        org_node = next(
            n for n in doc_fallback["@graph"] if n.get("type") == "Organization"
        )
        assert (
            org_node["externalIdentifiers"][0]["externalIdentifierType"]
            == "urlScheme"
        )
        assert "unravel" in org_node["externalIdentifiers"][0]["identifier"]

    def test_depends_on_relationships(self):
        from unravel_sbom.reporters.spdx import generate
        from unravel_sbom.scanners.npm import PackageLockScanner

        result = PackageLockScanner().scan(FIXTURES / "npm" / "package-lock.json")
        doc = generate(result, scan_root=FIXTURES)

        depends_rels = [
            n
            for n in doc["@graph"]
            if n.get("type") == "Relationship"
            and n.get("relationshipType") == "dependsOn"
        ]
        express_rel = next(r for r in depends_rels if "express" in r["from"])
        assert any("lodash" in target for target in express_rel["to"])

    def test_logical_component_scope_regression(self):
        from unravel_sbom.reporters.spdx import generate
        from unravel_sbom.scanners import ALL_SCANNERS
        from unravel_sbom.walker import walk

        result = walk(FIXTURES, ALL_SCANNERS)
        doc = generate(result, scan_root=FIXTURES)

        forbidden_keys = {
            "sha512",
            "SHA-512",
            "filename",
            "fileAnalyzed",
            "filesAnalyzed",
            "downloadLocation",
            "checksums",
            "cve",
            "vulnerability",
        }
        for node in doc["@graph"]:
            for key in node:
                assert key.lower() not in {k.lower() for k in forbidden_keys}, (
                    f"Forbidden key {key!r} found in node {node.get('type')}"
                )

    def test_cli_creator_fallback_warning(self, tmp_path):
        from click.testing import CliRunner
        from unravel_sbom.cli import cli

        runner = CliRunner()
        out_file = tmp_path / "test.spdx.json"
        res = runner.invoke(
            cli,
            ["scan", str(FIXTURES / "npm"), "-f", "spdx", "-o", str(out_file)],
        )
        assert res.exit_code == 0
        assert "Warning: no --creator-email/--creator-url given" in res.output

    def test_cli_creator_email_option(self, tmp_path):
        from click.testing import CliRunner
        from unravel_sbom.cli import cli

        runner = CliRunner()
        out_file = tmp_path / "test.spdx.json"
        res = runner.invoke(
            cli,
            [
                "scan",
                str(FIXTURES / "npm"),
                "-f",
                "spdx",
                "--creator-email",
                "auditor@example.com",
                "-o",
                str(out_file),
            ],
        )
        assert res.exit_code == 0
        assert "Warning: no --creator-email" not in res.output
        loaded = json.loads(out_file.read_text())
        person = next(n for n in loaded["@graph"] if n.get("type") == "Person")
        assert person["externalIdentifiers"][0]["identifier"] == "auditor@example.com"



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
