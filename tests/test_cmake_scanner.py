"""Tests for the CMake scanner."""

from __future__ import annotations

from pathlib import Path


FIXTURE = Path(__file__).parent / "fixtures" / "cmake" / "CMakeLists.txt"


def _scan():
    from unravel_sbom.scanners.cmake import CMakeScanner

    return CMakeScanner().scan(FIXTURE)


# ---------------------------------------------------------------------------
# find_package
# ---------------------------------------------------------------------------


class TestFindPackage:
    def test_finds_openssl(self):
        result = _scan()
        names = {p.name for p in result.packages}
        assert "OpenSSL" in names

    def test_openssl_version_from_argument(self):
        result = _scan()
        pkg = next(p for p in result.packages if p.name == "OpenSSL")
        assert pkg.version == "3.1.2"

    def test_finds_boost_with_inline_version(self):
        result = _scan()
        pkg = next(p for p in result.packages if p.name == "Boost")
        assert pkg.version == "1.83.0"

    def test_finds_gtest(self):
        result = _scan()
        names = {p.name for p in result.packages}
        assert "GTest" in names

    def test_skips_cmake_builtins(self):
        result = _scan()
        names = {p.name.lower() for p in result.packages}
        assert "threads" not in names
        assert "git" not in names


# ---------------------------------------------------------------------------
# FetchContent_Declare
# ---------------------------------------------------------------------------


class TestFetchContent:
    def test_finds_fmt(self):
        result = _scan()
        names = {p.name for p in result.packages}
        assert "fmt" in names

    def test_fmt_version_from_git_tag(self):
        result = _scan()
        pkg = next(p for p in result.packages if p.name == "fmt")
        assert pkg.version == "12.1.0"

    def test_pybind11_strips_v_prefix(self):
        result = _scan()
        pkg = next(p for p in result.packages if p.name == "pybind11")
        assert pkg.version == "3.0.1"

    def test_cli11_strips_v_prefix(self):
        result = _scan()
        pkg = next(p for p in result.packages if p.name == "CLI11")
        assert pkg.version == "2.4.1"

    def test_websocketpp_plain_version(self):
        result = _scan()
        pkg = next(p for p in result.packages if p.name == "websocketpp")
        assert pkg.version == "0.8.2"

    def test_tinyxml2_strips_v_prefix(self):
        result = _scan()
        pkg = next(p for p in result.packages if p.name == "tinyxml2")
        assert pkg.version == "10.0.0"

    def test_cpp_httplib_strips_v_prefix(self):
        result = _scan()
        pkg = next(p for p in result.packages if p.name == "cpp-httplib")
        assert pkg.version == "0.18.0"

    def test_asio_dash_tag_converted(self):
        # asio-1-30-2 → 1.30.2
        result = _scan()
        pkg = next(p for p in result.packages if p.name == "asio")
        assert pkg.version == "1.30.2"

    def test_nlohmann_json_version_keyword(self):
        result = _scan()
        pkg = next(p for p in result.packages if p.name == "nlohmann_json")
        assert pkg.version == "3.11.3"


# ---------------------------------------------------------------------------
# ExternalProject_Add
# ---------------------------------------------------------------------------


class TestExternalProject:
    def test_finds_libsodium(self):
        result = _scan()
        names = {p.name for p in result.packages}
        assert "libsodium" in names

    def test_libsodium_version(self):
        result = _scan()
        pkg = next(p for p in result.packages if p.name == "libsodium")
        assert pkg.version == "1.0.20"


# ---------------------------------------------------------------------------
# CPM_AddPackage
# ---------------------------------------------------------------------------


class TestCPMAddPackage:
    def test_finds_spdlog(self):
        result = _scan()
        names = {p.name for p in result.packages}
        assert "spdlog" in names

    def test_spdlog_version(self):
        result = _scan()
        pkg = next(p for p in result.packages if p.name == "spdlog")
        assert pkg.version == "1.13.0"

    def test_zlib_version_from_git_tag(self):
        result = _scan()
        pkg = next(p for p in result.packages if p.name == "zlib")
        assert pkg.version == "1.3.1"


# ---------------------------------------------------------------------------
# Deduplication & general
# ---------------------------------------------------------------------------


class TestGeneral:
    def test_no_duplicate_packages(self):
        result = _scan()
        names = [p.name for p in result.packages]
        assert len(names) == len(set(names)), "Duplicate package names found"

    def test_ecosystem_is_generic(self):
        from unravel_sbom.models import Ecosystem

        result = _scan()
        for pkg in result.packages:
            assert pkg.ecosystem == Ecosystem.GENERIC

    def test_source_file_set(self):
        result = _scan()
        for pkg in result.packages:
            assert pkg.source_file == FIXTURE

    def test_malformed_cmake_does_not_crash(self, tmp_path):
        from unravel_sbom.scanners.cmake import CMakeScanner

        bad = tmp_path / "CMakeLists.txt"
        bad.write_text("find_package(\nfind_package((((\n", encoding="utf-8")
        result = CMakeScanner().scan(bad)
        assert isinstance(result.packages, list)

    def test_purl_uses_generic_scheme(self):
        result = _scan()
        for pkg in result.packages:
            assert pkg.purl.startswith("pkg:generic/")

    def test_spdx_id_format(self):
        result = _scan()
        for pkg in result.packages:
            assert pkg.spdx_id.startswith("SPDXRef-")


# ---------------------------------------------------------------------------
# Walker integration: CMakeLists.txt is discovered recursively
# ---------------------------------------------------------------------------


class TestWalkerPicksUpCMake:
    def test_cmake_packages_in_full_scan(self):
        from unravel_sbom.scanners import ALL_SCANNERS
        from unravel_sbom.walker import walk

        fixtures = Path(__file__).parent / "fixtures"
        result = walk(fixtures, ALL_SCANNERS)
        names = {p.name for p in result.packages}
        assert "fmt" in names
        assert "pybind11" in names
        assert "OpenSSL" in names
