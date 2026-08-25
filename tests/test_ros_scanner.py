"""Tests for the ROS/ROS2 package.xml scanner and CMake ament variable expansion."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "ros"
PKG_XML = FIXTURES / "package.xml"
CMAKE = FIXTURES / "CMakeLists.txt"


# ---------------------------------------------------------------------------
# package.xml scanner
# ---------------------------------------------------------------------------


class TestPackageXmlScanner:
    def _scan(self):
        from unravel_sbom.scanners.ros import PackageXmlScanner

        return PackageXmlScanner().scan(PKG_XML)

    def test_finds_depend_entries(self):
        result = self._scan()
        names = {p.name for p in result.packages}
        assert "rclcpp" in names
        assert "sensor_msgs" in names
        assert "std_msgs" in names

    def test_finds_buildtool_depend(self):
        result = self._scan()
        names = {p.name for p in result.packages}
        assert "ament_cmake_auto" in names
        assert "ament_cmake_ros" in names

    def test_finds_build_depend(self):
        result = self._scan()
        names = {p.name for p in result.packages}
        assert "geometry_msgs" in names

    def test_finds_exec_depend(self):
        result = self._scan()
        names = {p.name for p in result.packages}
        assert "ament_index_python" in names

    def test_finds_test_depend(self):
        result = self._scan()
        names = {p.name for p in result.packages}
        assert "launch_testing_ament_cmake" in names

    def test_versioned_dep_extracted(self):
        result = self._scan()
        cam_lib = next(p for p in result.packages if p.name == "my_camera_lib")
        assert cam_lib.version == "1.6.12"

    def test_unversioned_dep_is_unknown(self):
        result = self._scan()
        rclcpp = next(p for p in result.packages if p.name == "rclcpp")
        assert rclcpp.version == "unknown"

    def test_package_own_name_excluded(self):
        result = self._scan()
        assert all(p.name != "my_ros2_pkg" for p in result.packages)

    def test_no_duplicates(self):
        result = self._scan()
        names = [p.name for p in result.packages]
        assert len(names) == len(set(names))

    def test_ecosystem_is_generic(self):
        from unravel_sbom.models import Ecosystem

        result = self._scan()
        for pkg in result.packages:
            assert pkg.ecosystem == Ecosystem.GENERIC

    def test_source_file_set(self):
        result = self._scan()
        for pkg in result.packages:
            assert pkg.source_file == PKG_XML

    def test_malformed_xml_raises_in_scan(self, tmp_path):
        import xml.etree.ElementTree as ET

        from unravel_sbom.scanners.ros import PackageXmlScanner

        bad = tmp_path / "package.xml"
        bad.write_text("<package><name>foo</name><<broken>")
        with pytest.raises(ET.ParseError):
            PackageXmlScanner().scan(bad)

    def test_safe_scan_isolates_error(self, tmp_path):
        from unravel_sbom.scanners.ros import PackageXmlScanner

        bad = tmp_path / "package.xml"
        bad.write_text("<package><name>foo</name><<broken>")
        result = PackageXmlScanner().safe_scan(bad)
        assert len(result.packages) == 0
        assert len(result.errors) == 1


# ---------------------------------------------------------------------------
# CMake scanner — ament variable expansion
# ---------------------------------------------------------------------------


class TestCMakeAmentExpansion:
    def _scan(self):
        from unravel_sbom.scanners.cmake import CMakeScanner

        return CMakeScanner().scan(CMAKE)

    def test_direct_find_package_found(self):
        result = self._scan()
        names = {p.name for p in result.packages}
        assert "my_camera_lib" in names
        assert "ament_cmake_auto" in names

    def test_ament_auto_find_expands_variable(self):
        """ament_auto_find_build_dependencies(REQUIRED ${MY_ROS2_DEPS}) must expand."""
        result = self._scan()
        names = {p.name for p in result.packages}
        assert "rclcpp" in names
        assert "sensor_msgs" in names
        assert "tf2_ros" in names

    def test_ament_target_dependencies_expands_variable(self):
        result = self._scan()
        names = {p.name for p in result.packages}
        # ament_target_dependencies also uses ${MY_ROS2_DEPS}
        assert "diagnostic_msgs" in names

    def test_cmake_keyword_required_not_added(self):
        result = self._scan()
        assert all(p.name.upper() != "REQUIRED" for p in result.packages)

    def test_no_duplicates(self):
        result = self._scan()
        names = [p.name for p in result.packages]
        assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# Walker integration
# ---------------------------------------------------------------------------


class TestWalkerPicksUpRos:
    def test_ros_packages_in_full_scan(self):
        from unravel_sbom.scanners import ALL_SCANNERS
        from unravel_sbom.walker import walk

        result = walk(FIXTURES, ALL_SCANNERS)
        names = {p.name for p in result.packages}

        # From package.xml
        assert "rclcpp" in names
        assert "my_camera_lib" in names
        assert "ament_cmake_auto" in names

        # From CMakeLists.txt variable expansion
        assert "sensor_msgs" in names

    def test_no_errors(self):
        from unravel_sbom.scanners import ALL_SCANNERS
        from unravel_sbom.walker import walk

        result = walk(FIXTURES, ALL_SCANNERS)
        assert result.errors == []
