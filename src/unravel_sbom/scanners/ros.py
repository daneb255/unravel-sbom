"""ROS / ROS2 package.xml scanner.

Parses the REP-149 (format 3) package manifest used by both ROS and ROS2.
All dependency tags are extracted:
  <depend>, <build_depend>, <exec_depend>, <buildtool_depend>, <test_depend>

Version constraints (<version_gt>, <version_gte>, <version_lt>, <version_lte>,
<version_eq>) are read when present; otherwise version is "unknown".

Reference: https://ros.org/reps/rep-0149.html
"""

from __future__ import annotations

import logging
import defusedxml.ElementTree as ET
from pathlib import Path

from unravel_sbom.models import Ecosystem, Package, ScanResult
from unravel_sbom.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# All dependency-carrying tags defined in REP-149
_DEP_TAGS = {
    "depend",
    "build_depend",
    "exec_depend",
    "run_depend",  # ROS1 / format 1 alias for exec_depend
    "buildtool_depend",
    "test_depend",
    "doc_depend",
    "conflict",
    "replace",
    "group_depend",
}

# Version-constraint attribute names (inline XML attributes in format 3)
_VER_ATTRS = ("version_eq", "version_gte", "version_gt", "version_lte", "version_lt")


def _extract_version(element: ET.Element) -> str:
    """Return the most specific version string from a dependency element."""
    for attr in _VER_ATTRS:
        val = element.get(attr, "").strip()
        if val:
            return val
    return "unknown"


class PackageXmlScanner(BaseScanner):
    """Scans ROS/ROS2 package.xml for declared dependencies."""

    MANIFEST_NAMES = ("package.xml",)

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        tree = ET.parse(str(path))
        root = tree.getroot()

        # Self-identification: skip the package's own name
        own_name = (root.findtext("name") or "").strip()

        seen: set[str] = set()

        for elem in root:
            if elem.tag not in _DEP_TAGS:
                continue
            dep_name = (elem.text or "").strip()
            if not dep_name or dep_name == own_name:
                continue
            if dep_name in seen:
                continue
            seen.add(dep_name)

            version = _extract_version(elem)

            result.packages.append(
                Package(
                    name=dep_name,
                    version=version,
                    ecosystem=Ecosystem.GENERIC,
                    source_file=path,
                )
            )

        return result
