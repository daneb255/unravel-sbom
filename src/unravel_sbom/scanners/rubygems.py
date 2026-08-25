from __future__ import annotations

import re
from pathlib import Path

from unravel_sbom.models import Ecosystem, Package, ScanResult
from unravel_sbom.scanners.base import BaseScanner

_GEMFILE_DECL_RE = re.compile(
    r"^\s*gem\s+[\"']([^\"']+)[\"'](?:\s*,\s*[\"']([^\"']+)[\"'])?",
    re.MULTILINE,
)

_SPEC_PARENT_RE = re.compile(r"^ {4}([A-Za-z0-9_\.\-]+)\s+\(([^\)]+)\)")
_SPEC_CHILD_RE = re.compile(r"^ {6,}([A-Za-z0-9_\.\-]+)(?:\s+\([^\)]+\))?")


def _clean_gem_version(ver: str) -> str:
    return re.sub(r"^[~>=< ]+", "", ver).strip() or "unknown"


class GemfileLockScanner(BaseScanner):
    """Parses Gemfile.lock lockfiles for exact resolved Ruby gems and dependency trees."""

    MANIFEST_NAMES = ("gemfile.lock",)

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        content = path.read_text(encoding="utf-8", errors="replace")

        in_specs = False
        current_pkg: Package | None = None

        for line in content.splitlines():
            # Check for section header
            if line.strip() == "specs:":
                in_specs = True
                continue

            if in_specs:
                # If we encounter an unindented or 2-space indented line, section ended
                if line and not line.startswith("    "):
                    in_specs = False
                    if current_pkg:
                        result.packages.append(current_pkg)
                        current_pkg = None
                    continue

                parent_match = _SPEC_PARENT_RE.match(line)
                if parent_match:
                    if current_pkg:
                        result.packages.append(current_pkg)
                    name = parent_match.group(1)
                    version = parent_match.group(2)
                    current_pkg = Package(
                        name=name,
                        version=version,
                        ecosystem=Ecosystem.GEM,
                        source_file=path,
                        supplier=f"RubyGems:{path.name}",
                        depends_on=[],
                    )
                    continue

                child_match = _SPEC_CHILD_RE.match(line)
                if child_match and current_pkg:
                    dep_name = child_match.group(1)
                    current_pkg.depends_on.append(dep_name)
                    continue

        if current_pkg:
            result.packages.append(current_pkg)

        return result


class GemfileScanner(BaseScanner):
    """Parses Gemfile manifest files for declared Ruby gem dependencies."""

    MANIFEST_NAMES = ("gemfile",)

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        content = path.read_text(encoding="utf-8", errors="replace")

        seen: set[str] = set()

        for m in _GEMFILE_DECL_RE.finditer(content):
            name = m.group(1).strip()
            raw_ver = m.group(2)
            version = _clean_gem_version(raw_ver) if raw_ver else "unknown"

            if name in seen:
                continue
            seen.add(name)

            result.packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.GEM,
                    source_file=path,
                    supplier=f"RubyGems:{path.name}",
                )
            )

        return result
