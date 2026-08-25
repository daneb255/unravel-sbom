from __future__ import annotations

import re
from pathlib import Path

from unravel_sbom.models import Ecosystem, Package, ScanResult
from unravel_sbom.scanners.base import BaseScanner

_REQUIRE_BLOCK_START = re.compile(r"^\s*require\s*\(\s*")
_REQUIRE_SINGLE_LINE = re.compile(r"^\s*require\s+([^\s\(\)]+)\s+([^\s\(\)]+)")
_MODULE_LINE = re.compile(r"^\s*module\s+([^\s]+)")


class GoSumScanner(BaseScanner):
    """Parses go.sum lockfiles for exact locked Go module versions."""

    MANIFEST_NAMES = ("go.sum",)

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        content = path.read_text(encoding="utf-8", errors="replace")

        seen: set[tuple[str, str]] = set()

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue

            mod_name = parts[0]
            raw_version = parts[1]
            # Strip /go.mod suffix if present
            if raw_version.endswith("/go.mod"):
                raw_version = raw_version[:-7]

            key = (mod_name, raw_version)
            if key in seen:
                continue
            seen.add(key)

            result.packages.append(
                Package(
                    name=mod_name,
                    version=raw_version,
                    ecosystem=Ecosystem.GOLANG,
                    source_file=path,
                    supplier=f"golang:{path.name}",
                )
            )

        return result


class GoModScanner(BaseScanner):
    """Parses go.mod manifest files for required Go module dependencies."""

    MANIFEST_NAMES = ("go.mod",)

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        content = path.read_text(encoding="utf-8", errors="replace")

        root_module: str | None = None
        in_require_block = False

        for line in content.splitlines():
            # Strip comments
            comment_idx = line.find("//")
            clean_line = line[:comment_idx].strip() if comment_idx != -1 else line.strip()

            if not clean_line:
                continue

            # Check root module declaration
            mod_match = _MODULE_LINE.match(clean_line)
            if mod_match:
                root_module = mod_match.group(1)
                continue

            # Check require ( ... ) block
            if _REQUIRE_BLOCK_START.match(clean_line):
                in_require_block = True
                continue

            if in_require_block:
                if clean_line.startswith(")"):
                    in_require_block = False
                    continue
                parts = clean_line.split()
                if len(parts) >= 2:
                    mod_name, version = parts[0], parts[1]
                    if mod_name != root_module:
                        result.packages.append(
                            Package(
                                name=mod_name,
                                version=version,
                                ecosystem=Ecosystem.GOLANG,
                                source_file=path,
                                supplier=f"golang:{path.name}",
                            )
                        )
                continue

            # Single-line require
            req_match = _REQUIRE_SINGLE_LINE.match(clean_line)
            if req_match:
                mod_name, version = req_match.group(1), req_match.group(2)
                if mod_name != root_module:
                    result.packages.append(
                        Package(
                            name=mod_name,
                            version=version,
                            ecosystem=Ecosystem.GOLANG,
                            source_file=path,
                            supplier=f"golang:{path.name}",
                        )
                    )

        return result
