from __future__ import annotations

import re
from pathlib import Path

from unravel_sbom.models import Ecosystem, Package, ScanResult
from unravel_sbom.scanners.base import BaseScanner

# Configuration keywords in Gradle build scripts
_CONFIGS = (
    r"implementation|api|compileOnly|runtimeOnly|testImplementation|"
    r"testCompileOnly|testRuntimeOnly|annotationProcessor|classpath"
)

# String coordinate format:
# implementation "group:artifact:version" or implementation('group:artifact')
_STRING_DEP_RE = re.compile(
    rf"(?:{_CONFIGS})\s*\(?\s*[\"']([^\"':]+):([^\"':]+)(?::([^\"':\$\)]+))?[\"']\s*\)?",
    re.IGNORECASE,
)

# Map coordinate format: implementation group: '...', name: '...', version: '...'
_MAP_DEP_RE = re.compile(
    rf"(?:{_CONFIGS})\s*\(?\s*group\s*[:=]\s*[\"']([^\"']+)[\"']\s*,\s*name\s*[:=]\s*[\"']([^\"']+)[\"'](?:\s*,\s*version\s*[:=]\s*[\"']([^\"']+)[\"'])?",
    re.IGNORECASE,
)


class GradleScanner(BaseScanner):
    """Parses Gradle build files (build.gradle, build.gradle.kts, lockfile)."""

    MANIFEST_NAMES = ("build.gradle", "build.gradle.kts", "gradle.lockfile")

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        content = path.read_text(encoding="utf-8", errors="replace")

        seen: set[str] = set()

        # Case 1: gradle.lockfile
        if path.name.lower() == "gradle.lockfile":
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                coord_part = line.split("=", 1)[0].strip()
                parts = coord_part.split(":")
                if len(parts) >= 3:
                    group, artifact, version = parts[0], parts[1], parts[2]
                    name = f"{group}:{artifact}"
                    if name in seen:
                        continue
                    seen.add(name)
                    result.packages.append(
                        Package(
                            name=name,
                            version=version,
                            ecosystem=Ecosystem.MAVEN,
                            source_file=path,
                            supplier=f"Gradle:{path.name}",
                        )
                    )
            return result

        # Case 2: build.gradle / build.gradle.kts

        # String format matches
        for m in _STRING_DEP_RE.finditer(content):
            group, artifact = m.group(1).strip(), m.group(2).strip()
            version = m.group(3).strip() if m.group(3) else "unknown"
            name = f"{group}:{artifact}"
            if name in seen:
                continue
            seen.add(name)
            result.packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.MAVEN,
                    source_file=path,
                    supplier=f"Gradle:{path.name}",
                )
            )

        # Map format matches
        for m in _MAP_DEP_RE.finditer(content):
            group, artifact = m.group(1).strip(), m.group(2).strip()
            version = m.group(3).strip() if m.group(3) else "unknown"
            name = f"{group}:{artifact}"
            if name in seen:
                continue
            seen.add(name)
            result.packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.MAVEN,
                    source_file=path,
                    supplier=f"Gradle:{path.name}",
                )
            )

        return result
