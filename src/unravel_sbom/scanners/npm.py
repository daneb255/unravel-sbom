from __future__ import annotations

import json
import logging
from pathlib import Path

from unravel_sbom.models import Ecosystem, Package, ScanResult
from unravel_sbom.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# Minimal SPDX license ID mapping for the most common npm licences.
# Everything unknown falls back to NOASSERTION.
_LICENSE_MAP: dict[str, str] = {
    "MIT": "MIT",
    "ISC": "ISC",
    "BSD-2-Clause": "BSD-2-Clause",
    "BSD-3-Clause": "BSD-3-Clause",
    "Apache-2.0": "Apache-2.0",
    "Apache 2.0": "Apache-2.0",
    "GPL-2.0": "GPL-2.0-only",
    "GPL-3.0": "GPL-3.0-only",
    "LGPL-2.1": "LGPL-2.1-only",
    "CC0-1.0": "CC0-1.0",
    "0BSD": "0BSD",
    "Unlicense": "Unlicense",
}


def _normalise_license(raw: str | None) -> str:
    if not raw:
        return "NOASSERTION"
    # Some packages encode license as {"type": "MIT"} object
    if isinstance(raw, dict):
        raw = raw.get("type", "")
    return _LICENSE_MAP.get(raw.strip(), raw.strip() or "NOASSERTION")


class PackageJsonScanner(BaseScanner):
    """Scans package.json for direct dependencies."""

    MANIFEST_NAMES = ("package.json",)

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        data = json.loads(path.read_text(encoding="utf-8"))

        # Skip the root package itself (no version range → it IS the project)
        deps: dict[str, str] = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        deps.update(data.get("peerDependencies", {}))
        deps.update(data.get("optionalDependencies", {}))

        for name, version_range in deps.items():
            # Strip semver range prefixes: ^1.2.3 → 1.2.3
            version = version_range.lstrip("^~>=<").split(" ")[0].strip() or "unknown"
            pkg = Package(
                name=name,
                version=version,
                ecosystem=Ecosystem.NPM,
                source_file=path,
            )
            result.packages.append(pkg)

        return result


class PackageLockScanner(BaseScanner):
    """Scans package-lock.json (v2/v3) for exact resolved versions."""

    MANIFEST_NAMES = ("package-lock.json",)

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        data = json.loads(path.read_text(encoding="utf-8"))
        lock_version = data.get("lockfileVersion", 1)

        if lock_version >= 2 and "packages" in data:
            # v2/v3 format
            for pkg_path, info in data["packages"].items():
                if pkg_path == "":
                    continue  # root
                name = info.get("name") or pkg_path.split("node_modules/")[-1]
                version = info.get("version", "unknown")
                license_id = _normalise_license(info.get("license"))
                pkg = Package(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NPM,
                    license_id=license_id,
                    source_file=path,
                )
                result.packages.append(pkg)
        else:
            # v1 format
            for name, info in data.get("dependencies", {}).items():
                version = info.get("version", "unknown")
                pkg = Package(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NPM,
                    source_file=path,
                )
                result.packages.append(pkg)

        return result
