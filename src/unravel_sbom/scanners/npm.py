from __future__ import annotations

import base64
import json
import logging
import re
from pathlib import Path

from unravel_sbom.models import Ecosystem, Package, ScanResult
from unravel_sbom.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

_EXACT_VERSION_RE = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$")

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


_INTEGRITY_ALGS = {"sha512": "SHA-512", "sha384": "SHA-384", "sha256": "SHA-256"}


def _integrity_hashes(integrity: object) -> dict[str, str]:
    """npm "integrity" (SRI: "sha512-<base64> ...") as {"SHA-512": "<hex>"}. SHA-1 is skipped as too weak."""
    hashes: dict[str, str] = {}
    if not isinstance(integrity, str):
        return hashes
    for entry in integrity.split():
        alg, _, b64 = entry.partition("-")
        if alg in _INTEGRITY_ALGS and b64:
            try:
                hashes[_INTEGRITY_ALGS[alg]] = base64.b64decode(
                    b64, validate=True
                ).hex()
            except ValueError:
                continue
    return hashes


class PackageJsonScanner(BaseScanner):
    """Scans package.json for direct dependencies."""

    MANIFEST_NAMES = ("package.json",)
    SUPERSEDED_BY = ("package-lock.json",)

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
            # Only exact pins are versions; ranges, workspace:, file:, git+ are not.
            version = (
                version_range.strip()
                if _EXACT_VERSION_RE.match(version_range.strip())
                else "unknown"
            )
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
                deps = info.get("dependencies", {})
                depends_on = list(deps.keys()) if isinstance(deps, dict) else []
                pkg = Package(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NPM,
                    license_id=license_id,
                    source_file=path,
                    depends_on=depends_on,
                    hashes=_integrity_hashes(info.get("integrity")),
                )
                result.packages.append(pkg)
        else:
            # v1 format
            for name, info in data.get("dependencies", {}).items():
                version = info.get("version", "unknown")
                deps = info.get("requires", {}) or info.get("dependencies", {})
                depends_on = list(deps.keys()) if isinstance(deps, dict) else []
                pkg = Package(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NPM,
                    source_file=path,
                    depends_on=depends_on,
                    hashes=_integrity_hashes(info.get("integrity")),
                )
                result.packages.append(pkg)

        return result
