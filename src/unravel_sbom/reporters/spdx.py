"""Generate a valid SPDX 2.3 document in JSON format.

Specification: https://spdx.github.io/spdx-spec/v2.3/
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from unravel_sbom.models import Package, ScanResult

logger = logging.getLogger(__name__)

SPDX_VERSION = "SPDX-2.3"
DATA_LICENSE = "CC0-1.0"
TOOL_NAME = "Tool: unravel-sbom-0.1.0"


def _document_namespace(name: str, scan_root: Path) -> str:
    digest = hashlib.sha1(  # noqa: S324
        str(scan_root.resolve()).encode(), usedforsecurity=False
    ).hexdigest()[:12]
    safe_name = name.replace(" ", "-")
    return f"https://unravel-sbom.local/{safe_name}-{digest}"


def _package_to_spdx(pkg: Package) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "SPDXID": pkg.spdx_id,
        "name": pkg.name,
        "versionInfo": pkg.version or "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": pkg.license_id,
        "licenseDeclared": pkg.license_id,
        "copyrightText": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": pkg.purl,
            }
        ],
    }

    if pkg.supplier and pkg.supplier != "NOASSERTION":
        entry["supplier"] = (
            pkg.supplier
            if pkg.supplier.startswith("Organization:")
            or pkg.supplier.startswith("Person:")
            or pkg.supplier.startswith("Tool:")
            or pkg.supplier.startswith("Makefile:")
            else f"Organization: {pkg.supplier}"
        )
    else:
        entry["supplier"] = "NOASSERTION"

    if pkg.homepage:
        entry["homepage"] = pkg.homepage

    return entry


def _deduplicate(packages: list[Package]) -> list[Package]:
    """Keep the first occurrence of each (name, ecosystem, version) triple."""
    seen: set[tuple[str, str, str]] = set()
    out: list[Package] = []
    for pkg in packages:
        key = (pkg.name, pkg.ecosystem.value, pkg.version or "")
        if key not in seen:
            seen.add(key)
            out.append(pkg)
    return out


def generate(
    result: ScanResult,
    scan_root: Path,
    document_name: str | None = None,
) -> dict[str, Any]:
    """Build an SPDX 2.3 JSON document dict from a ScanResult."""
    name = document_name or f"SBOM-{scan_root.resolve().name}"
    packages = _deduplicate(result.packages)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    root_spdx_id = "SPDXRef-DOCUMENT"

    doc: dict[str, Any] = {
        "SPDXID": root_spdx_id,
        "spdxVersion": SPDX_VERSION,
        "creationInfo": {
            "created": now,
            "creators": [TOOL_NAME],
            "licenseListVersion": "3.21",
        },
        "name": name,
        "dataLicense": DATA_LICENSE,
        "documentNamespace": _document_namespace(name, scan_root),
        "packages": [],
        "relationships": [],
    }

    for pkg in packages:
        doc["packages"].append(_package_to_spdx(pkg))
        doc["relationships"].append(
            {
                "spdxElementId": root_spdx_id,
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": pkg.spdx_id,
            }
        )

    if not packages:
        logger.warning("No packages found — SBOM will be empty.")

    return doc


def write(doc: dict[str, Any], output_path: Path) -> None:
    output_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    logger.info(
        "SBOM written to %s (%d packages)", output_path, len(doc.get("packages", []))
    )
