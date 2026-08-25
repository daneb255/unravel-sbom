"""Generate a valid SPDX 3.0.1 document in JSON-LD format.

Conformant with BSI TR-03183-2.

Specification: https://spdx.github.io/spdx-spec/v3.0.1/
BSI Guideline: BSI TR-03183-2 (Cyber Resilience Act SBOM Requirements)

Scope Decision:
unravel-sbom inspects source code manifests and lockfiles without analyzing
deployed binary artifact bytes. Therefore, all components are modeled as
BSI "logical components" (§3.2.2). Mandatory fields for logical components:
- creator (originatedBy / suppliedBy)
- name
- version (software_packageVersion)
- dependencies (dependsOn relationships)
- distribution licences (hasConcludedLicense)
- other unique identifiers (packageURL via externalIdentifiers)
- original licences (hasDeclaredLicense)

Physical component properties (filename, SHA-512 hashes, executable/archive
properties) apply only to "fully described components" and are deliberately
excluded here as they cannot be produced from manifest parsing alone.

Known Limitations:
- Component creator falls back to the document-level creator identity for each
  package, as source manifests do not provide verifiable per-package author identities
  without live registry queries.
- A single license value is reused for both concluded (distribution) and declared
  (original) licenses until scanners provide upstream vs. as-distributed distinction.
- Effective licence and security.txt URL are omitted (optional, no data source).
- Vulnerability / CVE metadata is strictly omitted per BSI TR-03183-2 mandate.
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

SPDX_SPEC_VERSION = "3.0.1"
SPDX_CONTEXT_URL = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
DATA_LICENSE_IRI = "https://spdx.org/licenses/CC0-1.0"
DEFAULT_CREATOR_URL = "https://github.com/daneb255/unravel"


def _document_namespace(name: str, scan_root: Path) -> str:
    digest = hashlib.sha1(
        str(scan_root.resolve()).encode(), usedforsecurity=False
    ).hexdigest()[:12]
    safe_name = name.replace(" ", "-")
    return f"https://unravel-sbom.local/{safe_name}-{digest}"


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


def package_count(doc: dict[str, Any]) -> int:
    """Return the number of software_Package elements in the SPDX document."""
    return sum(
        1
        for node in doc.get("@graph", [])
        if isinstance(node, dict) and node.get("type") == "software_Package"
    )


def generate(
    result: ScanResult,
    scan_root: Path,
    document_name: str | None = None,
    *,
    creator_email: str | None = None,
    creator_url: str | None = None,
) -> dict[str, Any]:
    """Build an SPDX 3.0.1 JSON-LD document dict from a ScanResult."""
    name = document_name or f"SBOM-{scan_root.resolve().name}"
    packages = _deduplicate(result.packages)
    ns = _document_namespace(name, scan_root)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    creation_info_id = f"{ns}#creationinfo"
    creator_agent_id = f"{ns}#creator-agent"

    # 1. Creator Agent (Person or Organization)
    if creator_email:
        creator_agent_node: dict[str, Any] = {
            "type": "Person",
            "spdxId": creator_agent_id,
            "creationInfo": creation_info_id,
            "name": creator_email.split("@")[0] or "Creator",
            "externalIdentifiers": [
                {
                    "type": "ExternalIdentifier",
                    "externalIdentifierType": "email",
                    "identifier": creator_email,
                }
            ],
        }
    else:
        url = creator_url or DEFAULT_CREATOR_URL
        creator_agent_node = {
            "type": "Organization",
            "spdxId": creator_agent_id,
            "creationInfo": creation_info_id,
            "name": "Creator",
            "externalIdentifiers": [
                {
                    "type": "ExternalIdentifier",
                    "externalIdentifierType": "urlScheme",
                    "identifier": url,
                }
            ],
        }

    # 2. CreationInfo
    creation_info_node: dict[str, Any] = {
        "type": "CreationInfo",
        "spdxId": creation_info_id,
        "specVersion": SPDX_SPEC_VERSION,
        "created": now,
        "createdBy": [creator_agent_id],
    }

    # Map package names to their full spdxId for resolving dependency edges
    name_to_spdx_id: dict[str, str] = {
        pkg.name: f"{ns}#{pkg.spdx_id}" for pkg in packages
    }

    root_elements: list[str] = []
    package_nodes: list[dict[str, Any]] = []
    license_nodes: list[dict[str, Any]] = []
    relationship_nodes: list[dict[str, Any]] = []

    for pkg in packages:
        pkg_id = f"{ns}#{pkg.spdx_id}"
        root_elements.append(pkg_id)

        # Version resolution with BSI-mandated fallback
        if pkg.version and pkg.version != "unknown":
            version_str = pkg.version
        elif pkg.source_file and pkg.source_file.exists():
            mtime = datetime.fromtimestamp(
                pkg.source_file.stat().st_mtime, tz=timezone.utc
            )
            version_str = mtime.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            version_str = "NOASSERTION"

        pkg_node: dict[str, Any] = {
            "type": "software_Package",
            "spdxId": pkg_id,
            "creationInfo": creation_info_id,
            "name": pkg.name,
            "software_packageVersion": version_str,
            "originatedBy": [creator_agent_id],
            "externalIdentifiers": [
                {
                    "type": "ExternalIdentifier",
                    "externalIdentifierType": "packageUrl",
                    "identifier": pkg.purl,
                }
            ],
        }
        package_nodes.append(pkg_node)

        # License expression and licensing relationships
        license_expr = pkg.license_id if pkg.license_id else "NOASSERTION"
        license_node_id = f"{ns}#license-{pkg.spdx_id}"
        license_node: dict[str, Any] = {
            "type": "simpleLicensing_LicenseExpression",
            "spdxId": license_node_id,
            "creationInfo": creation_info_id,
            "simpleLicensing_licenseExpression": license_expr,
        }
        license_nodes.append(license_node)

        completeness = "complete" if license_expr != "NOASSERTION" else "noAssertion"

        relationship_nodes.append(
            {
                "type": "Relationship",
                "spdxId": f"{ns}#rel-concluded-{pkg.spdx_id}",
                "creationInfo": creation_info_id,
                "from": pkg_id,
                "relationshipType": "hasConcludedLicense",
                "to": [license_node_id],
                "completeness": completeness,
            }
        )
        relationship_nodes.append(
            {
                "type": "Relationship",
                "spdxId": f"{ns}#rel-declared-{pkg.spdx_id}",
                "creationInfo": creation_info_id,
                "from": pkg_id,
                "relationshipType": "hasDeclaredLicense",
                "to": [license_node_id],
                "completeness": completeness,
            }
        )

        # Dependency relationships (dependsOn)
        dep_targets = [
            name_to_spdx_id[dep_name]
            for dep_name in pkg.depends_on
            if dep_name in name_to_spdx_id
        ]
        relationship_nodes.append(
            {
                "type": "Relationship",
                "spdxId": f"{ns}#rel-depends-{pkg.spdx_id}",
                "creationInfo": creation_info_id,
                "from": pkg_id,
                "relationshipType": "dependsOn",
                "to": dep_targets,
                "completeness": "noAssertion",
            }
        )

    # 3. SpdxDocument Root
    doc_node: dict[str, Any] = {
        "type": "SpdxDocument",
        "spdxId": f"{ns}#SPDXRef-DOCUMENT",
        "name": name,
        "dataLicense": DATA_LICENSE_IRI,
        "creationInfo": creation_info_id,
        "rootElement": root_elements,
    }

    graph: list[dict[str, Any]] = [
        doc_node,
        creation_info_node,
        creator_agent_node,
        *package_nodes,
        *license_nodes,
        *relationship_nodes,
    ]

    if not packages:
        logger.warning("No packages found — SBOM will be empty.")

    return {
        "@context": SPDX_CONTEXT_URL,
        "@graph": graph,
    }


def write(doc: dict[str, Any], output_path: Path) -> None:
    """Write SPDX 3.0.1 JSON-LD document to file."""
    output_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    logger.info(
        "SPDX 3.0.1 SBOM written to %s (%d packages)",
        output_path,
        package_count(doc),
    )
