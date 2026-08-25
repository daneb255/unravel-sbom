"""Generate a valid CycloneDX 1.6 BOM document in JSON format.

Specification: https://cyclonedx.org/docs/1.6/json/
Schema: https://github.com/CycloneDX/specification/blob/master/schema/bom-1.6.schema.json
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any
import uuid

from unravel_sbom import __version__
from unravel_sbom.models import Ecosystem, Package, ScanResult

logger = logging.getLogger(__name__)

SPEC_VERSION = "1.6"
BOM_FORMAT = "CycloneDX"
TOOL_NAME = "unravel-sbom"
TOOL_VERSION = __version__

# Map our ecosystem to the CycloneDX component type.
_ECOSYSTEM_TYPE: dict[Ecosystem, str] = {
    Ecosystem.NPM: "library",
    Ecosystem.PYPI: "library",
    Ecosystem.CONAN: "library",
    Ecosystem.GOLANG: "library",
    Ecosystem.CARGO: "library",
    Ecosystem.MAVEN: "library",
    Ecosystem.GEM: "library",
    Ecosystem.NUGET: "library",
    Ecosystem.GENERIC: "library",
}

# Map scope strings to CycloneDX scope values
_SCOPE_MAP = {"runtime": "required", "build": "optional"}


def _serial_number() -> str:
    return f"urn:uuid:{uuid.uuid4()}"


def _licenses(license_id: str) -> list[dict[str, Any]]:
    """Return a CycloneDX licenses array from a raw license string."""
    if not license_id or license_id == "NOASSERTION":
        return []
    if " " in license_id:
        return [{"expression": license_id}]
    return [{"license": {"id": license_id, "acknowledgement": "declared"}}]


def _supplier(supplier_str: str) -> dict[str, Any] | None:
    """Convert our free-form supplier string to a CycloneDX organization object."""
    if not supplier_str or supplier_str == "NOASSERTION":
        return None
    for prefix in ("Organization: ", "Person: ", "Tool: ", "Makefile:"):
        if supplier_str.startswith(prefix):
            supplier_str = supplier_str[len(prefix) :]
            break
    return {"name": supplier_str}


def _package_to_component(pkg: Package) -> dict[str, Any]:
    comp: dict[str, Any] = {
        "type": _ECOSYSTEM_TYPE.get(pkg.ecosystem, "library"),
        "bom-ref": pkg.spdx_id,
        "name": pkg.name,
        "version": pkg.version or "unknown",
        "purl": pkg.purl,
    }

    scope = getattr(pkg, "scope", None)
    if scope and scope in _SCOPE_MAP:
        comp["scope"] = _SCOPE_MAP[scope]

    lic = _licenses(pkg.license_id)
    if lic:
        comp["licenses"] = lic

    sup = _supplier(pkg.supplier)
    if sup:
        comp["supplier"] = sup

    ext_refs: list[dict[str, Any]] = []
    if pkg.homepage:
        ext_refs.append({"type": "website", "url": pkg.homepage})
    resolved_path = getattr(pkg, "resolved_path", None)
    if resolved_path:
        ext_refs.append({"type": "distribution", "url": f"file://{resolved_path}"})
    if ext_refs:
        comp["externalReferences"] = ext_refs

    evidence = getattr(pkg, "evidence", None)
    if evidence:
        comp["evidence"] = {"occurrences": [{"location": ev} for ev in evidence]}

    return comp


def _deduplicate(packages: list[Package]) -> list[Package]:
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
    """Build a CycloneDX 1.6 JSON document dict from a ScanResult."""
    name = document_name or scan_root.resolve().name
    packages = _deduplicate(result.packages)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    components = [_package_to_component(p) for p in packages]

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "serialNumber": _serial_number(),
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": name,
            },
        },
        "components": components,
    }


def write(doc: dict[str, Any], out_path: Path) -> None:
    """Serialize doc to JSON and write to out_path."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    logger.info(
        "CycloneDX 1.6 document written to %s (%d components)",
        out_path,
        len(doc.get("components", [])),
    )
