from __future__ import annotations

import re
from pathlib import Path

import defusedxml.ElementTree as ET

from unravel_sbom.models import Ecosystem, Package, ScanResult
from unravel_sbom.scanners.base import BaseScanner

_PROP_VAR_RE = re.compile(r"\$\{([^}]+)\}")


def _strip_ns(tag: str) -> str:
    """Strip XML namespace prefix from tag if present."""
    return tag.split("}")[-1] if "}" in tag else tag


def _resolve_properties(text: str, props: dict[str, str]) -> str:
    """Replace ${prop.name} variables in text using the properties mapping."""
    return _PROP_VAR_RE.sub(lambda m: props.get(m.group(1), m.group(0)), text)


class PomXmlScanner(BaseScanner):
    """Parses Maven pom.xml files for declared dependencies and properties."""

    MANIFEST_NAMES = ("pom.xml",)

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        content = path.read_text(encoding="utf-8", errors="replace")

        try:
            root = ET.fromstring(content)
        except Exception as exc:
            result.errors.append((path, f"Malformed XML in pom.xml: {exc}"))
            return result

        # 1. Collect properties
        props: dict[str, str] = {}

        # Project version fallback
        proj_ver_elem = None
        for child in root:
            if _strip_ns(child.tag) == "version" and child.text:
                proj_ver_elem = child.text.strip()
                props["project.version"] = proj_ver_elem
                props["version"] = proj_ver_elem
                break

        # Parent version fallback
        parent_elem = None
        for child in root:
            if _strip_ns(child.tag) == "parent":
                for p_child in child:
                    if _strip_ns(p_child.tag) == "version" and p_child.text:
                        parent_elem = p_child.text.strip()
                        if "project.version" not in props:
                            props["project.version"] = parent_elem
                            props["version"] = parent_elem
                        break

        # Explicit properties block
        for child in root:
            if _strip_ns(child.tag) == "properties":
                for prop_node in child:
                    prop_name = _strip_ns(prop_node.tag)
                    if prop_node.text:
                        props[prop_name] = prop_node.text.strip()

        # 2. Extract dependencies from <dependencies> and <dependencyManagement>
        seen: set[str] = set()

        def parse_dep_container(container_node: ET.Element) -> None:
            for dep in container_node:
                if _strip_ns(dep.tag) != "dependency":
                    continue

                group_id: str | None = None
                artifact_id: str | None = None
                version: str = "unknown"

                for field in dep:
                    field_tag = _strip_ns(field.tag)
                    val = field.text.strip() if field.text else ""
                    if field_tag == "groupId":
                        group_id = _resolve_properties(val, props)
                    elif field_tag == "artifactId":
                        artifact_id = _resolve_properties(val, props)
                    elif field_tag == "version" and val:
                        version = _resolve_properties(val, props)

                if group_id and artifact_id:
                    name = f"{group_id}:{artifact_id}"
                    if name in seen:
                        continue
                    seen.add(name)

                    result.packages.append(
                        Package(
                            name=name,
                            version=version,
                            ecosystem=Ecosystem.MAVEN,
                            source_file=path,
                            supplier=f"Maven:{path.name}",
                        )
                    )

        for child in root:
            tag = _strip_ns(child.tag)
            if tag == "dependencies":
                parse_dep_container(child)
            elif tag == "dependencyManagement":
                for sub in child:
                    if _strip_ns(sub.tag) == "dependencies":
                        parse_dep_container(sub)

        return result
