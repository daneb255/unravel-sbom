from __future__ import annotations

import json
from pathlib import Path

import defusedxml.ElementTree as ET

from unravel_sbom.models import Ecosystem, Package, ScanResult
from unravel_sbom.scanners.base import BaseScanner


def _strip_ns(tag: str) -> str:
    return tag.split("}")[-1] if "}" in tag else tag


class NuGetScanner(BaseScanner):
    """Parses .NET NuGet manifests (.csproj, packages.config, packages.lock.json)."""

    MANIFEST_NAMES = (
        "packages.config",
        "packages.lock.json",
        "directory.build.props",
        "directory.packages.props",
    )
    MANIFEST_EXTENSIONS = (".csproj", ".fsproj", ".vbproj")

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        content = path.read_text(encoding="utf-8", errors="replace")

        name_lower = path.name.lower()
        seen: set[str] = set()

        # Case 1: packages.lock.json
        if name_lower == "packages.lock.json":
            try:
                data = json.loads(content)
                deps_target = data.get("dependencies", {})
                if isinstance(deps_target, dict):
                    for tfm_deps in deps_target.values():
                        if not isinstance(tfm_deps, dict):
                            continue
                        for pkg_name, pkg_info in tfm_deps.items():
                            if not isinstance(pkg_info, dict) or pkg_name in seen:
                                continue
                            seen.add(pkg_name)

                            version = pkg_info.get("resolved") or "unknown"
                            sub_deps = pkg_info.get("dependencies", {})
                            depends_on = (
                                list(sub_deps.keys())
                                if isinstance(sub_deps, dict)
                                else []
                            )

                            result.packages.append(
                                Package(
                                    name=pkg_name,
                                    version=str(version),
                                    ecosystem=Ecosystem.NUGET,
                                    source_file=path,
                                    supplier=f"NuGet:{path.name}",
                                    depends_on=depends_on,
                                )
                            )
            except Exception as exc:
                result.errors.append(
                    (path, f"Failed to parse packages.lock.json: {exc}")
                )
            return result

        # Case 2: XML files (.csproj, .fsproj, packages.config, Directory.Build.props)
        try:
            root = ET.fromstring(content)
        except Exception as exc:
            result.errors.append((path, f"Malformed XML in NuGet manifest: {exc}"))
            return result

        # Check for packages.config <package id="..." version="..." />
        if name_lower == "packages.config" or _strip_ns(root.tag) == "packages":
            for child in root:
                if _strip_ns(child.tag) == "package":
                    pkg_id = child.attrib.get("id")
                    version = child.attrib.get("version", "unknown")
                    if pkg_id and pkg_id not in seen:
                        seen.add(pkg_id)
                        result.packages.append(
                            Package(
                                name=pkg_id,
                                version=version,
                                ecosystem=Ecosystem.NUGET,
                                source_file=path,
                                supplier=f"NuGet:{path.name}",
                            )
                        )
            return result

        # Project files (.csproj) containing PackageReference
        for elem in root.iter():
            tag = _strip_ns(elem.tag)
            if tag in ("PackageReference", "PackageVersion"):
                pkg_name = elem.attrib.get("Include") or elem.attrib.get("Update")
                version = elem.attrib.get("Version")

                # Version could be a child element <Version>1.0.0</Version>
                if not version:
                    for child in elem:
                        if _strip_ns(child.tag) == "Version" and child.text:
                            version = child.text.strip()
                            break

                version = version or "unknown"

                if pkg_name and pkg_name not in seen:
                    seen.add(pkg_name)
                    result.packages.append(
                        Package(
                            name=pkg_name,
                            version=version,
                            ecosystem=Ecosystem.NUGET,
                            source_file=path,
                            supplier=f"NuGet:{path.name}",
                        )
                    )

        return result
