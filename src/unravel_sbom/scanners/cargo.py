from __future__ import annotations

from pathlib import Path

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore[no-redef]

from unravel_sbom.models import Ecosystem, Package, ScanResult
from unravel_sbom.scanners.base import BaseScanner


def _clean_version(ver: str) -> str:
    """Normalize version string by stripping caret/tilde/whitespace."""
    return ver.strip().lstrip("^~=<> ")


class CargoLockScanner(BaseScanner):
    """Parses Cargo.lock lockfiles for exact resolved Rust crates."""

    MANIFEST_NAMES = ("cargo.lock",)

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        content = path.read_text(encoding="utf-8", errors="replace")

        data = tomllib.loads(content)
        packages_data = data.get("package", [])
        if not isinstance(packages_data, list):
            return result

        for entry in packages_data:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            version = entry.get("version")
            if not name or not version:
                continue

            raw_deps = entry.get("dependencies", [])
            depends_on: list[str] = []
            if isinstance(raw_deps, list):
                for dep in raw_deps:
                    if isinstance(dep, str):
                        dep_name = dep.split()[0]
                        depends_on.append(dep_name)

            result.packages.append(
                Package(
                    name=str(name),
                    version=str(version),
                    ecosystem=Ecosystem.CARGO,
                    source_file=path,
                    supplier=f"Cargo:{path.name}",
                    depends_on=depends_on,
                )
            )

        return result


class CargoTomlScanner(BaseScanner):
    """Parses Cargo.toml manifest files for declared Rust crate dependencies."""

    MANIFEST_NAMES = ("cargo.toml",)

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        content = path.read_text(encoding="utf-8", errors="replace")

        data = tomllib.loads(content)

        dep_sections = [
            data.get("dependencies", {}),
            data.get("dev-dependencies", {}),
            data.get("build-dependencies", {}),
            data.get("workspace", {}).get("dependencies", {}),
        ]

        # Also inspect target-specific dependencies: [target.'...'.dependencies]
        target_table = data.get("target", {})
        if isinstance(target_table, dict):
            for target_cfg in target_table.values():
                if isinstance(target_cfg, dict):
                    if "dependencies" in target_cfg:
                        dep_sections.append(target_cfg["dependencies"])
                    if "dev-dependencies" in target_cfg:
                        dep_sections.append(target_cfg["dev-dependencies"])
                    if "build-dependencies" in target_cfg:
                        dep_sections.append(target_cfg["build-dependencies"])

        seen: set[str] = set()

        for section in dep_sections:
            if not isinstance(section, dict):
                continue
            for name, spec in section.items():
                if name in seen:
                    continue
                seen.add(name)

                version = "unknown"
                if isinstance(spec, str):
                    version = _clean_version(spec) or "unknown"
                elif isinstance(spec, dict):
                    raw_ver = spec.get("version")
                    if raw_ver:
                        version = _clean_version(str(raw_ver)) or "unknown"
                    elif "git" in spec:
                        version = str(
                            spec.get("branch")
                            or spec.get("tag")
                            or spec.get("rev")
                            or "git"
                        )
                    elif "path" in spec:
                        version = "path"

                result.packages.append(
                    Package(
                        name=name,
                        version=version,
                        ecosystem=Ecosystem.CARGO,
                        source_file=path,
                        supplier=f"Cargo:{path.name}",
                    )
                )

        return result
