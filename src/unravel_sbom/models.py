from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Ecosystem(str, Enum):
    NPM = "npm"
    PYPI = "pypi"
    CONAN = "conan"
    GOLANG = "golang"
    CARGO = "cargo"
    MAVEN = "maven"
    GEM = "gem"
    NUGET = "nuget"
    GENERIC = "generic"


@dataclass
class Package:
    name: str
    version: str
    ecosystem: Ecosystem
    license_id: str = "NOASSERTION"
    supplier: str = "NOASSERTION"
    source_file: Path | None = None
    # Extra metadata populated by scanners that can resolve it
    homepage: str | None = None
    depends_on: list[str] = field(default_factory=list)
    # Hash of the resolved artifact, e.g. {"SHA-512": "<hex>"} (npm: package-lock "integrity")
    hashes: dict[str, str] = field(default_factory=dict)

    @property
    def purl(self) -> str:
        from packageurl import PackageURL  # lazy import

        name = self.name
        version = self.version or None
        match self.ecosystem:
            case Ecosystem.NPM:
                # scoped packages: the purl spec keeps the "@" of the scope, encoded as %40
                if "/" in name:
                    namespace, name = name.split("/", 1)
                    return str(
                        PackageURL(
                            "npm", namespace=namespace, name=name, version=version
                        )
                    )
                return str(PackageURL("npm", name=name, version=version))
            case Ecosystem.PYPI:
                return str(PackageURL("pypi", name=name, version=version))
            case Ecosystem.CONAN:
                return str(PackageURL("conan", name=name, version=version))
            case Ecosystem.GOLANG:
                if "/" in name:
                    namespace, short_name = name.rsplit("/", 1)
                    return str(
                        PackageURL(
                            "golang",
                            namespace=namespace,
                            name=short_name,
                            version=version,
                        )
                    )
                return str(PackageURL("golang", name=name, version=version))
            case Ecosystem.CARGO:
                return str(PackageURL("cargo", name=name, version=version))
            case Ecosystem.MAVEN:
                if ":" in name:
                    group_id, artifact_id = name.split(":", 1)
                    return str(
                        PackageURL(
                            "maven",
                            namespace=group_id,
                            name=artifact_id,
                            version=version,
                        )
                    )
                return str(PackageURL("maven", name=name, version=version))
            case Ecosystem.GEM:
                return str(PackageURL("gem", name=name, version=version))
            case Ecosystem.NUGET:
                return str(PackageURL("nuget", name=name, version=version))
            case _:
                return str(PackageURL("generic", name=name, version=version))

    @property
    def spdx_id(self) -> str:
        safe = (
            self.name.replace("@", "")
            .replace("/", "-")
            .replace("_", "-")
            .replace(".", "-")
            .strip("-")
        )
        ver = (
            (self.version or "unknown")
            .replace(".", "-")
            .replace("^", "")
            .replace("~", "")
        )
        digest = hashlib.sha1(  # nosec B324
            f"{self.ecosystem.value}:{self.name}@{self.version}".encode(),
            usedforsecurity=False,
        ).hexdigest()[:8]
        return f"SPDXRef-{self.ecosystem.value}-{safe}-{ver}-{digest}"


def unique_ref_by_name(packages: list[Package]) -> dict[str, Package]:
    """Map name → package, only for names with exactly one version present.

    A bare dependency name is ambiguous when several versions exist, so those
    names are left out rather than linked to a guessed version.
    """
    by_name: dict[str, list[Package]] = {}
    for pkg in packages:
        by_name.setdefault(pkg.name, []).append(pkg)
    return {n: ps[0] for n, ps in by_name.items() if len(ps) == 1}


@dataclass
class ScanResult:
    packages: list[Package] = field(default_factory=list)
    errors: list[tuple[Path, str]] = field(default_factory=list)

    def merge(self, other: ScanResult) -> None:
        self.packages.extend(other.packages)
        self.errors.extend(other.errors)
