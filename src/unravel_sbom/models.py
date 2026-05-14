from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Ecosystem(str, Enum):
    NPM = "npm"
    PYPI = "pypi"
    CONAN = "conan"
    GENERIC = "generic"


@dataclass
class Package:
    name: str
    version: str
    ecosystem: Ecosystem
    license_id: str = "NOASSERTION"
    supplier: str = "NOASSERTION"
    source_file: Optional[Path] = None
    # Extra metadata populated by scanners that can resolve it
    homepage: Optional[str] = None

    @property
    def purl(self) -> str:
        from packageurl import PackageURL  # lazy import

        name = self.name
        version = self.version or None
        match self.ecosystem:
            case Ecosystem.NPM:
                # scoped packages: @scope/name
                if "/" in name:
                    namespace, name = name.split("/", 1)
                    namespace = namespace.lstrip("@")
                    return str(
                        PackageURL(
                            "npm", namespace=namespace, name=name, version=version
                        )
                    )
                return str(PackageURL("npm", name=name, version=version))
            case Ecosystem.PYPI:
                return str(
                    PackageURL(
                        "pypi", name=name.lower().replace("-", "_"), version=version
                    )
                )
            case Ecosystem.CONAN:
                return str(PackageURL("conan", name=name, version=version))
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
        return f"SPDXRef-{self.ecosystem.value}-{safe}-{ver}"


@dataclass
class ScanResult:
    packages: list[Package] = field(default_factory=list)
    errors: list[tuple[Path, str]] = field(default_factory=list)

    def merge(self, other: "ScanResult") -> None:
        self.packages.extend(other.packages)
        self.errors.extend(other.errors)
