from __future__ import annotations

import logging
import re
import sys
from pathlib import Path

from unravel_sbom.models import Ecosystem, Package, ScanResult
from unravel_sbom.scanners.base import BaseScanner

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]

logger = logging.getLogger(__name__)

# Matches: name==1.2.3, name>=1.0,<2, name~=1.4, etc.
_REQ_LINE_RE = re.compile(
    r"""^
    \s*
    (?P<name>[A-Za-z0-9_.\-]+)   # package name
    \s*
    (?P<spec>[^;#\n]*)            # version specifier(s), optional
    """,
    re.VERBOSE,
)
# Extract the first concrete version from a specifier string, e.g. "==1.2.3" → "1.2.3"
_VERSION_RE = re.compile(r"[=!<>~^]{1,2}\s*([A-Za-z0-9._*+-]+)")


def _extract_version(spec: str) -> str:
    """Return the first pinned/ranged version from a PEP-508 specifier, or 'unknown'."""
    if not spec:
        return "unknown"
    # Prefer exact pins
    exact = re.search(r"==\s*([A-Za-z0-9._+-]+)", spec)
    if exact:
        return exact.group(1)
    m = _VERSION_RE.search(spec)
    return m.group(1) if m else "unknown"


class RequirementsTxtScanner(BaseScanner):
    MANIFEST_NAMES = (
        "requirements.txt",
        "requirements-dev.txt",
        "requirements_dev.txt",
    )

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", "-r", "--", "git+", "http")):
                continue
            m = _REQ_LINE_RE.match(line)
            if not m:
                continue
            name = m.group("name")
            version = _extract_version(m.group("spec"))
            result.packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.PYPI,
                    source_file=path,
                )
            )
        return result


class PyprojectTomlScanner(BaseScanner):
    MANIFEST_NAMES = ("pyproject.toml",)

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        data = tomllib.loads(path.read_text(encoding="utf-8"))

        # PEP-621 / hatch / flit
        project_deps: list[str] = data.get("project", {}).get("dependencies", [])
        for dep in project_deps:
            m = _REQ_LINE_RE.match(dep)
            if m:
                result.packages.append(
                    Package(
                        name=m.group("name"),
                        version=_extract_version(m.group("spec")),
                        ecosystem=Ecosystem.PYPI,
                        source_file=path,
                    )
                )

        # Poetry [tool.poetry.dependencies]
        poetry_deps: dict = (
            data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        )
        for name, constraint in poetry_deps.items():
            if name.lower() == "python":
                continue
            if isinstance(constraint, str):
                version = _extract_version(constraint)
            elif isinstance(constraint, dict):
                version = constraint.get("version", "unknown")
                version = (
                    _extract_version(version) if version != "unknown" else "unknown"
                )
            else:
                version = "unknown"
            result.packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.PYPI,
                    source_file=path,
                )
            )

        return result


class PoetryLockScanner(BaseScanner):
    MANIFEST_NAMES = ("poetry.lock",)

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        for entry in data.get("package", []):
            name = entry.get("name", "")
            version = entry.get("version", "unknown")
            if not name:
                continue
            result.packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.PYPI,
                    source_file=path,
                )
            )
        return result
