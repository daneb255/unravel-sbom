from __future__ import annotations

import ast
import logging
import re
from pathlib import Path

from unravel_sbom.models import Ecosystem, Package, ScanResult
from unravel_sbom.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# conanfile.txt: lines under [requires] look like "zlib/1.2.11" or "boost/1.79.0@conan/stable"
_REQUIRES_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.\-]+)/(?P<version>[A-Za-z0-9._\-]+)(?:@[^\s]*)?"
)


class ConanfileTxtScanner(BaseScanner):
    MANIFEST_NAMES = ("conanfile.txt",)

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        in_requires = False
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                in_requires = stripped.lower().startswith("[requires]")
                continue
            if not in_requires or not stripped or stripped.startswith("#"):
                continue
            m = _REQUIRES_RE.match(stripped)
            if m:
                result.packages.append(
                    Package(
                        name=m.group("name"),
                        version=m.group("version"),
                        ecosystem=Ecosystem.CONAN,
                        source_file=path,
                    )
                )
        return result


class ConanfilePyScanner(BaseScanner):
    """Parses conanfile.py via AST to extract requires/build_requires assignments."""

    MANIFEST_NAMES = ("conanfile.py",)

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            raise ValueError(f"AST parse failed: {exc}") from exc

        requires_strings: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for item in ast.walk(node):
                # class-level assignments: requires = "zlib/1.2.11" or requires = ["zlib/1.2.11"]
                if isinstance(item, ast.Assign):
                    for target in item.targets:
                        if isinstance(target, ast.Name) and target.id in (
                            "requires",
                            "build_requires",
                        ):
                            requires_strings.extend(_extract_str_values(item.value))
                # self.requires("zlib/1.2.11") calls
                elif isinstance(item, ast.Call):
                    func = item.func
                    if isinstance(func, ast.Attribute) and func.attr in (
                        "requires",
                        "build_requires",
                    ):
                        for arg in item.args:
                            if isinstance(arg, ast.Constant) and isinstance(
                                arg.value, str
                            ):
                                requires_strings.append(arg.value)

        for ref in requires_strings:
            m = _REQUIRES_RE.match(ref.strip())
            if m:
                result.packages.append(
                    Package(
                        name=m.group("name"),
                        version=m.group("version"),
                        ecosystem=Ecosystem.CONAN,
                        source_file=path,
                    )
                )
        return result


def _extract_str_values(node: ast.expr) -> list[str]:
    """Recursively collect string literals from an AST node (Constant or List/Tuple)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple)):
        values: list[str] = []
        for elt in node.elts:
            values.extend(_extract_str_values(elt))
        return values
    return []
