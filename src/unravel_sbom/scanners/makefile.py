from __future__ import annotations

import logging
import re
import shlex
from pathlib import Path

from unravel_sbom.models import Ecosystem, Package, ScanResult
from unravel_sbom.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# Matches: LDFLAGS = -lz -lpthread  or  LDLIBS += -lssl -lcrypto
_FLAG_VAR_RE = re.compile(r"^\s*(?:LDFLAGS|LDLIBS)\s*[\+:?]?=\s*(.+)", re.MULTILINE)
# A -l flag references a library: -lz → libz, -lssl → libssl
_LIB_FLAG_RE = re.compile(r"-l([A-Za-z0-9_.\-]+)")
# pkg-config calls: $(shell pkg-config --libs foo bar)
_PKG_CONFIG_RE = re.compile(r"pkg-config\s+(?:--[a-z\-]+\s+)*([A-Za-z0-9_.\- ]+)")

# git clone [-b branch] URL  — used by Yocto/fetch-style Makefiles
# Captures everything on the line after "git clone" up to ; or end-of-line
_GIT_CLONE_RE = re.compile(r"git\s+clone\b([^\n;]*)", re.IGNORECASE)
_GIT_URL_RE = re.compile(r"(https?://\S+|git://\S+)")
_GIT_BRANCH_FLAG_RE = re.compile(r"-b\s+(?!https?://)([A-Za-z0-9._\-]+)")

# Simple Make variable assignment: NAME = value  (used to resolve $(BRANCH) etc.)
_MAKE_VAR_ASSIGN_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*[\?:+]?=\s*([^\\\n]+)",
    re.MULTILINE,
)


def _strip_make_variables(text: str) -> str:
    """Remove $(VAR) / ${VAR} interpolations so shlex doesn't choke."""
    return re.sub(r"\$[\(\{][^\)\}]*[\)\}]", "", text)


def _name_from_url(url: str) -> str:
    """Extract a short package name from a git/http URL."""
    base = url.rstrip("/").split("/")[-1]
    if base.endswith(".git"):
        base = base[:-4]
    return base


class MakefileScanner(BaseScanner):
    MANIFEST_NAMES = (
        "makefile",
        "makefile.am",
        "makefile.in",
        "gnumakefile",
        "makefile.yocto",
    )

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        content = path.read_text(encoding="utf-8", errors="replace")

        libs: dict[str, str] = {}  # name → version

        # 1. Extract -l flags from LDFLAGS / LDLIBS
        for match in _FLAG_VAR_RE.finditer(content):
            value = _strip_make_variables(match.group(1))
            try:
                tokens = shlex.split(value)
            except ValueError:
                tokens = value.split()
            for token in tokens:
                lm = _LIB_FLAG_RE.match(token)
                if lm:
                    libs[lm.group(1)] = "unknown"

        # 2. Extract pkg-config module names
        for match in _PKG_CONFIG_RE.finditer(content):
            raw = _strip_make_variables(match.group(1))
            for name in raw.split():
                name = name.strip()
                if name and not name.startswith("-"):
                    libs[name] = "unknown"

        # 3. git clone URLs (Yocto / fetch-style Makefiles)
        # Collect simple variable assignments first so $(BRANCH) can be resolved
        make_vars: dict[str, str] = {}
        for m in _MAKE_VAR_ASSIGN_RE.finditer(content):
            val = _strip_make_variables(m.group(2)).strip()
            if val:
                make_vars[m.group(1)] = val

        for m in _GIT_CLONE_RE.finditer(content):
            args = m.group(1)
            url_m = _GIT_URL_RE.search(args)
            if not url_m:
                continue
            url = url_m.group(1).rstrip(";\\'\"")
            name = _name_from_url(url)
            if not name or name in libs:
                continue

            # Try explicit -b <branch> first; variable refs will have been stripped
            args_clean = _strip_make_variables(args)
            branch_m = _GIT_BRANCH_FLAG_RE.search(args_clean)
            if branch_m:
                version = branch_m.group(1)
            else:
                # Fall back to a BRANCH variable declared elsewhere in the file
                version = make_vars.get("BRANCH", "unknown")

            libs[name] = version

        for name, version in libs.items():
            result.packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.GENERIC,
                    source_file=path,
                    supplier=f"Makefile:{path.name}",
                )
            )
        return result
