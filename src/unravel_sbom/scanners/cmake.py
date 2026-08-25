"""CMakeLists.txt scanner.

Extracts dependencies declared via:
  - find_package(Name [version] ...)
  - FetchContent_Declare(name GIT_REPOSITORY ... GIT_TAG ...)
  - FetchContent_Declare(name URL ... URL_HASH ...)
  - ExternalProject_Add(name GIT_REPOSITORY ... GIT_TAG ...)
  - CPM_AddPackage(NAME name VERSION version ...)
  - ament_auto_find_build_dependencies(...) / ament_target_dependencies(...)
    with CMake variable expansion for ${VAR} list references (ROS2 pattern)
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from unravel_sbom.models import Ecosystem, Package, ScanResult
from unravel_sbom.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------

# CMake is case-insensitive for commands; flags/options inside calls are UPPER.
# Multi-line calls: content between the first '(' and its matching ')'.

# find_package(OpenSSL 3.1.2 REQUIRED) or find_package(Boost COMPONENTS ...)
_FIND_PKG_RE = re.compile(
    r"find_package\s*\(\s*([A-Za-z0-9_.\-]+)"  # name
    r"(?:\s+([0-9][A-Za-z0-9._\-]*))?",  # optional version
    re.IGNORECASE,
)

# FetchContent_Declare / ExternalProject_Add argument parsers
_FETCH_NAME_RE = re.compile(
    r"(?:FetchContent_Declare|ExternalProject_Add)\s*\(\s*([A-Za-z0-9_.\-]+)",
    re.IGNORECASE,
)

# GIT_TAG, VERSION, or URL_HASH can carry a version hint
_GIT_TAG_RE = re.compile(r"\bGIT_TAG\s+([^\s\)]+)", re.IGNORECASE)
_VERSION_RE = re.compile(r"\bVERSION\s+([0-9][A-Za-z0-9._\-]*)", re.IGNORECASE)
_GIT_REPO_RE = re.compile(r"\bGIT_REPOSITORY\s+(\S+)", re.IGNORECASE)
_URL_RE = re.compile(r"\bURL\s+(https?://\S+)", re.IGNORECASE)

# CPM_AddPackage(NAME name VERSION 1.2.3 ...)
_CPM_NAME_RE = re.compile(r"CPM_AddPackage\s*\(", re.IGNORECASE)
_CPM_KV_RE = re.compile(
    r"\b(NAME|VERSION|GITHUB_REPOSITORY|GIT_TAG)\s+(\S+)", re.IGNORECASE
)

# CMake variable set: set(FOO_VERSION 1.2.3) — used as fallback version lookup
_SET_VERSION_RE = re.compile(
    r"set\s*\(\s*([A-Za-z0-9_]+_VERSION)\s+([0-9][A-Za-z0-9._\-]*)\s*\)",
    re.IGNORECASE,
)

# set(VARNAME item1 item2 ...) — generic list variable (for ROS dep lists)
# Captured as: group(1)=name, group(2)=body (may span multiple lines)
# We use _extract_blocks to get the full body rather than a regex.

# ${VAR} reference in a CMake call argument
_VAR_REF_RE = re.compile(r"\$\{([A-Za-z0-9_]+)\}")

# ROS2 ament dependency declaration commands that take a list of package names
_AMENT_DEP_CMDS = (
    "ament_auto_find_build_dependencies",
    "ament_target_dependencies",
    "rosidl_target_interfaces",
)
# Keywords that are NOT package names inside those calls
_AMENT_KEYWORDS = frozenset(
    {
        "required",
        "optional",
        "public",
        "private",
        "interface",
        "targets",
        "target",
        "before",
        "after",
    }
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_blocks(content: str, command: str) -> list[str]:
    """Return the raw argument text of every call to *command* (case-insensitive)."""
    pattern = re.compile(rf"\b{command}\s*\(", re.IGNORECASE)
    blocks: list[str] = []
    for m in pattern.finditer(content):
        start = m.end()
        depth = 1
        i = start
        while i < len(content) and depth:
            if content[i] == "(":
                depth += 1
            elif content[i] == ")":
                depth -= 1
            i += 1
        blocks.append(content[start : i - 1])
    return blocks


def _strip_cmake_comments(content: str) -> str:
    """Remove # ... line comments from CMake source."""
    return re.sub(r"#[^\n]*", "", content)


def _clean_git_tag(tag: str) -> str:
    """Turn a git tag/hash into a human-readable version string."""
    tag = tag.strip('"').strip("'")
    # tags/v3.0.1 or refs/tags/v3.0.1
    tag = re.sub(r"^(?:refs/)?tags/", "", tag)
    # v1.2.3 → 1.2.3
    if re.match(r"^v\d", tag):
        return tag[1:]
    # asio-1-30-2 style: name-major-minor-patch
    dash_ver = re.match(r"^[a-z][\w]+-(\d+[-_]\d+[-_]\d+)", tag, re.IGNORECASE)
    if dash_ver:
        return dash_ver.group(1).replace("-", ".").replace("_", ".")
    return tag


def _name_from_repo_url(url: str) -> str:
    """Infer a short library name from a git/http URL."""
    base = url.rstrip("/").split("/")[-1]
    # strip .git suffix
    if base.endswith(".git"):
        base = base[:-4]
    return base


def _collect_set_versions(content: str) -> dict[str, str]:
    """Build a name→version map from set(FOO_VERSION x.y.z) declarations."""
    versions: dict[str, str] = {}
    for m in _SET_VERSION_RE.finditer(content):
        var_name = m.group(1).upper()  # e.g. OPENSSL_VERSION
        pkg_name = var_name.replace("_VERSION", "").lower()
        versions[pkg_name] = m.group(2)
    return versions


def _collect_cmake_lists(content: str) -> dict[str, list[str]]:
    """Build a variable-name → [items] map from set(VAR item1 item2 ...) blocks.

    Handles multi-line set() calls. Used to expand ${VAR} in ROS2 dep lists.
    """
    lists: dict[str, list[str]] = {}
    for block in _extract_blocks(content, "set"):
        tokens = block.split()
        if len(tokens) < 2:
            continue
        var_name = tokens[0]
        items = [t.strip('"').strip("'") for t in tokens[1:] if t.strip('"').strip("'")]
        lists[var_name] = items
    return lists


def _expand_cmake_args(
    tokens: list[str], cmake_lists: dict[str, list[str]]
) -> list[str]:
    """Expand ${VAR} references in a token list using *cmake_lists*."""
    result: list[str] = []
    for tok in tokens:
        m = _VAR_REF_RE.fullmatch(tok)
        if m:
            result.extend(cmake_lists.get(m.group(1), []))
        elif not _VAR_REF_RE.search(tok):
            # plain token, no unexpanded variable
            result.append(tok)
        # tokens with partial ${VAR} (e.g. "${PREFIX}_msgs") are dropped
    return result


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class CMakeScanner(BaseScanner):
    """Scans CMakeLists.txt for C/C++ dependencies declared via CMake primitives."""

    MANIFEST_NAMES = ("cmakelists.txt",)

    def scan(self, path: Path) -> ScanResult:
        result = ScanResult()
        raw = path.read_text(encoding="utf-8", errors="replace")
        content = _strip_cmake_comments(raw)

        set_versions = _collect_set_versions(content)
        cmake_lists = _collect_cmake_lists(content)
        seen: set[str] = set()

        def _add(name: str, version: str) -> None:
            key = name.lower()
            if key in seen:
                return
            seen.add(key)
            result.packages.append(
                Package(
                    name=name,
                    version=version or set_versions.get(name.lower(), "unknown"),
                    ecosystem=Ecosystem.GENERIC,
                    source_file=path,
                )
            )

        # ── find_package ────────────────────────────────────────────────────
        for m in _FIND_PKG_RE.finditer(content):
            name = m.group(1)
            # Skip CMake built-ins that are not real dependencies
            if name.lower() in (
                "threads",
                "cmake",
                "packagehandlestandardargs",
                "git",
                "doxygen",
                "python",
                "python3",
                "java",
                "pkg_check_modules",
            ):
                continue
            version = m.group(2) or set_versions.get(name.lower(), "unknown")
            _add(name, version)

        # ── FetchContent_Declare ─────────────────────────────────────────────
        for block in _extract_blocks(content, "FetchContent_Declare"):
            name_m = re.match(r"\s*([A-Za-z0-9_.\-]+)", block)
            if not name_m:
                continue
            name = name_m.group(1)

            version = "unknown"
            tag_m = _GIT_TAG_RE.search(block)
            ver_m = _VERSION_RE.search(block)
            if ver_m:
                version = ver_m.group(1)
            elif tag_m:
                version = _clean_git_tag(tag_m.group(1))

            # If still unknown, try to infer from repo URL
            if version == "unknown":
                repo_m = _GIT_REPO_RE.search(block) or _URL_RE.search(block)
                if repo_m:
                    inferred = _name_from_repo_url(repo_m.group(1))
                    if inferred.lower() != name.lower():
                        pass  # keep the declared name

            _add(name, version)

        # ── ExternalProject_Add ──────────────────────────────────────────────
        for block in _extract_blocks(content, "ExternalProject_Add"):
            name_m = re.match(r"\s*([A-Za-z0-9_.\-]+)", block)
            if not name_m:
                continue
            name = name_m.group(1)

            version = "unknown"
            tag_m = _GIT_TAG_RE.search(block)
            ver_m = _VERSION_RE.search(block)
            if ver_m:
                version = ver_m.group(1)
            elif tag_m:
                version = _clean_git_tag(tag_m.group(1))

            _add(name, version)

        # ── CPM_AddPackage ───────────────────────────────────────────────────
        for block in _extract_blocks(content, "CPM_AddPackage"):
            kv: dict[str, str] = {}
            for m in _CPM_KV_RE.finditer(block):
                kv[m.group(1).upper()] = m.group(2).strip('"').strip("'")

            name = kv.get("NAME", "")
            if not name and "GITHUB_REPOSITORY" in kv:
                name = _name_from_repo_url(kv["GITHUB_REPOSITORY"])
            if not name:
                continue

            version = kv.get("VERSION", "unknown")
            if version == "unknown":
                tag = kv.get("GIT_TAG", "")
                if tag:
                    version = _clean_git_tag(tag)

            _add(name, version)

        # ── ROS2 ament dependency declarations ───────────────────────────────
        # ament_auto_find_build_dependencies(REQUIRED ${IFM3D_ROS2_DEPS})
        # ament_target_dependencies(target PUBLIC ${DEPS})  ← first token is target
        for cmd in _AMENT_DEP_CMDS:
            skip_first = cmd.lower() == "ament_target_dependencies"
            for block in _extract_blocks(content, cmd):
                raw_tokens = block.split()
                tokens = _expand_cmake_args(raw_tokens, cmake_lists)
                first = True
                for tok in tokens:
                    tok = tok.strip('"').strip("'")
                    if not tok:
                        continue
                    # ament_target_dependencies: first token is always the CMake target
                    if skip_first and first:
                        first = False
                        continue
                    first = False
                    # Skip keywords, cmake imported targets (contain ::),
                    # and unexpanded vars
                    if (
                        tok.lower() in _AMENT_KEYWORDS
                        or "::" in tok
                        or tok.startswith("$")
                    ):
                        continue
                    _add(tok, "unknown")

        return result
