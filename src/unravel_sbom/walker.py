"""Recursive directory walker — inspired by unblob's extraction strategy.

Walk a directory tree depth-first, match each file against registered
scanners, and aggregate results while isolating per-file failures.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from unravel_sbom.models import ScanResult
from unravel_sbom.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# Directories that are almost never useful to scan
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        ".venv",
        "venv",
        ".env",
        "env",
        "dist",
        "build",
        ".eggs",
    }
)


def walk(
    root: Path,
    scanners: list[BaseScanner],
    *,
    max_depth: int | None = None,
    on_file: Callable[[Path], None] | None = None,
    _current_depth: int = 0,
) -> ScanResult:
    """Recursively scan *root* using all registered *scanners*.

    Errors in individual files are logged and collected; the walk always
    continues (unblob principle of error isolation).

    Args:
        on_file: Optional callback invoked with the matched file path just
                 before it is scanned. Used by the CLI progress display.
    """
    aggregate = ScanResult()

    try:
        entries = sorted(root.iterdir())
    except PermissionError as exc:
        logger.warning("Cannot read directory %s: %s", root, exc)
        aggregate.errors.append((root, str(exc)))
        return aggregate

    for entry in entries:
        try:
            if entry.is_symlink():
                logger.debug("Skipping symlink %s", entry)
                continue

            if entry.is_dir():
                if entry.name in _SKIP_DIRS:
                    logger.debug("Skipping directory %s", entry)
                    continue
                if max_depth is not None and _current_depth >= max_depth:
                    continue
                sub = walk(
                    entry,
                    scanners,
                    max_depth=max_depth,
                    on_file=on_file,
                    _current_depth=_current_depth + 1,
                )
                aggregate.merge(sub)

            elif entry.is_file():
                for scanner in scanners:
                    if scanner.matches(entry):
                        logger.debug("Matched %s → %s", entry, type(scanner).__name__)
                        if on_file is not None:
                            on_file(entry)
                        partial = scanner.safe_scan(entry)
                        aggregate.merge(partial)
                        # A file can be matched by at most one scanner type at a time.
                        break

        except Exception as exc:
            logger.warning("Unexpected error processing %s: %s", entry, exc)
            aggregate.errors.append((entry, str(exc)))

    return aggregate
