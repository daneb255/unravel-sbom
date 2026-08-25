from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path

from unravel_sbom.models import ScanResult

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """Parse a single manifest file and return discovered packages."""

    # Filenames this scanner handles (lower-cased for matching)
    MANIFEST_NAMES: tuple[str, ...] = ()
    # File extensions this scanner handles (e.g. ('.csproj', '.fsproj'))
    MANIFEST_EXTENSIONS: tuple[str, ...] = ()

    def matches(self, path: Path) -> bool:
        name_match = path.name.lower() in self.MANIFEST_NAMES
        ext_match = (
            path.suffix.lower() in self.MANIFEST_EXTENSIONS
            if self.MANIFEST_EXTENSIONS
            else False
        )
        return name_match or ext_match

    def safe_scan(self, path: Path) -> ScanResult:
        """Wraps scan() with error isolation so one bad file doesn't abort the run."""
        try:
            result = self.scan(path)
            logger.debug("Scanned %s → %d packages", path, len(result.packages))
            return result
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse %s: %s", path, exc)
            result = ScanResult()
            result.errors.append((path, str(exc)))
            return result

    @abstractmethod
    def scan(self, path: Path) -> ScanResult:
        """Parse the manifest at *path* and return a ScanResult."""
