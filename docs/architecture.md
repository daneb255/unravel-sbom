# Architecture

## Package layout

```
src/unravel_sbom/
├── cli.py                ← click command group (scan / upload / dtrack)
├── models.py             ← Package, ScanResult, Ecosystem; PURL generation
├── walker.py             ← depth-first recursive scanner (unblob-style isolation)
├── scanners/
│   ├── base.py           ← BaseScanner ABC + safe_scan() error boundary
│   ├── npm.py            ← PackageJsonScanner, PackageLockScanner
│   ├── pypi.py           ← RequirementsTxtScanner, PyprojectTomlScanner, PoetryLockScanner
│   ├── conan.py          ← ConanfileTxtScanner, ConanfilePyScanner (AST)
│   ├── cmake.py          ← CMakeScanner (find_package, FetchContent, ExternalProject, CPM)
│   ├── ros.py            ← PackageXmlScanner (REP-149 package.xml, ament variable expansion)
│   └── makefile.py       ← MakefileScanner (-l flags, pkg-config, git clone / Yocto)
├── reporters/
│   ├── spdx.py           ← SPDX 2.3 JSON document builder + deduplication
│   └── cyclonedx.py      ← CycloneDX 1.6 JSON document builder + deduplication
└── upload/
    └── dtrack.py         ← Dependency-Track HTTP client (upload, poll, lookup)
```

## Data flow

```
Directory
    │
    ▼
walker.walk()          — depth-first, skips .git / __pycache__ / node_modules / venv
    │
    ├── scanner.matches(file)?
    │       └── scanner.safe_scan(file) → ScanResult
    │               └── errors isolated per file
    ▼
ScanResult             — list[Package] + list[errors]
    │
    ├── spdx_reporter.generate()   → SPDX 2.3 JSON dict
    └── cdx_reporter.generate()    → CycloneDX 1.6 JSON dict
                                           │
                                           └── dtrack.upload_bom() (optional)
```

## Adding a new scanner

Three steps — no changes needed in the walker, reporters, or upload client:

1. **Create** `src/unravel_sbom/scanners/myecosystem.py` and subclass `BaseScanner`.

    ```python
    from unravel_sbom.scanners.base import BaseScanner
    from unravel_sbom.models import ScanResult, Package, Ecosystem

    class MyScanner(BaseScanner):
        MANIFEST_NAMES = frozenset({"my-manifest.txt"})

        def scan(self, path: Path) -> ScanResult:
            result = ScanResult()
            # parse path, populate result.packages
            return result
    ```

2. **Add fixture files** under `tests/fixtures/myecosystem/`.

3. **Register** an instance in `src/unravel_sbom/scanners/__init__.py`:

    ```python
    from unravel_sbom.scanners.myecosystem import MyScanner

    ALL_SCANNERS = [
        ...,
        MyScanner(),
    ]
    ```

## Error isolation

Every scanner call goes through `safe_scan()` in `BaseScanner`. Any unhandled exception is caught, logged at `WARNING` level, and appended to `ScanResult.errors`. The walk always continues.

This mirrors the [unblob](https://github.com/onekey-sec/unblob) principle: partial results are far better than no results.
