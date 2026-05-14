# unravel-sbom

**Generate accurate, standards-compliant Software Bills of Materials (SBOMs) from your local development projects — in seconds.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![SPDX 2.3](https://img.shields.io/badge/SPDX-2.3-green.svg)](https://spdx.github.io/spdx-spec/v2.3/)
[![CycloneDX 1.6](https://img.shields.io/badge/CycloneDX-1.6-orange.svg)](https://cyclonedx.org/docs/1.6/)
[![Dependency-Track](https://img.shields.io/badge/Dependency--Track-ready-blue.svg)](https://dependencytrack.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`unravel-sbom` is an open-source Python CLI tool that recursively scans multi-ecosystem development projects and produces valid SBOMs in **[SPDX v2.3](https://spdx.github.io/spdx-spec/v2.3/)** and **[CycloneDX 1.6](https://cyclonedx.org/docs/1.6/)** JSON format. It covers **npm**, **PyPI**, **Conan**, **CMake**, **ROS/ROS2**, and **Makefile**-based C/C++ projects — and pushes results directly to **[Dependency-Track](https://dependencytrack.org/)** in a single command.

Whether you need SBOM generation for supply-chain compliance, vulnerability management, or license auditing, `unravel-sbom` gives you a machine-readable inventory of every dependency, complete with Package URLs (PURLs), SPDX license identifiers, and supplier metadata.

---

## Table of Contents

- [Why unravel-sbom?](#why-unravel-sbom)
- [Inspired by unblob](#inspired-by-unblob)
- [Shift Left with pkggate](#shift-left-with-pkggate)
- [Features](#features)
- [Supported Ecosystems](#supported-ecosystems)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Output Formats](#output-formats)
  - [SPDX 2.3](#spdx-23)
  - [CycloneDX 1.6](#cyclonedx-16)
- [Dependency-Track Integration](#dependency-track-integration)
  - [Scan and Upload in One Step](#scan-and-upload-in-one-step)
  - [Upload an Existing BOM](#upload-an-existing-bom)
  - [Project Lookup](#project-lookup)
  - [CI/CD Pipeline Example](#cicd-pipeline-example)
- [Architecture](#architecture)
- [Running Tests](#running-tests)
- [CI/CD and Publishing](#cicd-and-publishing)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Why unravel-sbom?

Supply-chain security is no longer optional. Regulations like the US Executive Order 14028, the EU Cyber Resilience Act, and frameworks such as SLSA and NTIA all require a software bill of materials. Existing SBOM tools are often language-specific, heavyweight, or produce output that fails validation.

`unravel-sbom` was built around three principles:

1. **Correctness first.** Every output field maps directly to the SPDX 2.3 and CycloneDX 1.6 specifications. PURLs are generated via the official `packageurl-python` library. Documents are ready for immediate ingestion by Grype, Dependency-Track, FOSSA, and other SBOM-aware tools.
2. **Resilience over rigidity.** A single malformed `package.json` should never abort a scan of thousands of files. Each parser is isolated — errors are collected and reported, not thrown.
3. **Zero heavy dependencies.** No Docker daemon, no language runtimes beyond Python 3.10. Point it at a directory, get a standards-compliant SBOM, and optionally push it to Dependency-Track — all from one command.

---

## Inspired by unblob

The recursive scanning and error-isolation strategy in `unravel-sbom` is directly inspired by **[unblob](https://github.com/onekey-sec/unblob)**, the open-source firmware extraction tool developed by [ONEKEY](https://onekey.com).

unblob's core philosophy is to scan deeply into unknown binary structures while never letting a single extraction failure prevent the rest of the analysis from completing. We apply the same principle to source-code manifests:

- The walker descends into every subdirectory it can read.
- Each scanner wraps its parser in a `safe_scan()` boundary.
- Failures are logged with full context and collected into the final result — they do not propagate as exceptions.
- Symlinks and well-known noise directories (`.git`, `__pycache__`, `node_modules`, virtual envs) are skipped automatically.

This makes `unravel-sbom` suitable for scanning large monorepos, embedded firmware source trees, and CI pipelines where partial results are far better than no results.

---

## Shift Left with pkggate

Generating an SBOM tells you what is already in your project. Preventing vulnerable or policy-violating packages from entering in the first place is the next layer of defence — this is the shift-left principle applied to supply-chain security.

**[pkggate](https://github.com/daneb255/pkggate)** is an open-source package firewall that sits in front of your package registries (PyPI, npm, and others) and enforces security policy at install time, before a dependency ever lands in your codebase:

- Blocks packages with known CVEs above a configurable severity threshold
- Enforces allow/deny lists and licence policies
- Logs every install decision for audit purposes
- Works transparently as a pip/npm proxy — no changes to developer workflows

### How the two tools complement each other

| Layer | Tool | When it acts |
| --- | --- | --- |
| **Prevent** — block vulnerable packages at install time | [pkggate](https://github.com/daneb255/pkggate) | Developer workstation & CI install step |
| **Detect** — inventory what is in the project and track it | `unravel-sbom` | After install, on every build or release |
| **Monitor** — continuous vulnerability tracking over time | Dependency-Track | Ongoing, fed by `unravel-sbom` uploads |

Used together they close the full loop: pkggate stops bad packages coming in, `unravel-sbom` documents everything that did come in, and Dependency-Track alerts you if the risk profile changes after release.

---

## Features

- **Recursive multi-ecosystem scanning** — one command covers the entire project tree
- **SPDX 2.3 JSON output** — validated against the official specification
- **CycloneDX 1.6 JSON output** — alternative format for Dependency-Track and other tools
- **Both formats simultaneously** — `--format both` writes `.spdx.json` and `.cdx.json` in one pass
- **Native Dependency-Track upload** — push the BOM directly via `PUT /api/v1/bom` with async token polling
- **Package URL (PURL)** per component — compatible with OSV, Grype, and Dependency-Track
- **SPDX license identifiers** — `MIT`, `Apache-2.0`, `GPL-3.0-only`, compound expressions, and more
- **Automatic deduplication** — identical `(name, ecosystem, version)` entries are merged
- **Lock-file priority** — resolved versions from lock files take precedence over range specifiers
- **Configurable depth** — limit recursion with `--max-depth` for large trees
- **Live progress bar** — real-time file counter with current filename while scanning; automatically suppressed in CI/piped output
- **Elapsed time** — every scan reports how long it took (`45ms`, `1.2s`, `2m 5s`)
- **Environment-variable support** — `$DTRACK_URL` and `$DTRACK_API_KEY` for clean CI pipelines
- **CMake support** — extracts `find_package()`, `FetchContent_Declare()`, `ExternalProject_Add()`, and `CPM_AddPackage()` with version normalisation (`v1.2.3`, `tags/v1.2.3`, `name-1-2-3` all resolved correctly)
- **ROS / ROS2 support** — parses `package.xml` (REP-149 format 3) for all dependency tag types; expands `${VAR}` lists in `ament_auto_find_build_dependencies()` and `ament_target_dependencies()`
- **119 unit tests** — covering every scanner, walker, SPDX/CycloneDX reporters, and the upload client

---

## Supported Ecosystems

| Ecosystem | Files Scanned | Notes |
|-----------|--------------|-------|
| **npm / Node.js** | `package.json`, `package-lock.json` | Lock file (v1/v2/v3) preferred for exact versions; scoped packages (`@scope/name`) fully supported |
| **PyPI / Python** | `requirements.txt`, `pyproject.toml`, `poetry.lock` | Handles PEP-621, Hatch, Flit, and Poetry formats; `python` itself is excluded |
| **Conan / C++** | `conanfile.txt`, `conanfile.py` | AST-based parsing of `.py` files; resolves `requires`, `build_requires`, and `self.requires()` calls |
| **CMake / C++** | `CMakeLists.txt` | Extracts `find_package()`, `FetchContent_Declare()`, `ExternalProject_Add()`, `CPM_AddPackage()`; normalises `v`-prefixed tags, `tags/v…`, and dash-separated version tags; skips CMake built-ins |
| **ROS / ROS2** | `package.xml`, `CMakeLists.txt` | Parses REP-149 `package.xml` for all dep tags (`<depend>`, `<build_depend>`, `<exec_depend>`, `<test_depend>`, etc.) with version constraints; expands CMake `${VAR}` lists in `ament_auto_find_build_dependencies()` |
| **Makefile / C** | `Makefile`, `Makefile.am`, `Makefile.in`, `Makefile.yocto` | Extracts `-l` flags from `LDFLAGS`/`LDLIBS`, `pkg-config` module names, and `git clone` URLs with branch-as-version (Yocto/fetch-style projects) |

---

## Installation

**From source (recommended during development):**

```bash
git clone https://github.com/your-org/unravel-sbom.git
cd unravel-sbom
pip install -e .
```

**Requirements:**

- Python 3.10 or later
- `click >= 8.1`
- `packageurl-python >= 0.16`
- `tomli >= 2.0` (Python < 3.11 only)

---

## Quick Start

```bash
# Scan and write SPDX 2.3 JSON (default)
unravel-sbom scan .

# Scan a C++ project using CMake
unravel-sbom scan ~/projects/my-cpp-app -f cyclonedx

# Write CycloneDX 1.6 JSON
unravel-sbom scan . -f cyclonedx

# Write both formats at once
unravel-sbom scan . -f both

# Scan, write CycloneDX, and push to Dependency-Track
unravel-sbom scan . -f cyclonedx \
  --dtrack-url https://dtrack.example.com \
  --dtrack-key $DTRACK_API_KEY \
  --dtrack-project myapp --dtrack-version 1.4.2

# Upload an existing BOM file to Dependency-Track
unravel-sbom upload myapp.cdx.json \
  --dtrack-url https://dtrack.example.com \
  --dtrack-key $DTRACK_API_KEY
```

Example terminal output:

```text
Scanning /home/user/projects/my-app …
    42 files  package-lock.json
  Found 148 package entries in 0.3s.
  CycloneDX 1.6 → my-app.cdx.json  (132 components)
  Dependency-Track ✓  token=3a9f1c2d-...  (https://dtrack.example.com)
```
---

## CLI Reference

`unravel-sbom` uses a sub-command structure:

```
unravel-sbom scan     — scan a directory and write an SBOM
unravel-sbom upload   — upload an existing CycloneDX BOM to Dependency-Track
unravel-sbom dtrack   — Dependency-Track project management utilities
```

### `unravel-sbom scan`

```
Usage: unravel-sbom scan [OPTIONS] SOURCE

Options:
  -o, --output FILE               Output path (default: <dir>.spdx.json or <dir>.cdx.json)
  -f, --format [spdx|cyclonedx|both]
                                  Output format  [default: spdx]
  --name TEXT                     Document/BOM name  [default: SBOM-<dir>]
  --max-depth INTEGER             Maximum recursion depth  [default: unlimited]
  --dtrack-url URL                Dependency-Track base URL  [$DTRACK_URL]
  --dtrack-key KEY                Dependency-Track API key  [$DTRACK_API_KEY]
  --dtrack-project NAME           Project name  [default: directory name]
  --dtrack-version TEXT           Project version  [default: latest]
  --dtrack-uuid UUID              Target project by UUID instead of name+version
  --dtrack-autocreate / --no-dtrack-autocreate
                                  Auto-create project if missing  [default: on]
  --dtrack-wait                   Poll until Dependency-Track finishes processing
  --dtrack-timeout SECS           HTTP timeout in seconds  [default: 30]
  -v, --verbose                   Enable debug logging
  -h, --help                      Show this message and exit
```

### `unravel-sbom upload`

```
Usage: unravel-sbom upload [OPTIONS] BOM_FILE

Options:
  --dtrack-url URL      Dependency-Track base URL  [$DTRACK_URL]  (required)
  --dtrack-key KEY      Dependency-Track API key   [$DTRACK_API_KEY]  (required)
  --dtrack-project NAME Project name  [default: BOM filename stem]
  --dtrack-version TEXT Project version  [default: latest]
  --dtrack-uuid UUID    Target project by UUID
  --dtrack-autocreate / --no-dtrack-autocreate  [default: on]
  --dtrack-wait         Poll until processing is complete
  --dtrack-timeout SECS [default: 30]
  -v, --verbose
  -h, --help
```

### `unravel-sbom dtrack lookup`

```
Usage: unravel-sbom dtrack lookup [OPTIONS] PROJECT_NAME PROJECT_VERSION

  Look up a project by name and version and print its metadata as JSON.

Options:
  --url URL   Dependency-Track base URL  [$DTRACK_URL]  (required)
  --key KEY   API key  [$DTRACK_API_KEY]  (required)
```

---

## Output Formats

### SPDX 2.3

Every package entry in the SPDX JSON output includes:

```json
{
  "SPDXID": "SPDXRef-npm-express-4-18-2",
  "name": "express",
  "versionInfo": "4.18.2",
  "downloadLocation": "NOASSERTION",
  "filesAnalyzed": false,
  "licenseConcluded": "MIT",
  "licenseDeclared": "MIT",
  "copyrightText": "NOASSERTION",
  "supplier": "NOASSERTION",
  "externalRefs": [
    {
      "referenceCategory": "PACKAGE-MANAGER",
      "referenceType": "purl",
      "referenceLocator": "pkg:npm/express@4.18.2"
    }
  ]
}
```

| Document field | Value |
| --- | --- |
| `spdxVersion` | `SPDX-2.3` |
| `dataLicense` | `CC0-1.0` |
| `creationInfo.creators` | `Tool: unravel-sbom-0.1.0` |
| `relationships` | `DOCUMENT DESCRIBES <package>` for every entry |

### CycloneDX 1.6

Every component in the CycloneDX JSON output includes:

```json
{
  "type": "library",
  "bom-ref": "SPDXRef-npm-express-4-18-2",
  "name": "express",
  "version": "4.18.2",
  "purl": "pkg:npm/express@4.18.2",
  "licenses": [
    {
      "license": {
        "id": "MIT",
        "acknowledgement": "declared"
      }
    }
  ]
}
```

| Document field | Value |
| --- | --- |
| `bomFormat` | `CycloneDX` |
| `specVersion` | `1.6` |
| `serialNumber` | `urn:uuid:<uuid4>` per RFC 4122 |
| `metadata.tools` | `unravel-sbom 0.1.0` |

Compound license expressions (e.g. `MIT OR Apache-2.0`) are written as `{ "expression": "MIT OR Apache-2.0" }` per the CycloneDX spec. Components with no known license omit the `licenses` field entirely rather than writing `NOASSERTION`.

Both formats are directly consumable by:

| Tool | Use case |
| --- | --- |
| **[Dependency-Track](https://dependencytrack.org/)** | Continuous component analysis, vulnerability tracking |
| **[Grype](https://github.com/anchore/grype)** | Vulnerability scanning against the SBOM |
| **[FOSSA](https://fossa.com/)** | License compliance |
| **[sw360](https://www.eclipse.org/sw360/)** | Component lifecycle management |
| **[Syft](https://github.com/anchore/syft)** | Cross-format SBOM tooling |

---

## Dependency-Track Integration

[Dependency-Track](https://github.com/DependencyTrack/dependency-track) is an open-source SBOM analysis platform that continuously tracks vulnerabilities, licence risk, and component age across your portfolio. `unravel-sbom` uploads CycloneDX BOMs directly via the documented [CI/CD API endpoint](https://docs.dependencytrack.org/usage/cicd/).

### How the upload works

1. The BOM is JSON-encoded and Base64-wrapped as required by `PUT /api/v1/bom`.
2. Authentication uses the `X-Api-Key` header — generate a key under **Administration → Access Management → Teams** in Dependency-Track.
3. Dependency-Track returns an async processing token. With `--dtrack-wait`, `unravel-sbom` polls `GET /api/v1/bom/token/{token}` every 5 seconds until analysis completes (up to 5 minutes).
4. If the project does not exist and `--dtrack-autocreate` is on (the default), Dependency-Track creates it automatically.

### Scan and Upload in One Step

```bash
unravel-sbom scan ./my-app \
  --dtrack-url https://dtrack.example.com \
  --dtrack-key $DTRACK_API_KEY \
  --dtrack-project "my-app" \
  --dtrack-version "2.1.0" \
  --dtrack-wait
```

The upload always sends a CycloneDX 1.6 BOM regardless of `--format`. If you also want a local SPDX file, combine them:

```bash
unravel-sbom scan ./my-app \
  -f both \
  --dtrack-url https://dtrack.example.com \
  --dtrack-key $DTRACK_API_KEY \
  --dtrack-project "my-app" --dtrack-version "2.1.0"
```

### Upload an Existing BOM

If you already have a `.cdx.json` on disk (e.g. from a previous scan or another tool):

```bash
unravel-sbom upload my-app.cdx.json \
  --dtrack-url https://dtrack.example.com \
  --dtrack-key $DTRACK_API_KEY \
  --dtrack-project "my-app" \
  --dtrack-version "2.1.0"
```

### Target a Project by UUID

For scripted pipelines where the project UUID is known:

```bash
unravel-sbom scan ./my-app \
  --dtrack-url https://dtrack.example.com \
  --dtrack-key $DTRACK_API_KEY \
  --dtrack-uuid "f90934f5-cb88-47ce-81cb-db06fc67d4b4"
```

### Project Lookup

Inspect a project's metadata without uploading anything:

```bash
unravel-sbom dtrack lookup "my-app" "2.1.0" \
  --url https://dtrack.example.com \
  --key $DTRACK_API_KEY
```

Output (JSON):

```json
{
  "uuid": "f90934f5-cb88-47ce-81cb-db06fc67d4b4",
  "name": "my-app",
  "version": "2.1.0",
  "lastBomImport": "2024-11-01T12:34:56.000Z",
  "metrics": {
    "critical": 0,
    "high": 2,
    "medium": 7
  }
}
```

### CI/CD Pipeline Example

**GitHub Actions:**

```yaml
- name: Generate and upload SBOM
  env:
    DTRACK_URL: ${{ secrets.DTRACK_URL }}
    DTRACK_API_KEY: ${{ secrets.DTRACK_API_KEY }}
  run: |
    pip install unravel-sbom
    unravel-sbom scan . \
      -f cyclonedx \
      --dtrack-project "${{ github.repository }}" \
      --dtrack-version "${{ github.ref_name }}" \
      --dtrack-wait
```

**GitLab CI:**

```yaml
sbom:
  stage: test
  script:
    - pip install unravel-sbom
    - unravel-sbom scan .
        -f cyclonedx
        --dtrack-url $DTRACK_URL
        --dtrack-key $DTRACK_API_KEY
        --dtrack-project $CI_PROJECT_NAME
        --dtrack-version $CI_COMMIT_TAG
        --dtrack-wait
  artifacts:
    paths:
      - "*.cdx.json"
```

---

## Architecture

```
unravel_sbom/
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

**Adding a new scanner** takes three steps:

1. Create `scanners/myecosystem.py` and subclass `BaseScanner`.
2. Set `MANIFEST_NAMES` and implement `scan(path) -> ScanResult`.
3. Add an instance to `ALL_SCANNERS` in `scanners/__init__.py`.

No changes are needed in the walker, reporters, or upload client.

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

```
119 passed in 0.21s
```

Test coverage:

| Area | Tests |
| --- | --- |
| npm scanner (package.json, package-lock.json v1–v3) | 6 |
| PyPI scanner (requirements.txt, pyproject.toml, poetry.lock) | 9 |
| Conan scanner (conanfile.txt, conanfile.py AST) | 6 |
| CMake scanner (find_package, FetchContent, ExternalProject, CPM) | 26 |
| ROS/ROS2 scanner (package.xml, ament variable expansion) | 20 |
| Makefile scanner (LDFLAGS, LDLIBS, pkg-config, git clone) | 6 |
| Walker (recursion, skip-dirs, error isolation) | 3 |
| SPDX 2.3 reporter (fields, PURLs, deduplication, relationships) | 6 |
| CycloneDX 1.6 reporter (fields, license forms, deduplication) | 11 |
| Dependency-Track client (upload, poll, lookup, errors, CLI) | 26 |

---

## CI/CD and Publishing

Three GitHub Actions workflows ship with the project under [.github/workflows/](.github/workflows/).

### Workflows at a glance

| File | Triggers | Purpose |
| --- | --- | --- |
| `ci.yml` | push / PR → `main` | Lint, type-check, test across Python 3.10–3.12, enforce 80 % coverage |
| `security.yml` | push / PR / weekly cron | Bandit static analysis + Safety dependency scan, PR comment with results |
| `publish.yml` | GitHub Release published | Full 5-stage pipeline: test → build → TestPyPI → smoke-test → PyPI |

### Publish pipeline stages

```
Release published
      │
      ▼
 1. test          pytest on 3.10, 3.11, 3.12  (all must pass)
      │
      ▼
 2. build         python -m build → sdist + wheel, twine check
      │
      ▼
 3. publish-testpypi   → https://test.pypi.org/p/unravel-sbom
      │
      ▼
 4. smoke-test    installs from TestPyPI, runs unravel-sbom --version
                  + scans a minimal package.json, asserts CycloneDX output
      │
      ▼
 5. publish-pypi  → https://pypi.org/p/unravel-sbom  (OIDC trusted publishing)
```

### PyPI trusted publishing setup (no API token required)

This project uses [OIDC trusted publishing](https://docs.pypi.org/trusted-publishers/), which means **no `PYPI_API_TOKEN` secret is needed**. One-time setup:

1. Go to **[pypi.org/manage/account/publishing](https://pypi.org/manage/account/publishing/)** (and the same on [test.pypi.org](https://test.pypi.org/manage/account/publishing/)).
2. Add a new trusted publisher:
   - **PyPI project name:** `unravel-sbom`
   - **Owner:** `<your-github-username>`
   - **Repository:** `unravel-sbom`
   - **Workflow filename:** `publish.yml`
   - **Environment name:** `pypi` (or `testpypi`)
3. Create matching **Environments** in the GitHub repo settings (`pypi`, `testpypi`).
4. Publish a GitHub Release — the workflow fires automatically.

### Installing dev dependencies locally

```bash
pip install -e ".[dev]"

# Run the full local check identical to CI
ruff check src tests
ruff format --check src tests
mypy src --ignore-missing-imports
pytest tests/ -v --cov=src --cov-report=term-missing
coverage report --fail-under=80
```

---

## Roadmap

### v0.2 — Ecosystem coverage

- [x] **CMake** — `CMakeLists.txt` (`find_package`, `FetchContent`, `ExternalProject`, `CPM`) — shipped in v0.1
- [ ] **Go modules** — `go.mod` / `go.sum`
- [ ] **Cargo (Rust)** — `Cargo.toml` / `Cargo.lock`
- [ ] **Maven (Java)** — `pom.xml`
- [ ] **Gradle** — `build.gradle` / `build.gradle.kts`
- [ ] **RubyGems** — `Gemfile` / `Gemfile.lock`
- [ ] **NuGet (.NET)** — `*.csproj` / `packages.config`

### v0.3 — Richer metadata

- [ ] **License resolution via PyPI / npm registry APIs** (opt-in, with `--resolve-licenses`)
- [ ] **Hash population** — `sha256` checksums for downloaded packages where deterministic
- [ ] **CPE generation** alongside PURLs for NVD lookups
- [ ] **Supplier inference** from registry metadata

### v0.4 — Integration & output formats

- [x] **CycloneDX 1.6 output** — shipped in v0.1
- [x] **Dependency-Track upload** — shipped in v0.1
- [ ] **SPDX tag-value (.spdx) format** output
- [ ] **GitHub Actions / GitLab CI official action** — drop-in SBOM generation step
- [ ] **Pre-commit hook** support

### v0.5 — Analysis

- [ ] **Vulnerability overlay** — cross-reference packages against OSV and NVD
- [ ] **License policy enforcement** — fail the scan if disallowed licenses are detected
- [ ] **Diff mode** — compare two SBOMs and report added/removed/changed components
- [ ] **SBOM merging** — combine multiple SBOMs from sub-projects into one document

### Long-term

- [ ] **Plugin system** — third-party scanners installable as Python packages
- [ ] **Language server protocol (LSP) integration** — inline SBOM hints in editors
- [ ] **Firmware / container layer scanning** — deeper unblob-style extraction for binary artefacts

---

## Contributing

Contributions are welcome. To add support for a new package manager:

1. Fork the repository and create a feature branch.
2. Add a scanner in `src/unravel_sbom/scanners/`.
3. Add fixture files under `tests/fixtures/<ecosystem>/`.
4. Write tests covering the happy path, edge cases, and malformed input.
5. Open a pull request — CI must stay green.

Please file issues for false positives, missing fields, or ecosystems you'd like to see supported.

---

## License

MIT © 2024 Daniel Bitzer — see [LICENSE](LICENSE) for details.

SPDX specification © Linux Foundation. Used under [CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).

CycloneDX specification © OWASP Foundation. Used under [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0).

unblob is developed by [ONEKEY](https://onekey.com) and licensed under MIT.
