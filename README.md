# unravel-sbom: Multi-Ecosystem SBOM Generator (SPDX 3.0.1 & CycloneDX 1.6)

**Fast, accurate, standards-compliant Software Bill of Materials (SBOM) generator engineered for EU Cyber Resilience Act (CRA) compliance under BSI TR-03183-2, CycloneDX 1.6, and OWASP Dependency-Track integration.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://img.shields.io/pypi/v/unravel-sbom.svg)](https://pypi.org/project/unravel-sbom/)
[![SPDX 3.0.1](https://img.shields.io/badge/SPDX-3.0.1%20JSON--LD-green.svg)](https://spdx.github.io/spdx-spec/v3.0.1/)
[![BSI TR-03183-2](https://img.shields.io/badge/BSI%20TR--03183--2-CRA%20Ready-blue.svg)](https://www.bsi.bund.de/)
[![CycloneDX 1.6](https://img.shields.io/badge/CycloneDX-1.6-orange.svg)](https://cyclonedx.org/docs/1.6/)
[![Dependency-Track](https://img.shields.io/badge/Dependency--Track-ready-blue.svg)](https://dependencytrack.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED.svg)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`unravel-sbom` is an open-source Python CLI tool that recursively scans multi-ecosystem development projects and produces valid SBOMs in **[SPDX 3.0.1](https://spdx.github.io/spdx-spec/v3.0.1/)** (BSI TR-03183-2 conformant JSON-LD) and **[CycloneDX 1.6](https://cyclonedx.org/docs/1.6/)** JSON format. It covers **npm**, **PyPI**, **Conan**, **CMake**, **ROS/ROS2**, and **Makefile**-based C/C++ projects — and pushes results directly to **[Dependency-Track](https://dependencytrack.org/)** in a single command.

Whether you need SBOM generation for software supply-chain security compliance (EU CRA, US Executive Order 14028, NTIA), vulnerability management, or license auditing, `unravel-sbom` delivers a complete, machine-readable inventory of every dependency with Package URLs (PURLs), SPDX license identifiers, and resolved dependency graphs.

![unravel-sbom demo](docs/unravel-sbom.gif)

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
  - [SPDX 3.0.1 (BSI TR-03183-2 / CRA Conformance)](#spdx-301-bsi-tr-03183-2--cra-conformance)
  - [CycloneDX 1.6](#cyclonedx-16)
- [Dependency-Track Integration](#dependency-track-integration)
  - [Scan and Upload in One Step](#scan-and-upload-in-one-step)
  - [Upload an Existing BOM](#upload-an-existing-bom)
  - [Project Lookup](#project-lookup)
  - [CI/CD Pipeline Example](#cicd-pipeline-example)
- [Frequently Asked Questions (FAQ)](#frequently-asked-questions-faq)
- [Architecture](#architecture)
- [Running Tests](#running-tests)
- [CI/CD and Publishing](#cicd-and-publishing)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

> ⭐ If `unravel-sbom` helps you, please consider [starring the repo](../../stargazers) to support the project!

---

## Why unravel-sbom?

Supply-chain security is no longer optional. Regulations like the US Executive Order 14028, the EU Cyber Resilience Act, and frameworks such as SLSA and NTIA all require a software bill of materials. Existing SBOM tools are often language-specific, heavyweight, or produce output that fails validation.

`unravel-sbom` was built around three principles:

1. **Correctness first.** Every output field maps directly to the SPDX 3.0.1 (BSI TR-03183-2) and CycloneDX 1.6 specifications. PURLs are generated via the official `packageurl-python` library. Documents are ready for immediate ingestion by Grype, Dependency-Track, FOSSA, and other SBOM-aware tools.
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
- **SPDX 3.0.1 JSON-LD output** — conformant with BSI TR-03183-2 (CRA SBOM requirements for logical components)
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
| **Go modules** | `go.mod`, `go.sum` | Direct/indirect module dependencies, module exclusion, exact hashes in `go.sum` |
| **Cargo / Rust** | `Cargo.toml`, `Cargo.lock` | Parses `[[package]]` trees, dependency graphs, workspace and target-specific dependencies |
| **Maven / Java** | `pom.xml` | Safe XML parsing, XML namespace stripping, property interpolation (`${property}`), `groupId:artifactId` coordinates |
| **Gradle / Kotlin** | `build.gradle`, `build.gradle.kts`, `gradle.lockfile` | Groovy & Kotlin DSL string and map notation, exact locked versions from `gradle.lockfile` |
| **RubyGems / Ruby** | `Gemfile`, `Gemfile.lock` | Complete `specs` hierarchy, transitive dependency resolution, and version constraints |
| **NuGet / .NET** | `*.csproj`, `*.fsproj`, `*.vbproj`, `packages.config`, `packages.lock.json` | PackageReference, PackageVersion, packages.config, and packages.lock.json dependency trees |
| **Conan / C++** | `conanfile.txt`, `conanfile.py` | AST-based parsing of `.py` files; resolves `requires`, `build_requires`, and `self.requires()` calls |
| **CMake / C++** | `CMakeLists.txt` | Extracts `find_package()`, `FetchContent_Declare()`, `ExternalProject_Add()`, `CPM_AddPackage()`; normalises `v`-prefixed tags, `tags/v…`, and dash-separated version tags; skips CMake built-ins |
| **ROS / ROS2** | `package.xml`, `CMakeLists.txt` | Parses REP-149 `package.xml` for all dep tags (`<depend>`, `<build_depend>`, `<exec_depend>`, `<test_depend>`, etc.) with version constraints; expands CMake `${VAR}` lists in `ament_auto_find_build_dependencies()` |
| **Makefile / C** | `Makefile`, `Makefile.am`, `Makefile.in`, `Makefile.yocto` | Extracts `-l` flags from `LDFLAGS`/`LDLIBS`, `pkg-config` module names, and `git clone` URLs with branch-as-version (Yocto/fetch-style projects) |

---

## Installation

**From source (recommended during development):**

```bash
git clone https://github.com/daneb255/unravel-sbom.git
cd unravel-sbom
pip install -e .
```

**Using Docker:**

```bash
# Build the Docker image
docker build -t unravel-sbom .

# Scan current directory and generate an SPDX 3.0.1 SBOM
docker run --rm -v "$(pwd):/scan" unravel-sbom scan . --creator-email "dev@example.com"
```

**Requirements:**

- Python 3.10 or later
- `click >= 8.1`
- `defusedxml >= 0.7`
- `toml >= 0.10`
- `packageurl-python >= 0.16`
- `tomli >= 2.0` (Python < 3.11 only)

---

## Quick Start

```bash
# Scan and write SPDX 3.0.1 JSON-LD (default)
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
  --creator-email EMAIL           Email identifying the SBOM creator (BSI TR-03183-2)  [$UNRAVEL_CREATOR_EMAIL]
  --creator-url URL               URL identifying the SBOM creator  [$UNRAVEL_CREATOR_URL]
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

### SPDX 3.0.1 (BSI TR-03183-2 / CRA Conformance)

The German Federal Office for Information Security (**BSI**) published Technical Guideline **TR-03183-2**, which specifies requirements for Software Bills of Materials (SBOMs) under the European **Cyber Resilience Act (CRA)**.

BSI TR-03183-2 mandates the use of **SPDX ≥ 3.0.1** (or CycloneDX ≥ 1.6) and defines strict baseline requirements for document-level and component-level metadata.

#### Logical Components vs. Fully Described Components (§3.2.2)

`unravel-sbom` parses source-code manifests and dependency lockfiles (such as `package-lock.json`, `poetry.lock`, `requirements.txt`, CMake, Conan, and Makefiles) directly from development trees without requiring deployed binary artefacts.

Consequently, every package is modeled as a **BSI Logical Component** (§3.2.2):

- **Included Mandatory Fields:** Creator identity (`originatedBy`), component name (`name`), exact version (`software_packageVersion`), dependency relationships (`dependsOn`), distribution licenses (`hasConcludedLicense`), declared licenses (`hasDeclaredLicense`), and unique Package URLs (`packageUrl`).
- **Deliberately Excluded Physical Properties:** File hashes (`SHA-512`), artifact filenames, and executable/archive attributes only apply to "fully described components" (§3.2.1) and are omitted honestly rather than fabricated.
- **Prohibition of Vulnerability Data:** In accordance with BSI TR-03183-2, SBOMs generated by `unravel-sbom` strictly contain inventory and relationship data, and never include vulnerability or CVE findings (which belong in separate VEX documents).

Document graph structure:

```json
{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#SPDXRef-DOCUMENT",
      "name": "SBOM-my-app",
      "dataLicense": "https://spdx.org/licenses/CC0-1.0",
      "creationInfo": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creationinfo",
      "rootElement": [
        "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#SPDXRef-npm-express-4-18-2"
      ]
    },
    {
      "type": "CreationInfo",
      "spdxId": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creationinfo",
      "specVersion": "3.0.1",
      "created": "2026-08-25T12:00:00Z",
      "createdBy": [
        "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creator-agent"
      ]
    },
    {
      "type": "Person",
      "spdxId": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creator-agent",
      "creationInfo": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creationinfo",
      "name": "dev",
      "externalIdentifiers": [
        {
          "type": "ExternalIdentifier",
          "externalIdentifierType": "email",
          "identifier": "dev@example.com"
        }
      ]
    },
    {
      "type": "software_Package",
      "spdxId": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#SPDXRef-npm-express-4-18-2",
      "creationInfo": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creationinfo",
      "name": "express",
      "software_packageVersion": "4.18.2",
      "originatedBy": [
        "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creator-agent"
      ],
      "externalIdentifiers": [
        {
          "type": "ExternalIdentifier",
          "externalIdentifierType": "packageUrl",
          "identifier": "pkg:npm/express@4.18.2"
        }
      ]
    },
    {
      "type": "simpleLicensing_LicenseExpression",
      "spdxId": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#license-SPDXRef-npm-express-4-18-2",
      "creationInfo": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creationinfo",
      "simpleLicensing_licenseExpression": "MIT"
    },
    {
      "type": "Relationship",
      "spdxId": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#rel-concluded-SPDXRef-npm-express-4-18-2",
      "creationInfo": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creationinfo",
      "from": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#SPDXRef-npm-express-4-18-2",
      "relationshipType": "hasConcludedLicense",
      "to": [
        "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#license-SPDXRef-npm-express-4-18-2"
      ],
      "completeness": "complete"
    },
    {
      "type": "Relationship",
      "spdxId": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#rel-depends-SPDXRef-npm-express-4-18-2",
      "creationInfo": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creationinfo",
      "from": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#SPDXRef-npm-express-4-18-2",
      "relationshipType": "dependsOn",
      "to": [
        "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#SPDXRef-npm-lodash-4-17-21"
      ],
      "completeness": "noAssertion"
    }
  ]
}
```

| Mandatory BSI TR-03183-2 Field | SPDX 3.0.1 Element / Property | Notes |
| --- | --- | --- |
| **SBOM Creator** | `CreationInfo.createdBy` → `Person` / `Organization` | Provided via `--creator-email` or `--creator-url` |
| **Component Creator** | `software_Package.originatedBy` | References creator agent |
| **Component Name** | `software_Package.name` | Normalized package name |
| **Component Version** | `software_Package.software_packageVersion` | Falls back to manifest file `st_mtime` ISO 8601 string or `NOASSERTION` |
| **Unique Identifiers** | `externalIdentifiers` (`packageUrl`) | Standard PURL string (`pkg:pypi/...`, `pkg:npm/...`) |
| **Distribution Licences** | `Relationship` (`hasConcludedLicense`) | Concluded license expression |
| **Original Licences** | `Relationship` (`hasDeclaredLicense`) | Declared license expression |
| **Dependencies** | `Relationship` (`dependsOn`) | Direct package dependencies from lockfiles |

---

## CycloneDX 1.6

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

## Frequently Asked Questions (FAQ)

<details>
<summary><strong>What is an SBOM and why is it mandatory under the EU Cyber Resilience Act (CRA)?</strong></summary>

A Software Bill of Materials (SBOM) is a comprehensive, machine-readable inventory of software components, dependencies, and hierarchical relationships making up a software product. Under the EU Cyber Resilience Act (CRA) and US Executive Order 14028, maintaining an up-to-date SBOM is a mandatory compliance requirement for placing connected digital products and software on the market.
</details>

<details>
<summary><strong>What is BSI TR-03183-2 and why is SPDX 3.0.1 required?</strong></summary>

The German Federal Office for Information Security (**BSI**) published Technical Guideline **TR-03183-2** as the foundational standard for CRA-compliant SBOM generation. It explicitly requires **SPDX ≥ 3.0.1** (or CycloneDX ≥ 1.6), enforcing mandatory creator identity, package URLs (PURLs), license expressions, and dependency relationship trees.
</details>

<details>
<summary><strong>How does unravel-sbom distinguish between logical and physical components?</strong></summary>

In BSI TR-03183-2 (§3.2.2), packages detected from source code manifests and lockfiles are classified as **logical components**. They accurately represent declared dependency trees without requiring compiled binary files. `unravel-sbom` captures all required logical metadata (creator, name, version, PURL, declared/concluded licenses, `dependsOn` edges) while omitting binary-specific attributes (such as SHA-512 hashes and executable flags) to maintain strict compliance.
</details>

<details>
<summary><strong>Why are CVE vulnerabilities omitted from generated SBOMs?</strong></summary>

BSI TR-03183-2 explicitly specifies that SBOMs must not embed point-in-time vulnerability data. Software vulnerability statuses change continuously; storing CVEs statically in an SBOM causes immediate obsolescence. Vulnerability management is handled dynamically by platforms like **Dependency-Track**, **Grype**, or through companion **VEX** (Vulnerability Exploitability eXchange) feeds.
</details>

<details>
<summary><strong>Can unravel-sbom scan multi-language and embedded monorepos?</strong></summary>

Yes. `unravel-sbom` was designed specifically for multi-ecosystem repositories, firmware trees, and robotics workspaces. A single command recursively parses npm, Python (Pip/Poetry/Hatch), Conan, CMake (`find_package`, `FetchContent`, `CPM`), ROS/ROS2 (`package.xml`), and C/C++ Makefiles.
</details>

<details>
<summary><strong>How does unravel-sbom integrate with Dependency-Track and CI/CD?</strong></summary>

`unravel-sbom` includes a native client for OWASP Dependency-Track. With a single CLI invocation (or within GitHub Actions / GitLab CI), it scans the codebase, generates a CycloneDX 1.6 BOM, uploads it via `PUT /api/v1/bom`, and optionally polls the server until vulnerability analysis is complete.
</details>

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
│   ├── golang.py         ← GoModScanner, GoSumScanner
│   ├── cargo.py          ← CargoTomlScanner, CargoLockScanner
│   ├── maven.py          ← PomXmlScanner
│   ├── gradle.py         ← GradleScanner
│   ├── rubygems.py       ← GemfileScanner, GemfileLockScanner
│   ├── nuget.py          ← NuGetScanner (.csproj, packages.config, packages.lock.json)
│   ├── conan.py          ← ConanfileTxtScanner, ConanfilePyScanner (AST)
│   ├── cmake.py          ← CMakeScanner (find_package, FetchContent, ExternalProject, CPM)
│   ├── ros.py            ← PackageXmlScanner (REP-149 package.xml, ament variable expansion)
│   └── makefile.py       ← MakefileScanner (-l flags, pkg-config, git clone / Yocto)
├── reporters/
│   ├── spdx.py           ← SPDX 3.0.1 JSON-LD document builder + deduplication
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
140 passed in 0.35s
```

Test coverage:

| Area | Tests |
| --- | --- |
| npm scanner (package.json, package-lock.json v1–v3) | 6 |
| PyPI scanner (requirements.txt, pyproject.toml, poetry.lock) | 9 |
| Go modules scanner (go.mod, go.sum) | 5 |
| Cargo scanner (Cargo.toml, Cargo.lock) | 5 |
| Maven scanner (pom.xml, property expansion) | 3 |
| Gradle scanner (build.gradle, build.gradle.kts, gradle.lockfile) | 2 |
| RubyGems scanner (Gemfile, Gemfile.lock) | 2 |
| NuGet scanner (.csproj, packages.config, packages.lock.json) | 3 |
| Conan scanner (conanfile.txt, conanfile.py AST) | 6 |
| CMake scanner (find_package, FetchContent, ExternalProject, CPM) | 26 |
| ROS/ROS2 scanner (package.xml, ament variable expansion) | 20 |
| Makefile scanner (LDFLAGS, LDLIBS, pkg-config, git clone) | 6 |
| Walker (recursion, skip-dirs, error isolation) | 3 |
| SPDX 3.0.1 reporter (fields, PURLs, deduplication, relationships) | 11 |
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
- [x] **Go modules** — `go.mod` / `go.sum`
- [x] **Cargo (Rust)** — `Cargo.toml` / `Cargo.lock`
- [x] **Maven (Java)** — `pom.xml`
- [x] **Gradle** — `build.gradle` / `build.gradle.kts`
- [x] **RubyGems** — `Gemfile` / `Gemfile.lock`
- [x] **NuGet (.NET)** — `*.csproj` / `packages.config` / `packages.lock.json`

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
