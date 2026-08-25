# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-08-25

### Added

- **SPDX 3.0.1 (JSON-LD)** output conformant with BSI Technical Guideline TR-03183-2 (Cyber Resilience Act SBOM requirements for logical components).
- **6 New Package Manager Ecosystems**:
  - **Go modules** (`go.mod`, `go.sum`) with `pkg:golang` PURLs.
  - **Cargo / Rust** (`Cargo.toml`, `Cargo.lock`) with `pkg:cargo` PURLs and `depends_on` graph extraction.
  - **Maven / Java** (`pom.xml`) with safe XML parsing, XML namespace stripping, and property interpolation.
  - **Gradle / Kotlin** (`build.gradle`, `build.gradle.kts`, `gradle.lockfile`) with Groovy & Kotlin DSL parsing.
  - **RubyGems / Ruby** (`Gemfile`, `Gemfile.lock`) with `specs` dependency tree resolution.
  - **NuGet / .NET** (`*.csproj`, `*.fsproj`, `*.vbproj`, `packages.config`, `packages.lock.json`).
- `--creator-email` and `--creator-url` CLI options (and `UNRAVEL_CREATOR_EMAIL`, `UNRAVEL_CREATOR_URL` environment variables) to configure creator identity.
- Multi-stage `Dockerfile` and `.dockerignore` for running `unravel-sbom` in containers.
- Dependency graph parsing: `depends_on` relationships extracted in `PoetryLockScanner`, `PackageLockScanner`, `CargoLockScanner`, `GemfileLockScanner`, and `NuGetScanner` to build `dependsOn` graph edges in SPDX 3.0.1.
- Comprehensive FAQ section and search engine optimizations in `README.md`.

### Changed

- Migrated default SPDX output format from SPDX 2.3 JSON to SPDX 3.0.1 JSON-LD.
- Upgraded library dependencies (`click==8.4.2`, `defusedxml==0.7.1`, `toml==0.10.2`, `tomli==2.4.1`, `packageurl-python==0.17.6`).
- Updated version metadata to `0.2.0` across the project.

## [0.1.0] - 2026-05-15

### Added

- `scan` command: walk a project directory and generate an SBOM in SPDX v2.3 or CycloneDX 1.6 format
- `upload` command: upload an existing SBOM file to a Dependency-Track instance
- `dtrack` command group with `lookup` subcommand for querying Dependency-Track project metadata
- Ecosystem scanners: Python/PyPI, npm, CMake, Conan, Makefile, ROS
- SPDX v2.3 reporter (JSON output)
- CycloneDX 1.6 reporter (JSON output)
- Dependency-Track upload integration
- Progress indicator and verbose/debug logging via `--verbose` flag
- MkDocs Material documentation site with GitHub Pages deployment
- CI/CD pipeline (lint, type-check, tests, security scan, publish to PyPI)
