# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
