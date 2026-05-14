# Contributing to unravel-sbom

Thank you for your interest in contributing! This document covers how to set up the project, the standards every PR must meet, and the process for getting changes merged.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Quality Standards](#code-quality-standards)
- [Running the Test Suite](#running-the-test-suite)
- [Adding a New Scanner](#adding-a-new-scanner)
- [Pull Request Process](#pull-request-process)
- [Commit Message Style](#commit-message-style)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Code of Conduct](#code-of-conduct)

---

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/unravel-sbom.git
   cd unravel-sbom
   ```
3. Create a **feature branch**:
   ```bash
   git checkout -b feat/my-new-scanner
   ```

---

## Development Setup

**Requirements:** Python 3.10 or later, Git.

```bash
# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install the package in editable mode with all dev dependencies
pip install -e ".[dev]"
```

---

## Code Quality Standards

Every PR must pass all of the following checks — the same checks run in CI:

```bash
# Lint (must be clean — zero errors)
ruff check src tests

# Formatting (auto-fix, then verify)
ruff format src tests
ruff format --check src tests

# Type checking
mypy src --ignore-missing-imports

# Security static analysis
bandit -r src/

# Dependency vulnerability scan
safety check
```

Run the full local CI check in one go:

```bash
ruff check src tests && \
ruff format --check src tests && \
mypy src --ignore-missing-imports && \
pytest tests/ -v --cov=src --cov-report=term-missing && \
coverage report --fail-under=80
```

CI enforces **80 % test coverage** as a hard minimum.

---

## Running the Test Suite

```bash
pytest tests/ -v
```

To run only a specific file or test class:

```bash
pytest tests/test_cmake_scanner.py -v
pytest tests/test_scanners.py::TestMakefileScanner -v
```

---

## Adding a New Scanner

The architecture is designed so that adding a scanner requires changes in exactly three places — no modifications to the walker, reporters, or upload client are needed.

1. **Create** `src/unravel_sbom/scanners/<ecosystem>.py` and subclass `BaseScanner`:

   ```python
   from unravel_sbom.scanners.base import BaseScanner
   from unravel_sbom.models import Ecosystem, Package, ScanResult
   from pathlib import Path

   class MyEcosystemScanner(BaseScanner):
       MANIFEST_NAMES = ("my-manifest.lock",)

       def scan(self, path: Path) -> ScanResult:
           result = ScanResult()
           # ... parse path and populate result.packages
           return result
   ```

2. **Register** it in `src/unravel_sbom/scanners/__init__.py`:

   ```python
   from unravel_sbom.scanners.myecosystem import MyEcosystemScanner

   ALL_SCANNERS = [
       ...,
       MyEcosystemScanner(),
   ]
   ```

3. **Test** it:
   - Add a representative fixture file under `tests/fixtures/<ecosystem>/`
   - Add a test class in `tests/test_scanners.py` (or a dedicated file for complex scanners)
   - Cover the happy path, version extraction, deduplication, and malformed-input isolation

---

## Pull Request Process

1. Ensure all checks pass locally before opening a PR.
2. Open the PR against the `main` branch.
3. Fill in the PR description: what changed and why.
4. A maintainer will review within a few days. CI must be green before merging.
5. Squash or rebase to keep history clean — no merge commits.

---

## Commit Message Style

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(scanners): add Go modules scanner
fix(cmake): handle refs/tags/ prefix in GIT_TAG
docs: update README with new ecosystem table row
test(ros): add malformed package.xml isolation test
chore(deps): bump defusedxml from 0.7.1 to 0.8.0
```

---

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.**

Please read [SECURITY.md](SECURITY.md) and report privately to `d@bitzer.dev`.

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating you agree to uphold it.
