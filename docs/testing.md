# Testing & CI

## Running tests locally

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

```
119 passed in 0.21s
```

### With coverage

```bash
pytest tests/ -v --cov=src --cov-report=term-missing
coverage report --fail-under=80
```

### Full local check (identical to CI)

```bash
ruff check src tests
ruff format --check src tests
mypy src --ignore-missing-imports
pytest tests/ -v --cov=src --cov-report=term-missing
coverage report --fail-under=80
```

---

## Test coverage

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

## GitHub Actions workflows

| File | Triggers | Purpose |
| --- | --- | --- |
| `ci.yml` | push / PR → `main` | Lint, type-check, test across Python 3.10–3.12, enforce 80% coverage |
| `security.yml` | push / PR / weekly cron | Bandit static analysis + Safety dependency scan |
| `publish.yml` | GitHub Release published | Full 5-stage publish pipeline |

### Publish pipeline

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

This project uses [OIDC trusted publishing](https://docs.pypi.org/trusted-publishers/) — no `PYPI_API_TOKEN` secret needed.

1. Go to **[pypi.org/manage/account/publishing](https://pypi.org/manage/account/publishing/)** (and the same on [test.pypi.org](https://test.pypi.org/manage/account/publishing/)).
2. Add a trusted publisher:
    - **PyPI project name:** `unravel-sbom`
    - **Owner:** `<your-github-username>`
    - **Repository:** `unravel-sbom`
    - **Workflow filename:** `publish.yml`
    - **Environment name:** `pypi` (or `testpypi`)
3. Create matching **Environments** in the GitHub repo settings (`pypi`, `testpypi`).
4. Publish a GitHub Release — the workflow fires automatically.
