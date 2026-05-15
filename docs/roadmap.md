# Roadmap

## v0.2 — Ecosystem coverage

- [x] **CMake** — shipped in v0.1
- [ ] **Go modules** — `go.mod` / `go.sum`
- [ ] **Cargo (Rust)** — `Cargo.toml` / `Cargo.lock`
- [ ] **Maven (Java)** — `pom.xml`
- [ ] **Gradle** — `build.gradle` / `build.gradle.kts`
- [ ] **RubyGems** — `Gemfile` / `Gemfile.lock`
- [ ] **NuGet (.NET)** — `*.csproj` / `packages.config`

## v0.3 — Richer metadata

- [ ] **License resolution via PyPI / npm registry APIs** (opt-in, `--resolve-licenses`)
- [ ] **Hash population** — `sha256` checksums for downloaded packages where deterministic
- [ ] **CPE generation** alongside PURLs for NVD lookups
- [ ] **Supplier inference** from registry metadata

## v0.4 — Integration & output formats

- [x] **CycloneDX 1.6 output** — shipped in v0.1
- [x] **Dependency-Track upload** — shipped in v0.1
- [ ] **SPDX tag-value (`.spdx`) format** output
- [ ] **GitHub Actions / GitLab CI official action**
- [ ] **Pre-commit hook** support

## v0.5 — Analysis

- [ ] **Vulnerability overlay** — cross-reference packages against OSV and NVD
- [ ] **License policy enforcement** — fail the scan if disallowed licenses are detected
- [ ] **Diff mode** — compare two SBOMs and report added/removed/changed components
- [ ] **SBOM merging** — combine multiple SBOMs from sub-projects into one document

## Long-term

- [ ] **Plugin system** — third-party scanners installable as Python packages
- [ ] **Language server protocol (LSP) integration** — inline SBOM hints in editors
- [ ] **Firmware / container layer scanning** — deeper unblob-style extraction
