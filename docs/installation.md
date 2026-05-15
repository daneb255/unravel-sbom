# Installation

## Requirements

- Python **3.10** or later
- No Docker, no extra runtimes

## From PyPI

```bash
pip install unravel-sbom
```

## From Source

```bash
git clone https://github.com/daneb255/unravel-sbom.git
cd unravel-sbom
pip install -e .
```

## Development Install

Includes linting, type-checking, and testing tools:

```bash
pip install -e ".[dev]"
```

## Verify

```bash
unravel-sbom --version
```

## Dependencies

| Package | Purpose |
| --- | --- |
| `click >= 8.1` | CLI framework |
| `packageurl-python >= 0.16` | PURL generation |
| `defusedxml >= 0.7` | Safe XML parsing (XXE prevention) |
| `toml >= 0.10` | TOML parsing |
| `tomli >= 2.0` | TOML parsing (Python < 3.11 only) |
