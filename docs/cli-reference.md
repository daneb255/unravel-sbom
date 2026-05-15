# CLI Reference

`unravel-sbom` uses a sub-command structure:

```
unravel-sbom scan     — scan a directory and write an SBOM
unravel-sbom upload   — upload an existing CycloneDX BOM to Dependency-Track
unravel-sbom dtrack   — Dependency-Track project management utilities
```

---

## `unravel-sbom scan`

```
Usage: unravel-sbom scan [OPTIONS] SOURCE
```

Scan **SOURCE** directory and write an SBOM — optionally upload to Dependency-Track.

### Options

| Option | Default | Description |
| --- | --- | --- |
| `-o, --output FILE` | `<dir>.spdx.json` or `<dir>.cdx.json` | Output file path. Ignored when `--format=both`. |
| `-f, --format [spdx\|cyclonedx\|both]` | `spdx` | Output format. |
| `--name TEXT` | `SBOM-<dir>` | Document/BOM name. |
| `--max-depth INTEGER` | unlimited | Maximum directory recursion depth. |
| `--dtrack-url URL` | `$DTRACK_URL` | Dependency-Track base URL. |
| `--dtrack-key KEY` | `$DTRACK_API_KEY` | Dependency-Track API key. |
| `--dtrack-project NAME` | directory name | Project name in Dependency-Track. |
| `--dtrack-version TEXT` | `latest` | Project version string. |
| `--dtrack-uuid UUID` | — | Target project by UUID instead of name+version. |
| `--dtrack-autocreate / --no-dtrack-autocreate` | on | Auto-create the project if it doesn't exist. |
| `--dtrack-wait` | off | Poll until Dependency-Track finishes processing. |
| `--dtrack-timeout SECS` | `30` | HTTP timeout for Dependency-Track requests. |
| `-v, --verbose` | off | Enable debug logging. |
| `-h, --help` | — | Show help and exit. |

---

## `unravel-sbom upload`

```
Usage: unravel-sbom upload [OPTIONS] BOM_FILE
```

Upload an existing CycloneDX **BOM_FILE** to Dependency-Track.

### Required options

- `--dtrack-url URL` (or `$DTRACK_URL`)
- `--dtrack-key KEY` (or `$DTRACK_API_KEY`)

### All options

| Option | Default | Description |
| --- | --- | --- |
| `--dtrack-url URL` | `$DTRACK_URL` | Dependency-Track base URL. **(required)** |
| `--dtrack-key KEY` | `$DTRACK_API_KEY` | API key. **(required)** |
| `--dtrack-project NAME` | BOM filename stem | Project name. |
| `--dtrack-version TEXT` | `latest` | Project version. |
| `--dtrack-uuid UUID` | — | Target project by UUID. |
| `--dtrack-autocreate / --no-dtrack-autocreate` | on | Auto-create project. |
| `--dtrack-wait` | off | Poll until processing is complete. |
| `--dtrack-timeout SECS` | `30` | HTTP timeout. |
| `-v, --verbose` | off | Enable debug logging. |

---

## `unravel-sbom dtrack lookup`

```
Usage: unravel-sbom dtrack lookup [OPTIONS] PROJECT_NAME PROJECT_VERSION
```

Look up a project by name and version and print its metadata as JSON.

### Options

| Option | Description |
| --- | --- |
| `--url URL` | Dependency-Track base URL (`$DTRACK_URL`). **(required)** |
| `--key KEY` | API key (`$DTRACK_API_KEY`). **(required)** |
| `-v, --verbose` | Enable debug logging. |
