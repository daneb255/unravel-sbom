# Quick Start

## Basic scan

```bash
# Scan current directory, write SPDX 2.3 JSON (default)
unravel-sbom scan .

# Scan a specific project
unravel-sbom scan ~/projects/my-app
```

## Choose output format

```bash
# CycloneDX 1.6 JSON
unravel-sbom scan . -f cyclonedx

# Write both SPDX and CycloneDX in one pass
unravel-sbom scan . -f both
```

## Custom output path

```bash
unravel-sbom scan . -f cyclonedx -o build/sbom.cdx.json
```

## Scan and upload to Dependency-Track

```bash
unravel-sbom scan . -f cyclonedx \
  --dtrack-url https://dtrack.example.com \
  --dtrack-key $DTRACK_API_KEY \
  --dtrack-project myapp \
  --dtrack-version 1.4.2
```

## Upload an existing BOM

```bash
unravel-sbom upload myapp.cdx.json \
  --dtrack-url https://dtrack.example.com \
  --dtrack-key $DTRACK_API_KEY
```

## Example terminal output

```text
Scanning /home/user/projects/my-app …
    42 files  package-lock.json
  Found 148 package entries in 0.3s.
  CycloneDX 1.6 → my-app.cdx.json  (132 components)
  Dependency-Track ✓  token=3a9f1c2d-...  (https://dtrack.example.com)
```

!!! tip "Environment variables"
    Set `DTRACK_URL` and `DTRACK_API_KEY` in your environment to avoid repeating them on every command.
