# Dependency-Track Integration

[Dependency-Track](https://github.com/DependencyTrack/dependency-track) is an open-source SBOM analysis platform that continuously tracks vulnerabilities, licence risk, and component age across your portfolio. `unravel-sbom` uploads CycloneDX BOMs directly via the documented [CI/CD API endpoint](https://docs.dependencytrack.org/usage/cicd/).

## How the upload works

1. The BOM is JSON-encoded and Base64-wrapped as required by `PUT /api/v1/bom`.
2. Authentication uses the `X-Api-Key` header — generate a key under **Administration → Access Management → Teams**.
3. Dependency-Track returns an async processing token. With `--dtrack-wait`, `unravel-sbom` polls every 5 seconds until analysis completes (up to 5 minutes).
4. If the project does not exist and `--dtrack-autocreate` is on (the default), Dependency-Track creates it automatically.

---

## Scan and upload in one step

```bash
unravel-sbom scan ./my-app \
  --dtrack-url https://dtrack.example.com \
  --dtrack-key $DTRACK_API_KEY \
  --dtrack-project "my-app" \
  --dtrack-version "2.1.0" \
  --dtrack-wait
```

The upload always sends a CycloneDX 1.6 BOM regardless of `--format`. Combine with `--format both` to also write a local SPDX file:

```bash
unravel-sbom scan ./my-app \
  -f both \
  --dtrack-url https://dtrack.example.com \
  --dtrack-key $DTRACK_API_KEY \
  --dtrack-project "my-app" --dtrack-version "2.1.0"
```

---

## Upload an existing BOM

```bash
unravel-sbom upload my-app.cdx.json \
  --dtrack-url https://dtrack.example.com \
  --dtrack-key $DTRACK_API_KEY \
  --dtrack-project "my-app" \
  --dtrack-version "2.1.0"
```

---

## Target a project by UUID

```bash
unravel-sbom scan ./my-app \
  --dtrack-url https://dtrack.example.com \
  --dtrack-key $DTRACK_API_KEY \
  --dtrack-uuid "f90934f5-cb88-47ce-81cb-db06fc67d4b4"
```

---

## Project lookup

```bash
unravel-sbom dtrack lookup "my-app" "2.1.0" \
  --url https://dtrack.example.com \
  --key $DTRACK_API_KEY
```

Output:

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

---

## CI/CD pipeline examples

=== "GitHub Actions"

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

=== "GitLab CI"

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
