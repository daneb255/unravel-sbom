# Output Formats

`unravel-sbom` writes **SPDX 2.3** and/or **CycloneDX 1.6** JSON. Both formats are directly consumable by Dependency-Track, Grype, FOSSA, sw360, and Syft.

---

## SPDX 2.3

Every package entry includes:

```json
{
  "SPDXID": "SPDXRef-npm-express-4-18-2",
  "name": "express",
  "versionInfo": "4.18.2",
  "downloadLocation": "NOASSERTION",
  "filesAnalyzed": false,
  "licenseConcluded": "MIT",
  "licenseDeclared": "MIT",
  "copyrightText": "NOASSERTION",
  "supplier": "NOASSERTION",
  "externalRefs": [
    {
      "referenceCategory": "PACKAGE-MANAGER",
      "referenceType": "purl",
      "referenceLocator": "pkg:npm/express@4.18.2"
    }
  ]
}
```

### Document-level fields

| Field | Value |
| --- | --- |
| `spdxVersion` | `SPDX-2.3` |
| `dataLicense` | `CC0-1.0` |
| `creationInfo.creators` | `Tool: unravel-sbom-0.1.0` |
| `relationships` | `DOCUMENT DESCRIBES <package>` for every entry |

---

## CycloneDX 1.6

Every component includes:

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

### Document-level fields

| Field | Value |
| --- | --- |
| `bomFormat` | `CycloneDX` |
| `specVersion` | `1.6` |
| `serialNumber` | `urn:uuid:<uuid4>` per RFC 4122 |
| `metadata.tools` | `unravel-sbom 0.1.0` |

Compound license expressions (e.g. `MIT OR Apache-2.0`) are written as `{ "expression": "MIT OR Apache-2.0" }` per the CycloneDX spec. Components with no known license omit the `licenses` field entirely.

---

## Compatible tools

| Tool | Use case |
| --- | --- |
| **[Dependency-Track](https://dependencytrack.org/)** | Continuous component analysis, vulnerability tracking |
| **[Grype](https://github.com/anchore/grype)** | Vulnerability scanning against the SBOM |
| **[FOSSA](https://fossa.com/)** | License compliance |
| **[sw360](https://www.eclipse.org/sw360/)** | Component lifecycle management |
| **[Syft](https://github.com/anchore/syft)** | Cross-format SBOM tooling |
