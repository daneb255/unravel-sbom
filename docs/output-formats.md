# Output Formats

`unravel-sbom` writes **SPDX 3.0.1** (JSON-LD conformant with BSI TR-03183-2) and/or **CycloneDX 1.6** JSON. Both formats are directly consumable by Dependency-Track, Grype, FOSSA, sw360, and Syft.

---

## SPDX 3.0.1 (BSI TR-03183-2)

`unravel-sbom` produces SPDX 3.0.1 JSON-LD documents modeled strictly according to the **BSI Technical Guideline TR-03183-2** (Cyber Resilience Act SBOM Requirements) profile for **logical components** (§3.2.2).

### Document & Component Structure

```json
{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#SPDXRef-DOCUMENT",
      "name": "SBOM-my-app",
      "dataLicense": "https://spdx.org/licenses/CC0-1.0",
      "creationInfo": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creationinfo",
      "rootElement": [
        "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#SPDXRef-npm-express-4-18-2"
      ]
    },
    {
      "type": "CreationInfo",
      "spdxId": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creationinfo",
      "specVersion": "3.0.1",
      "created": "2026-08-25T12:00:00Z",
      "createdBy": [
        "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creator-agent"
      ]
    },
    {
      "type": "Person",
      "spdxId": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creator-agent",
      "creationInfo": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creationinfo",
      "name": "dev",
      "externalIdentifiers": [
        {
          "type": "ExternalIdentifier",
          "externalIdentifierType": "email",
          "identifier": "dev@example.com"
        }
      ]
    },
    {
      "type": "software_Package",
      "spdxId": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#SPDXRef-npm-express-4-18-2",
      "creationInfo": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creationinfo",
      "name": "express",
      "software_packageVersion": "4.18.2",
      "originatedBy": [
        "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creator-agent"
      ],
      "externalIdentifiers": [
        {
          "type": "ExternalIdentifier",
          "externalIdentifierType": "packageUrl",
          "identifier": "pkg:npm/express@4.18.2"
        }
      ]
    },
    {
      "type": "simpleLicensing_LicenseExpression",
      "spdxId": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#license-SPDXRef-npm-express-4-18-2",
      "creationInfo": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creationinfo",
      "simpleLicensing_licenseExpression": "MIT"
    },
    {
      "type": "Relationship",
      "spdxId": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#rel-concluded-SPDXRef-npm-express-4-18-2",
      "creationInfo": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creationinfo",
      "from": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#SPDXRef-npm-express-4-18-2",
      "relationshipType": "hasConcludedLicense",
      "to": [
        "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#license-SPDXRef-npm-express-4-18-2"
      ],
      "completeness": "complete"
    },
    {
      "type": "Relationship",
      "spdxId": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#rel-depends-SPDXRef-npm-express-4-18-2",
      "creationInfo": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#creationinfo",
      "from": "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#SPDXRef-npm-express-4-18-2",
      "relationshipType": "dependsOn",
      "to": [
        "https://unravel-sbom.local/SBOM-my-app-a1b2c3d4e5f6#SPDXRef-npm-lodash-4-17-21"
      ],
      "completeness": "noAssertion"
    }
  ]
}
```

### BSI Logical Component Conformance (§3.2.2)

| Mandatory Field | SPDX 3.0.1 Element / Property |
| --- | --- |
| Component Creator | `originatedBy` referencing creator `Person`/`Organization` |
| Component Name | `name` on `software_Package` |
| Component Version | `software_packageVersion` (falls back to manifest file mtime or `NOASSERTION`) |
| Unique Identifiers | `externalIdentifiers` with `externalIdentifierType: "packageUrl"` |
| Distribution Licences | `Relationship` with `relationshipType: "hasConcludedLicense"` |
| Original Licences | `Relationship` with `relationshipType: "hasDeclaredLicense"` |
| Dependencies | `Relationship` with `relationshipType: "dependsOn"` |

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
