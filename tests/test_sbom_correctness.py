"""Regression tests: SBOMs must not contain phantom or ambiguous components."""

from __future__ import annotations

import json
from pathlib import Path

from unravel_sbom.models import Ecosystem, Package, ScanResult
from unravel_sbom.reporters import cyclonedx, spdx
from unravel_sbom.scanners import ALL_SCANNERS
from unravel_sbom.scanners.pypi import _extract_version
from unravel_sbom.walker import walk


def _project(tmp_path: Path) -> Path:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "^4.17.0", "app": "workspace:*"}})
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"": {}, "node_modules/lodash": {"version": "4.17.21"}},
            }
        )
    )
    dep = tmp_path / "node_modules" / "evil"
    dep.mkdir(parents=True)
    (dep / "package.json").write_text(json.dumps({"dependencies": {"x": "1.0.0"}}))
    return tmp_path


def test_only_lockfile_versions_and_no_node_modules(tmp_path):
    result = walk(_project(tmp_path), ALL_SCANNERS)
    assert [(p.name, p.version) for p in result.packages] == [("lodash", "4.17.21")]


def test_pypi_ranges_are_unknown():
    assert _extract_version("==1.2.3") == "1.2.3"
    assert _extract_version(">=1.0,<2") == "unknown"
    assert _extract_version("~=1.4") == "unknown"


def test_bom_refs_unique_for_colliding_names():
    a = Package("@babel/core", "7.0.0", Ecosystem.NPM)
    b = Package("babel-core", "7.0.0", Ecosystem.NPM)
    assert a.spdx_id != b.spdx_id


def test_cyclonedx_dependencies_section(tmp_path):
    pkgs = [
        Package("a", "1.0.0", Ecosystem.NPM, depends_on=["b", "multi"]),
        Package("b", "1.0.0", Ecosystem.NPM),
        Package("multi", "1.0.0", Ecosystem.NPM),
        Package("multi", "2.0.0", Ecosystem.NPM),
    ]
    doc = cyclonedx.generate(ScanResult(packages=pkgs), scan_root=tmp_path)
    deps = {d["ref"]: d["dependsOn"] for d in doc["dependencies"]}
    assert deps[pkgs[0].spdx_id] == [pkgs[1].spdx_id]  # ambiguous "multi" skipped


def test_spdx_has_no_fabricated_originator(tmp_path):
    doc = spdx.generate(
        ScanResult(packages=[Package("a", "1.0.0", Ecosystem.NPM)]), scan_root=tmp_path
    )
    pkg = next(n for n in doc["@graph"] if n.get("type") == "software_Package")
    assert "originatedBy" not in pkg


def test_maven_dependency_management_not_a_dependency(tmp_path):
    (tmp_path / "pom.xml").write_text(
        "<project><dependencyManagement><dependencies><dependency>"
        "<groupId>g</groupId><artifactId>managed</artifactId><version>1</version>"
        "</dependency></dependencies></dependencyManagement>"
        "<dependencies><dependency><groupId>g</groupId><artifactId>real</artifactId>"
        "<version>2</version></dependency></dependencies></project>"
    )
    result = walk(tmp_path, ALL_SCANNERS)
    assert [p.name for p in result.packages] == ["g:real"]


def test_lockfile_integrity_becomes_a_hash(tmp_path):
    import base64
    import hashlib

    digest = hashlib.sha512(b"artifact").digest()
    integrity = "sha512-" + base64.b64encode(digest).decode()
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {},
                    "node_modules/a": {"version": "1.0.0", "integrity": integrity},
                    "node_modules/b": {
                        "version": "2.0.0",
                        "integrity": "sha1-AAAA sha512-%%%",
                    },  # weak and invalid
                    "node_modules/c": {"version": "3.0.0"},
                },
            }
        )
    )
    result = walk(tmp_path, ALL_SCANNERS)
    by_name = {p.name: p for p in result.packages}
    assert by_name["a"].hashes == {"SHA-512": digest.hex()}
    assert by_name["b"].hashes == {} and by_name["c"].hashes == {}

    comps = {
        c["name"]: c
        for c in cyclonedx.generate(result, scan_root=tmp_path)["components"]
    }
    assert comps["a"]["hashes"] == [{"alg": "SHA-512", "content": digest.hex()}]
    assert "hashes" not in comps["b"] and "hashes" not in comps["c"]

    doc = spdx.generate(result, scan_root=tmp_path)
    pkg = next(
        n
        for n in doc["@graph"]
        if n.get("type") == "software_Package" and n["name"] == "a"
    )
    assert pkg["verifiedUsing"] == [
        {"type": "Hash", "algorithm": "sha512", "hashValue": digest.hex()}
    ]
