"""Tests for `unravel-sbom check` with fake scanner binaries and a stub platform server."""

from __future__ import annotations

import json
import stat
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from click.testing import CliRunner

from unravel_sbom import check as chk
from unravel_sbom.cli import cli
from unravel_sbom.upload.cra import CraError, ingest

SARIF_EMPTY = {"version": "2.1.0", "runs": [{"results": []}]}
SARIF_ONE = {"version": "2.1.0", "runs": [{"results": [{"level": "error"}]}]}


def make_tool(bin_dir: Path, name: str, body: str) -> None:
    path = bin_dir / name
    path.write_text(
        f"#!{sys.executable}\nimport sys, json\nargs = sys.argv[1:]\n{body}\n"
    )
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


TRIVY = """
out = args[args.index("--output") + 1]
open(out, "w").write(json.dumps(%s))
"""
OPENGREP = """
if "--help" in args:
    print("  --sarif-output=FILE")
    sys.exit(0)
out = [a for a in args if a.startswith("--sarif-output=")][0].split("=", 1)[1]
open(out, "w").write(json.dumps(%s))
"""
CPPCHECK = "sys.stderr.write(json.dumps(%s))"


@pytest.fixture
def project(tmp_path: Path) -> Path:
    p = tmp_path / "proj"
    p.mkdir()
    (p / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"": {}, "node_modules/left-pad": {"version": "1.3.0"}},
            }
        )
    )
    return p


@pytest.fixture
def bin_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    d = tmp_path / "bin"
    d.mkdir()
    monkeypatch.setenv("PATH", str(d))  # only our fakes, the real tools must not run
    return d


# --- Stub platform ---------------------------------------------------------


class Stub:
    def __init__(self, status: int = 201, ergebnis: str = "ok") -> None:
        self.requests: list[dict] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                n = int(self.headers["Content-Length"])
                body = self.rfile.read(n)
                u = urlparse(self.path)
                outer.requests.append(
                    {
                        "path": u.path,
                        "query": {k: v[0] for k, v in parse_qs(u.query).items()},
                        "auth": self.headers["Authorization"],
                        "ctype": self.headers["Content-Type"],
                        "body": body,
                    }
                )
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                if status == 201:
                    answer = {
                        "ergebnis": ergebnis,
                        "zusammenfassung": "ok-text",
                        "status_aenderungen": [],
                    }
                else:
                    answer = {"detail": "Release '9' gibt es nicht"}
                self.wfile.write(json.dumps(answer).encode())

            def log_message(self, *a: object) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()


@pytest.fixture
def stub():
    s = Stub()
    yield s
    s.close()


# --- Upload client -----------------------------------------------------------


def test_ingest_sends_file_query_and_key(stub: Stub, tmp_path: Path):
    f = tmp_path / "sbom.cdx.json"
    f.write_text('{"a": 1}')
    answer = ingest(
        stub.url,
        "cra_key",
        "sbom",
        "1.0.0",
        f,
        commit="abc",
        pipeline_url="https://ci/1",
    )
    assert answer["ergebnis"] == "ok"
    r = stub.requests[0]
    assert r["path"] == "/api/v1/ci/ingest"
    assert r["query"] == {
        "quelle": "sbom",
        "version": "1.0.0",
        "commit": "abc",
        "url": "https://ci/1",
    }
    assert r["auth"] == "Bearer cra_key"
    assert r["ctype"].startswith("multipart/form-data; boundary=")
    assert (
        b'name="datei"; filename="sbom.cdx.json"' in r["body"]
        and b'{"a": 1}' in r["body"]
    )


def test_ingest_errors(tmp_path: Path):
    f = tmp_path / "x.json"
    f.write_text("{}")
    bad = Stub(status=404)
    try:
        with pytest.raises(CraError) as e:
            ingest(bad.url, "k", "sbom", "9", f)
        assert e.value.status == 404 and "9" in e.value.detail
    finally:
        bad.close()
    with pytest.raises(CraError, match="http"):
        ingest("ftp://x", "k", "sbom", "1", f)
    with pytest.raises(CraError, match="cannot reach"):
        ingest("http://127.0.0.1:1", "k", "sbom", "1", f, timeout=2)


# --- Tools -------------------------------------------------------------------


def test_missing_tools_are_skipped(project: Path, bin_dir: Path, tmp_path: Path):
    results = chk.run_tools(project, tmp_path / "out")
    assert {(r.tool, r.status) for r in results} == {
        ("trivy", "skipped"),
        ("opengrep", "skipped"),
        ("cppcheck", "skipped"),
    }
    assert chk.collect_uploads(results, tmp_path / "out") == {}


def test_tools_run_and_sast_is_merged(project: Path, bin_dir: Path, tmp_path: Path):
    (project / "main.c").write_text("int main(void){return 0;}")
    make_tool(bin_dir, "trivy", TRIVY % json.dumps(SARIF_EMPTY))
    make_tool(bin_dir, "opengrep", OPENGREP % json.dumps(SARIF_ONE))
    make_tool(bin_dir, "cppcheck", CPPCHECK % json.dumps(SARIF_ONE))
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []")
    out = tmp_path / "out"
    results = chk.run_tools(project, out, opengrep_config=rules)
    assert [(r.source, r.tool, r.status) for r in results] == [
        ("secrets", "trivy", "ok"),
        ("vulnscan", "trivy", "ok"),
        ("sast", "opengrep", "ok"),
        ("sast", "cppcheck", "ok"),
    ]
    uploads = chk.collect_uploads(results, out)
    assert set(uploads) == {"secrets", "vulnscan", "sast"}
    assert (
        len(json.loads(uploads["sast"].read_text())["runs"]) == 2
    )  # opengrep + cppcheck


def test_cppcheck_only_with_cpp_sources_and_opengrep_needs_rules(
    project: Path, bin_dir: Path, tmp_path: Path
):
    make_tool(bin_dir, "opengrep", OPENGREP % json.dumps(SARIF_EMPTY))
    make_tool(bin_dir, "cppcheck", CPPCHECK % json.dumps(SARIF_EMPTY))
    (project / "node_modules").mkdir()
    (project / "node_modules" / "x.c").write_text("")  # in a skipped directory
    by_tool = {r.tool: r for r in chk.run_tools(project, tmp_path / "o")}
    assert (
        "no C/C++" in by_tool["cppcheck"].message
        and "--opengrep-config" in by_tool["opengrep"].message
    )
    assert not chk.has_cpp(project)
    (project / "src").mkdir()
    (project / "src" / "a.hpp").write_text("")
    assert chk.has_cpp(project)


def test_skip_option(project: Path, bin_dir: Path, tmp_path: Path):
    make_tool(bin_dir, "trivy", TRIVY % json.dumps(SARIF_EMPTY))
    results = chk.run_tools(project, tmp_path / "o", skip=frozenset({"trivy"}))
    assert all(
        r.status == "skipped" and "--skip" in r.message
        for r in results
        if r.tool == "trivy"
    )


@pytest.mark.parametrize(
    ("body", "expect"),
    [
        ("sys.exit(3)", "exit code 3"),
        (
            'out = args[args.index("--output") + 1]\nopen(out, "w").write("kein json")',
            "not valid JSON",
        ),
        (
            'out = args[args.index("--output") + 1]\nopen(out, "w").write("{\\"version\\": \\"2.0.0\\", \\"runs\\": []}")',
            "not SARIF 2.1.0",
        ),
    ],
)
def test_failed_tool_is_an_error_and_not_uploaded(
    project: Path, bin_dir: Path, tmp_path: Path, body: str, expect: str
):
    make_tool(bin_dir, "trivy", body)
    results = chk.run_tools(project, tmp_path / "o")
    bad = [r for r in results if r.status == "error"]
    assert len(bad) == 2 and expect in bad[0].message
    assert chk.collect_uploads(results, tmp_path / "o") == {}


def test_opengrep_falls_back_to_sarif_dash_o(
    project: Path, bin_dir: Path, tmp_path: Path
):
    make_tool(
        bin_dir,
        "opengrep",
        'if "--help" in args:\n    print("--sarif  -o FILE")\n    sys.exit(0)\n'
        f'open(args[args.index("-o") + 1], "w").write(json.dumps({SARIF_EMPTY!r}))',
    )
    rules = tmp_path / "r.yml"
    rules.write_text("rules: []")
    r = next(
        x
        for x in chk.run_tools(project, tmp_path / "o", opengrep_config=rules)
        if x.tool == "opengrep"
    )
    assert r.status == "ok"


def test_ci_meta():
    assert chk.ci_meta(
        {
            "GITHUB_SHA": "s",
            "GITHUB_SERVER_URL": "https://gh",
            "GITHUB_REPOSITORY": "o/r",
            "GITHUB_RUN_ID": "7",
        }
    ) == (
        "s",
        "https://gh/o/r/actions/runs/7",
    )
    assert chk.ci_meta({"CI_COMMIT_SHA": "c", "CI_PIPELINE_URL": "https://gl/p/1"}) == (
        "c",
        "https://gl/p/1",
    )
    assert chk.ci_meta({}) == ("", "")


# --- Command -------------------------------------------------------------------


def run_cli(*args: str, env: dict[str, str] | None = None):
    return CliRunner().invoke(cli, ["check", *args], env=env or {})


def test_check_uploads_sbom_and_scans(
    project: Path, bin_dir: Path, tmp_path: Path, stub: Stub
):
    make_tool(bin_dir, "trivy", TRIVY % json.dumps(SARIF_EMPTY))
    out = tmp_path / "out"
    r = run_cli(
        str(project),
        "--cra-url",
        stub.url,
        "--cra-key",
        "cra_k",
        "--cra-version",
        "1.0.0",
        "--output-dir",
        str(out),
    )
    assert r.exit_code == 0, r.output
    assert [q["query"]["quelle"] for q in stub.requests] == [
        "sbom",
        "secrets",
        "vulnscan",
    ]
    sbom = json.loads((out / "sbom.cdx.json").read_text())
    assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.6"
    assert "Upload sbom ✓" in r.output and "- opengrep" in r.output


def test_check_dry_run_needs_no_platform(project: Path, bin_dir: Path, tmp_path: Path):
    r = run_cli(str(project), "--dry-run", "--output-dir", str(tmp_path / "o"))
    assert r.exit_code == 0 and "Dry run: would upload sbom" in r.output
    r = run_cli(str(project), "--output-dir", str(tmp_path / "o"))
    assert r.exit_code == 2 and "--cra-url" in r.output  # usage error


def test_check_reads_settings_from_environment(
    project: Path, bin_dir: Path, tmp_path: Path, stub: Stub
):
    env = {
        "CRA_URL": stub.url,
        "CRA_API_KEY": "cra_env",
        "CRA_VERSION": "2.0.0",
        "GITHUB_SHA": "deadbeef",
    }
    r = run_cli(str(project), "--output-dir", str(tmp_path / "o"), env=env)
    assert r.exit_code == 0, r.output
    q = stub.requests[0]
    assert (
        q["auth"] == "Bearer cra_env"
        and q["query"]["version"] == "2.0.0"
        and q["query"]["commit"] == "deadbeef"
    )


def test_exit_codes(project: Path, bin_dir: Path, tmp_path: Path):
    args = ["--cra-key", "k", "--cra-version", "1", "--output-dir", str(tmp_path / "o")]
    # platform rejects the upload -> 1
    bad = Stub(status=404)
    try:
        r = run_cli(str(project), "--cra-url", bad.url, *args)
        assert r.exit_code == 1 and "gibt es nicht" in r.output
    finally:
        bad.close()
    # platform unreachable -> 1
    assert (
        run_cli(str(project), "--cra-url", "http://127.0.0.1:1", *args).exit_code == 1
    )
    # findings only fail with --fail-on-findings
    findings = Stub(ergebnis="auffaelligkeiten")
    try:
        assert run_cli(str(project), "--cra-url", findings.url, *args).exit_code == 0
        assert (
            run_cli(
                str(project), "--cra-url", findings.url, "--fail-on-findings", *args
            ).exit_code
            == 1
        )
    finally:
        findings.close()
    # a tool crash -> 2, and the broken result is not uploaded, the SBOM still is
    make_tool(bin_dir, "trivy", "sys.exit(9)")
    ok = Stub()
    try:
        r = run_cli(str(project), "--cra-url", ok.url, *args)
        assert r.exit_code == 2 and "✗ trivy" in r.output
        assert [q["query"]["quelle"] for q in ok.requests] == ["sbom"]
    finally:
        ok.close()


def sarif_with_notes(*texts: str, successful: bool = True) -> str:
    notes = [{"level": "warning", "message": {"text": t}} for t in texts]
    inv = [{"executionSuccessful": successful, "toolExecutionNotifications": notes}]
    return json.dumps(
        {"version": "2.1.0", "runs": [{"results": [], "invocations": inv}]}
    )


def test_rule_timeouts_make_a_run_incomplete(tmp_path: Path):
    f = tmp_path / "o.sarif"
    f.write_text(
        sarif_with_notes(
            "Syntax error at line /src/a.ts:1",
            "Timeout when running rules.x on /src/big.js:",
        )
    )
    assert "1 rule timeout" in (chk.incomplete(f) or "")
    f.write_text(
        sarif_with_notes("Syntax error at line /src/a.ts:1")
    )  # unparsable files are not a timeout
    assert chk.incomplete(f) is None
    f.write_text(sarif_with_notes(successful=False))
    assert "unsuccessful" in (chk.incomplete(f) or "")


def test_tool_with_timeout_is_an_error_and_not_uploaded(
    project: Path, bin_dir: Path, tmp_path: Path
):
    doc = sarif_with_notes("Timeout when running rules.x on /src/big.js:")
    body = (
        'if "--help" in args:\n'
        '    print("--sarif-output=FILE")\n'
        "    sys.exit(0)\n"
        'out = [a for a in args if a.startswith("--sarif-output=")][0].split("=", 1)[1]\n'
        f"open(out, 'w').write({doc!r})\n"
    )
    make_tool(bin_dir, "opengrep", body)
    rules = tmp_path / "r.yml"
    rules.write_text("rules: []")
    results = chk.run_tools(project, tmp_path / "o", opengrep_config=rules)
    og = next(r for r in results if r.tool == "opengrep")
    assert og.status == "error" and "timeout" in og.message
    assert "sast" not in chk.collect_uploads(results, tmp_path / "o")
