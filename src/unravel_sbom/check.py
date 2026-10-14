"""`unravel-sbom check`: run the evidence tools of a CI job and collect their results.

The tools (trivy, opengrep, cppcheck) are external programs. They are never run through a
shell, and a tool that is missing is skipped. A tool that fails is reported as an error and
its result is never uploaded, so a crashed scanner cannot look like "no findings".
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 - only called with argv lists
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from unravel_sbom.walker import _SKIP_DIRS

TOOLS = ("trivy", "opengrep", "cppcheck")
CPP_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"})
TIMEOUT = 30 * 60


@dataclass
class ToolResult:
    source: str  # platform source: secrets, vulnscan or sast
    tool: str
    status: str  # ok | skipped | error
    message: str = ""
    file: Path | None = None


def has_cpp(root: Path) -> bool:
    for _, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        if any(Path(f).suffix.lower() in CPP_SUFFIXES for f in files):
            return True
    return False


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # nosec B603 - argv list, no shell
        argv, capture_output=True, text=True, timeout=TIMEOUT, check=False
    )


def check_sarif(path: Path) -> str | None:
    """Return an error message if the file is not usable SARIF 2.1.0, else None."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return f"not valid JSON: {exc}"
    if not isinstance(doc, dict) or doc.get("version") != "2.1.0":
        return "not SARIF 2.1.0"
    if not isinstance(doc.get("runs"), list):
        return "SARIF without runs"
    return None


def incomplete(path: Path) -> str | None:
    """Opengrep reports rule timeouts only as notifications, exit code 0 and executionSuccessful=true.
    Findings are silently missing then, so such a run must not count as a clean result."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    timeouts = 0
    for run in doc["runs"]:
        for inv in run.get("invocations") or []:
            if inv.get("executionSuccessful") is False:
                return "tool reports an unsuccessful run"
            for note in inv.get("toolExecutionNotifications") or []:
                if str((note.get("message") or {}).get("text", "")).startswith(
                    "Timeout"
                ):
                    timeouts += 1
    if timeouts:
        return f"{timeouts} rule timeout(s), the result is incomplete (exclude large generated files or run again)"
    return None


def merge_sarif(files: list[Path], out: Path) -> Path:
    """Combine several SARIF files into one (opengrep and cppcheck both feed `sast`)."""
    runs: list[Any] = []
    for f in files:
        runs += json.loads(f.read_text(encoding="utf-8"))["runs"]
    out.write_text(json.dumps({"version": "2.1.0", "runs": runs}), encoding="utf-8")
    return out


def _finish(
    source: str, tool: str, out: Path, proc: subprocess.CompletedProcess[str]
) -> ToolResult:
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or [""]
        return ToolResult(
            source, tool, "error", f"exit code {proc.returncode}: {tail[0]}"
        )
    problem = check_sarif(out) or incomplete(out)
    if problem:
        return ToolResult(source, tool, "error", problem)
    return ToolResult(source, tool, "ok", file=out)


def run_trivy(
    root: Path, outdir: Path, scanners: str, source: str, name: str
) -> ToolResult:
    out = outdir / name
    proc = _run(
        [
            "trivy",
            "fs",
            "--quiet",
            "--scanners",
            scanners,
            "--format",
            "sarif",
            "--output",
            str(out),
            str(root),
        ]
    )
    return _finish(source, "trivy", out, proc)


def run_opengrep(root: Path, outdir: Path, config: Path) -> ToolResult:
    out = outdir / "opengrep.sarif"
    # Two spellings exist in the wild, so ask the installed version.
    help_text = _run(["opengrep", "scan", "--help"])
    sarif_args = (
        [f"--sarif-output={out}"]
        if "--sarif-output" in help_text.stdout + help_text.stderr
        else ["--sarif", "-o", str(out)]
    )
    proc = _run(
        ["opengrep", "scan", "--config", str(config), *sarif_args, "--quiet", str(root)]
    )
    return _finish("sast", "opengrep", out, proc)


def run_cppcheck(root: Path, outdir: Path) -> ToolResult:
    out = outdir / "cppcheck.sarif"
    proc = _run(
        ["cppcheck", "--enable=warning", "--output-format=sarif", "--quiet", str(root)]
    )
    if proc.returncode != 0:
        return ToolResult(
            "sast",
            "cppcheck",
            "error",
            f"exit code {proc.returncode}: {proc.stderr.strip()[-200:]}",
        )
    out.write_text(proc.stderr, encoding="utf-8")  # cppcheck writes SARIF to stderr
    problem = check_sarif(out) or incomplete(out)
    if problem:
        return ToolResult("sast", "cppcheck", "error", problem)
    return ToolResult("sast", "cppcheck", "ok", file=out)


def run_tools(
    root: Path,
    outdir: Path,
    *,
    skip: frozenset[str] = frozenset(),
    opengrep_config: Path | None = None,
) -> list[ToolResult]:
    outdir.mkdir(parents=True, exist_ok=True)
    root = root.resolve()

    def why_not(tool: str) -> str | None:
        if tool in skip:
            return "skipped by --skip"
        return None if shutil.which(tool) else "not installed"

    def one(
        source: str, tool: str, reason: str | None, run: Callable[[], ToolResult]
    ) -> ToolResult:
        return ToolResult(source, tool, "skipped", reason) if reason else run()

    trivy = why_not("trivy")
    opengrep = why_not("opengrep") or (
        None if opengrep_config else "needs --opengrep-config (rules)"
    )
    cppcheck = why_not("cppcheck") or (None if has_cpp(root) else "no C/C++ sources")
    return [
        one(
            "secrets",
            "trivy",
            trivy,
            lambda: run_trivy(root, outdir, "secret", "secrets", "trivy-secrets.sarif"),
        ),
        one(
            "vulnscan",
            "trivy",
            trivy,
            lambda: run_trivy(root, outdir, "vuln", "vulnscan", "trivy-vuln.sarif"),
        ),
        one(
            "sast",
            "opengrep",
            opengrep,
            lambda: run_opengrep(root, outdir, opengrep_config or Path()),
        ),
        one("sast", "cppcheck", cppcheck, lambda: run_cppcheck(root, outdir)),
    ]


def collect_uploads(results: list[ToolResult], outdir: Path) -> dict[str, Path]:
    """One file per platform source. A source with any failed tool is left out."""
    uploads: dict[str, Path] = {}
    for source in ("secrets", "vulnscan", "sast"):
        mine = [r for r in results if r.source == source and r.status != "skipped"]
        if not mine or any(r.status == "error" for r in mine):
            continue
        files = [r.file for r in mine if r.file]
        uploads[source] = (
            files[0]
            if len(files) == 1
            else merge_sarif(files, outdir / f"{source}.sarif")
        )
    return uploads


def ci_meta(env: dict[str, str] | None = None) -> tuple[str, str]:
    """Commit and pipeline URL from the usual CI variables (GitHub Actions, GitLab CI)."""
    e = os.environ if env is None else env
    if e.get("GITHUB_SHA"):
        run_url = (
            f"{e.get('GITHUB_SERVER_URL', '')}/{e.get('GITHUB_REPOSITORY', '')}"
            f"/actions/runs/{e.get('GITHUB_RUN_ID', '')}"
        )
        return e["GITHUB_SHA"], run_url
    return e.get("CI_COMMIT_SHA", ""), e.get("CI_PIPELINE_URL", "")
