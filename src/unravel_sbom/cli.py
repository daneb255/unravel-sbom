from __future__ import annotations

import contextlib
import logging
import sys
import time
from pathlib import Path
from typing import Any

import click

from unravel_sbom import __version__
from unravel_sbom.models import ScanResult
from unravel_sbom.reporters import spdx as spdx_reporter
from unravel_sbom.scanners import ALL_SCANNERS
from unravel_sbom.walker import walk

_FORMATS = ("spdx", "cyclonedx", "both")


def _format_elapsed(seconds: float) -> str:
    """Format elapsed seconds as a human-readable string."""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{minutes}m {secs}s"


@contextlib.contextmanager
def _progress_context(active: bool):  # type: ignore[return]
    """Context manager that yields an on_file callback for the walker.

    When *active* (not in verbose mode), renders a live counter that
    overwrites a single line on TTY terminals: "  N files  <filename>".
    In non-TTY environments (pipes, CI) the counter is printed once per
    file without carriage-return so it doesn't clutter logs.
    The final state is kept visible (newline) so fast scans still show output.
    """
    if active:
        is_tty = sys.stderr.isatty()
        count = [0]
        width = 60

        def _cb(path: Path) -> None:
            count[0] += 1
            label = f"  {count[0]:>4} files  {path.name}"
            if is_tty:
                sys.stderr.write(f"\r{label:<{width}}")
            else:
                sys.stderr.write(f"{label}\n")
            sys.stderr.flush()

        try:
            yield _cb
        finally:
            if is_tty:
                sys.stderr.write("\n")
                sys.stderr.flush()
    else:
        yield None


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)s  %(name)s  %(message)s",
        stream=sys.stderr,
    )


# ---------------------------------------------------------------------------
# Shared Dependency-Track options (reused by both `scan` and `upload`)
# ---------------------------------------------------------------------------

_dtrack_options = [
    click.option(
        "--dtrack-url",
        envvar="DTRACK_URL",
        default=None,
        metavar="URL",
        help="Dependency-Track base URL (e.g. https://dtrack.example.com). "
        "Also reads $DTRACK_URL.",
    ),
    click.option(
        "--dtrack-key",
        envvar="DTRACK_API_KEY",
        default=None,
        metavar="KEY",
        help="Dependency-Track API key. Also reads $DTRACK_API_KEY.",
    ),
    click.option(
        "--dtrack-project",
        "dtrack_project_name",
        default=None,
        metavar="NAME",
        help="Project name in Dependency-Track (default: scanned directory name).",
    ),
    click.option(
        "--dtrack-version",
        "dtrack_project_version",
        default="latest",
        show_default=True,
        help="Project version string.",
    ),
    click.option(
        "--dtrack-uuid",
        "dtrack_project_uuid",
        default=None,
        metavar="UUID",
        help="Target a specific project by UUID instead of name+version.",
    ),
    click.option(
        "--dtrack-autocreate/--no-dtrack-autocreate",
        "dtrack_auto_create",
        default=True,
        show_default=True,
        help="Auto-create the project if it doesn't exist.",
    ),
    click.option(
        "--dtrack-wait",
        is_flag=True,
        default=False,
        help="Poll the processing token until Dependency-Track finishes analysing.",
    ),
    click.option(
        "--dtrack-timeout",
        type=int,
        default=30,
        show_default=True,
        metavar="SECS",
        help="HTTP timeout for Dependency-Track requests.",
    ),
]


def _add_dtrack_options(f):
    for opt in reversed(_dtrack_options):
        f = opt(f)
    return f


def _do_dtrack_upload(
    cdx_doc: dict[str, Any],
    *,
    base_url: str,
    api_key: str,
    project_name: str,
    project_version: str,
    project_uuid: str | None,
    auto_create: bool,
    wait: bool,
    timeout: int,
) -> None:
    from unravel_sbom.upload.dtrack import (
        DependencyTrackError,
        get_processing_status,
        upload_bom,
    )

    try:
        result = upload_bom(
            cdx_doc,
            base_url=base_url,
            api_key=api_key,
            project_name=project_name,
            project_version=project_version,
            project_uuid=project_uuid,
            auto_create=auto_create,
            timeout=timeout,
        )
    except DependencyTrackError as exc:
        click.echo(f"  Dependency-Track upload failed: {exc}", err=True)
        raise SystemExit(1) from exc

    click.echo(
        f"  Dependency-Track ✓  token={result.token}  ({base_url})",
        err=True,
    )

    if wait and result.token:
        click.echo("  Waiting for Dependency-Track processing …", err=True)
        for attempt in range(60):
            time.sleep(5)
            try:
                done = get_processing_status(
                    result.token, base_url=base_url, api_key=api_key, timeout=timeout
                )
            except DependencyTrackError as exc:
                click.echo(f"  Poll error: {exc}", err=True)
                break
            if done:
                click.echo("  Processing complete.", err=True)
                break
            if attempt % 6 == 5:
                click.echo(f"  Still processing … ({(attempt + 1) * 5}s)", err=True)
        else:
            click.echo("  Timed out waiting for processing (5 min).", err=True)


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="unravel-sbom")
def cli() -> None:
    """unravel-sbom — generate and upload SBOMs for your projects."""


# ---------------------------------------------------------------------------
# `scan` command
# ---------------------------------------------------------------------------


@cli.command("scan")
@click.argument("source", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    default=None,
    help="Output file path. Defaults to <dir>.spdx.json or <dir>.cdx.json. "
    "Ignored when --format=both.",
)
@click.option(
    "-f",
    "--format",
    "fmt",
    type=click.Choice(_FORMATS, case_sensitive=False),
    default="spdx",
    show_default=True,
    help="Output format: spdx, cyclonedx, or both.",
)
@click.option(
    "--name",
    "document_name",
    default=None,
    help="Document/BOM name (default: SBOM-<dir>).",
)
@click.option(
    "--max-depth",
    type=int,
    default=None,
    help="Maximum directory recursion depth (default: unlimited).",
)
@click.option(
    "--creator-email",
    envvar="UNRAVEL_CREATOR_EMAIL",
    default=None,
    metavar="EMAIL",
    help="Email identifying the SBOM creator (BSI TR-03183-2). "
    "Falls back to a placeholder URL with a warning if omitted.",
)
@click.option(
    "--creator-url",
    envvar="UNRAVEL_CREATOR_URL",
    default=None,
    metavar="URL",
    help="URL identifying the SBOM creator, alternative to --creator-email.",
)
@_add_dtrack_options
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
def scan_cmd(
    source: Path,
    output_path: Path | None,
    fmt: str,
    document_name: str | None,
    max_depth: int | None,
    creator_email: str | None,
    creator_url: str | None,
    dtrack_url: str | None,
    dtrack_key: str | None,
    dtrack_project_name: str | None,
    dtrack_project_version: str,
    dtrack_project_uuid: str | None,
    dtrack_auto_create: bool,
    dtrack_wait: bool,
    dtrack_timeout: int,
    verbose: bool,
) -> None:
    """Scan SOURCE and write an SBOM — optionally upload to Dependency-Track.

    \b
    Output formats (--format):
      spdx       SPDX 3.0.1 JSON-LD (BSI TR-03183-2) (default)
      cyclonedx  CycloneDX 1.6 JSON
      both       writes one file of each

    \b
    Supported ecosystems:
      • npm       (package.json, package-lock.json)
      • PyPI      (requirements.txt, pyproject.toml, poetry.lock)
      • Conan     (conanfile.txt, conanfile.py)
      • Makefile  (LDFLAGS / LDLIBS / pkg-config calls)

    \b
    Dependency-Track upload (requires --dtrack-url + --dtrack-key):
      Always uploads a CycloneDX BOM regardless of --format.
    """
    _setup_logging(verbose)
    fmt = fmt.lower()
    stem = source.resolve().name

    use_progress = not verbose
    click.echo(f"Scanning {source.resolve()} …", err=True)

    t0 = time.perf_counter()
    with _progress_context(use_progress) as on_file:
        result: ScanResult = walk(
            source, ALL_SCANNERS, max_depth=max_depth, on_file=on_file
        )
    elapsed = _format_elapsed(time.perf_counter() - t0)

    if result.errors:
        click.echo(
            f"  {len(result.errors)} file(s) could not be parsed (see --verbose for details).",
            err=True,
        )
    click.echo(
        f"  Found {len(result.packages)} package entries in {elapsed}.", err=True
    )

    cdx_doc: dict[str, Any] | None = None

    if fmt in ("spdx", "both"):
        spdx_out = (
            output_path
            if (fmt == "spdx" and output_path)
            else Path(f"{stem}.spdx.json")
        )
        if not creator_email and not creator_url:
            click.echo(
                "  Warning: no --creator-email/--creator-url given — SPDX output will use "
                "a placeholder creator URL and is not fully BSI TR-03183-2 conformant.",
                err=True,
            )
        doc = spdx_reporter.generate(
            result,
            scan_root=source,
            document_name=document_name,
            creator_email=creator_email,
            creator_url=creator_url,
        )
        spdx_reporter.write(doc, spdx_out)
        click.echo(
            f"  SPDX 3.0.1    → {spdx_out}  ({spdx_reporter.package_count(doc)} packages)",
            err=True,
        )

    if fmt in ("cyclonedx", "both"):
        from unravel_sbom.reporters import cyclonedx as cdx_reporter

        cdx_out = (
            output_path
            if (fmt == "cyclonedx" and output_path)
            else Path(f"{stem}.cdx.json")
        )
        cdx_doc = cdx_reporter.generate(
            result, scan_root=source, document_name=document_name
        )
        cdx_reporter.write(cdx_doc, cdx_out)
        click.echo(
            f"  CycloneDX 1.6 → {cdx_out}  ({len(cdx_doc['components'])} components)",
            err=True,
        )

    if dtrack_url and dtrack_key:
        from unravel_sbom.reporters import cyclonedx as cdx_reporter

        # Always need a CycloneDX BOM for Dependency-Track
        if cdx_doc is None:
            cdx_doc = cdx_reporter.generate(
                result, scan_root=source, document_name=document_name
            )
        _do_dtrack_upload(
            cdx_doc,
            base_url=dtrack_url,
            api_key=dtrack_key,
            project_name=dtrack_project_name or stem,
            project_version=dtrack_project_version,
            project_uuid=dtrack_project_uuid,
            auto_create=dtrack_auto_create,
            wait=dtrack_wait,
            timeout=dtrack_timeout,
        )
    elif dtrack_url or dtrack_key:
        missing = "--dtrack-key" if dtrack_url else "--dtrack-url"
        click.echo(
            f"  Warning: {missing} is required for Dependency-Track upload — skipping.",
            err=True,
        )


# ---------------------------------------------------------------------------
# `upload` command  (upload an existing BOM file)
# ---------------------------------------------------------------------------


@cli.command("upload")
@click.argument(
    "bom_file", type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@_add_dtrack_options
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
def upload_cmd(
    bom_file: Path,
    dtrack_url: str | None,
    dtrack_key: str | None,
    dtrack_project_name: str | None,
    dtrack_project_version: str,
    dtrack_project_uuid: str | None,
    dtrack_auto_create: bool,
    dtrack_wait: bool,
    dtrack_timeout: int,
    verbose: bool,
) -> None:
    """Upload an existing CycloneDX BOM_FILE to Dependency-Track.

    \b
    Required:
      --dtrack-url   or $DTRACK_URL
      --dtrack-key   or $DTRACK_API_KEY

    \b
    Example:
      unravel-sbom upload myapp.cdx.json \\
        --dtrack-url https://dtrack.example.com \\
        --dtrack-key YOUR_API_KEY \\
        --dtrack-project myapp --dtrack-version 1.4.2
    """
    _setup_logging(verbose)
    import json

    if not dtrack_url:
        raise click.UsageError("--dtrack-url (or $DTRACK_URL) is required")
    if not dtrack_key:
        raise click.UsageError("--dtrack-key (or $DTRACK_API_KEY) is required")

    try:
        cdx_doc: dict[str, Any] = json.loads(bom_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise click.BadParameter(
            f"Cannot read BOM file: {exc}", param_hint="BOM_FILE"
        ) from exc

    if cdx_doc.get("bomFormat") != "CycloneDX":
        raise click.BadParameter(
            "File does not appear to be a CycloneDX BOM (bomFormat != 'CycloneDX')",
            param_hint="BOM_FILE",
        )

    project_name = dtrack_project_name or bom_file.stem.replace(".cdx", "")
    click.echo(
        f"Uploading {bom_file.name} → {dtrack_url}  "
        f"(project={project_name!r} version={dtrack_project_version!r})",
        err=True,
    )

    _do_dtrack_upload(
        cdx_doc,
        base_url=dtrack_url,
        api_key=dtrack_key,
        project_name=project_name,
        project_version=dtrack_project_version,
        project_uuid=dtrack_project_uuid,
        auto_create=dtrack_auto_create,
        wait=dtrack_wait,
        timeout=dtrack_timeout,
    )


# ---------------------------------------------------------------------------
# `dtrack` sub-group (convenience alias for project management)
# ---------------------------------------------------------------------------


@cli.group("dtrack")
def dtrack_group() -> None:
    """Dependency-Track project management utilities."""


@dtrack_group.command("lookup")
@click.argument("project_name")
@click.argument("project_version")
@click.option(
    "--url",
    envvar="DTRACK_URL",
    required=True,
    metavar="URL",
    help="Dependency-Track base URL. Also reads $DTRACK_URL.",
)
@click.option(
    "--key",
    envvar="DTRACK_API_KEY",
    required=True,
    metavar="KEY",
    help="API key. Also reads $DTRACK_API_KEY.",
)
@click.option("-v", "--verbose", is_flag=True)
def dtrack_lookup(
    project_name: str, project_version: str, url: str, key: str, verbose: bool
) -> None:
    """Look up a project by NAME and VERSION and print its metadata as JSON."""
    import json

    _setup_logging(verbose)
    from unravel_sbom.upload.dtrack import DependencyTrackError, lookup_project

    try:
        project = lookup_project(
            project_name, project_version, base_url=url, api_key=key
        )
    except DependencyTrackError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1) from exc

    if project is None:
        click.echo(f"Project {project_name!r} {project_version!r} not found.", err=True)
        raise SystemExit(1)

    click.echo(json.dumps(project, indent=2))


main = cli

if __name__ == "__main__":
    cli()
