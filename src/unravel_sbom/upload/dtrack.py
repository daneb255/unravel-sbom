"""Dependency-Track BOM upload client.

Uploads a CycloneDX BOM to a Dependency-Track instance via the documented
CI/CD API endpoint:  PUT /api/v1/bom  (JSON + Base64-encoded BOM).

Reference: https://docs.dependencytrack.org/usage/cicd/
"""

from __future__ import annotations

import base64
import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

_BOM_ENDPOINT = "/api/v1/bom"
_PROJECT_ENDPOINT = "/api/v1/project"


class DependencyTrackError(RuntimeError):
    """Raised when the Dependency-Track API returns an error."""

    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body
        super().__init__(f"Dependency-Track API error {status}: {body}")


@dataclass
class UploadResult:
    token: str  # async processing token returned by the API
    project_uuid: str  # resolved project UUID (may be empty if auto-created async)
    status_code: int


def _base64_encode_bom(bom_dict: dict[str, Any]) -> str:
    raw = json.dumps(bom_dict, separators=(",", ":"))
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


def _validate_url_scheme(url: str) -> None:
    if not url.startswith(("http://", "https://")):
        raise ValueError(
            f"Dependency-Track URL must start with http:// or https://, got: {url!r}"
        )


def _request(
    method: str,
    url: str,
    api_key: str,
    payload: dict[str, Any],
    timeout: int,
) -> tuple[int, dict[str, Any]]:
    _validate_url_scheme(url)
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Content-Type": "application/json",
            "X-Api-Key": api_key,
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise DependencyTrackError(exc.code, raw) from exc
    except urllib.error.URLError as exc:
        raise DependencyTrackError(0, str(exc.reason)) from exc


def upload_bom(
    bom_dict: dict[str, Any],
    *,
    base_url: str,
    api_key: str,
    project_name: str,
    project_version: str = "latest",
    project_uuid: str | None = None,
    auto_create: bool = True,
    timeout: int = 30,
) -> UploadResult:
    """Upload *bom_dict* (a CycloneDX 1.6 BOM) to Dependency-Track.

    Identifies the target project either by *project_uuid* (preferred) or by
    *project_name* + *project_version* with optional auto-creation.

    Args:
        bom_dict:        The CycloneDX BOM as a Python dict
                         (from cdx_reporter.generate()).
        base_url:        Dependency-Track base URL, e.g.
                         "https://dtrack.example.com".
        api_key:         API key with BOM_UPLOAD (or PORTFOLIO_MANAGEMENT).
        project_name:    Project name in Dependency-Track.
        project_version: Project version string.
        project_uuid:    If known, target a specific project by UUID.
        auto_create:     Create the project if it does not exist yet.
        timeout:         HTTP timeout in seconds.

    Returns:
        UploadResult with the async processing token.

    Raises:
        DependencyTrackError: on any non-2xx response.
        ValueError: if base_url is empty or bom_dict is not a CycloneDX document.
    """
    if not base_url:
        raise ValueError("base_url must not be empty")
    if bom_dict.get("bomFormat") != "CycloneDX":
        raise ValueError("bom_dict must be a CycloneDX BOM (bomFormat == 'CycloneDX')")

    base_url = base_url.rstrip("/")
    endpoint = base_url + _BOM_ENDPOINT

    payload: dict[str, Any] = {
        "bom": _base64_encode_bom(bom_dict),
    }

    if project_uuid:
        payload["project"] = project_uuid
        logger.debug("Targeting project UUID %s", project_uuid)
    else:
        payload["projectName"] = project_name
        payload["projectVersion"] = project_version
        payload["autoCreate"] = auto_create
        logger.debug(
            "Targeting project %r version %r (autoCreate=%s)",
            project_name,
            project_version,
            auto_create,
        )

    logger.info("Uploading BOM to %s …", endpoint)
    status, body = _request("PUT", endpoint, api_key, payload, timeout)

    token = body.get("token", "")
    logger.info("Upload accepted — processing token: %s", token)

    return UploadResult(
        token=token,
        project_uuid=project_uuid or "",
        status_code=status,
    )


def get_processing_status(
    token: str,
    *,
    base_url: str,
    api_key: str,
    timeout: int = 30,
) -> bool:
    """Poll /api/v1/bom/token/{token} to check if processing is complete.

    Returns True when processing is finished, False when still in progress.
    Raises DependencyTrackError on API errors.
    """
    base_url = base_url.rstrip("/")
    _validate_url_scheme(base_url)
    url = f"{base_url}/api/v1/bom/token/{token}"
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"X-Api-Key": api_key, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            body = json.loads(resp.read().decode("utf-8"))
            return not body.get("processing", True)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise DependencyTrackError(exc.code, raw) from exc
    except urllib.error.URLError as exc:
        raise DependencyTrackError(0, str(exc.reason)) from exc


def lookup_project(
    project_name: str,
    project_version: str,
    *,
    base_url: str,
    api_key: str,
    timeout: int = 30,
) -> dict[str, Any] | None:
    """Return the Dependency-Track project dict, or None if not found."""
    import urllib.parse

    base_url = base_url.rstrip("/")
    _validate_url_scheme(base_url)
    params = urllib.parse.urlencode({"name": project_name, "version": project_version})
    url = f"{base_url}{_PROJECT_ENDPOINT}/lookup?{params}"
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"X-Api-Key": api_key, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raw = exc.read().decode("utf-8", errors="replace")
        raise DependencyTrackError(exc.code, raw) from exc
    except urllib.error.URLError as exc:
        raise DependencyTrackError(0, str(exc.reason)) from exc
