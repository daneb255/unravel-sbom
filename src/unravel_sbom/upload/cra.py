"""Upload client for the CRA platform ingest API (POST /api/v1/ci/ingest)."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

_INGEST = "/api/v1/ci/ingest"


class CraError(RuntimeError):
    """Raised when the platform rejects an upload or cannot be reached."""

    def __init__(self, status: int, detail: str) -> None:
        self.status = status
        self.detail = detail
        super().__init__(f"CRA platform error {status}: {detail}")


def _multipart(field: str, filename: str, content: bytes) -> tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    safe = filename.replace('"', "_").replace("\r", "_").replace("\n", "_")
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="{safe}"\r\n'
        "Content-Type: application/json\r\n\r\n"
    ).encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    return head + content + tail, f"multipart/form-data; boundary={boundary}"


def ingest(
    base_url: str,
    api_key: str,
    source: str,
    version: str,
    file: Path,
    *,
    commit: str = "",
    pipeline_url: str = "",
    timeout: int = 120,
) -> dict[str, Any]:
    """Upload one result file (sbom, secrets, sast or vulnscan) and return the platform's answer."""
    if not base_url.startswith(("http://", "https://")):
        raise CraError(0, f"URL must start with http:// or https://: {base_url!r}")
    query = urllib.parse.urlencode(
        {"quelle": source, "version": version, "commit": commit, "url": pipeline_url}
    )
    body, content_type = _multipart("datei", file.name, file.read_bytes())
    req = urllib.request.Request(  # nosec B310 - scheme checked above
        f"{base_url.rstrip('/')}{_INGEST}?{query}",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": content_type,
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            return json.loads(resp.read())  # type: ignore[no-any-return]
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        try:
            detail = json.loads(raw).get("detail", raw)
        except ValueError:
            detail = raw
        raise CraError(exc.code, str(detail)) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CraError(0, f"cannot reach {base_url}: {exc}") from exc
