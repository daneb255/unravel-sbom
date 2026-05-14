"""Tests for the Dependency-Track upload client.

All HTTP calls are intercepted with unittest.mock so no real server is needed.
"""

from __future__ import annotations

import base64
import json
import urllib.error
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from unravel_sbom.upload.dtrack import (
    DependencyTrackError,
    UploadResult,
    _base64_encode_bom,
    get_processing_status,
    lookup_project,
    upload_bom,
)

# ---------------------------------------------------------------------------
# Minimal CycloneDX BOM fixture
# ---------------------------------------------------------------------------

SAMPLE_BOM: dict = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000001",
    "version": 1,
    "metadata": {"timestamp": "2024-01-01T00:00:00Z"},
    "components": [
        {
            "type": "library",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
            "bom-ref": "SPDXRef-pypi-requests-2-31-0",
        },
    ],
}

BASE_URL = "https://dtrack.example.com"
API_KEY = "test-api-key-abc123"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(body: dict, status: int = 200):
    """Return a context-manager-compatible mock for urllib.request.urlopen."""
    raw = json.dumps(body).encode()
    mock_resp = MagicMock()
    mock_resp.status = status
    mock_resp.read.return_value = raw
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _mock_http_error(status: int, body: str = "error"):
    err = urllib.error.HTTPError(
        url="http://x",
        code=status,
        msg="err",
        hdrs=None,  # type: ignore[arg-type]
        fp=BytesIO(body.encode()),
    )
    return err


# ---------------------------------------------------------------------------
# _base64_encode_bom
# ---------------------------------------------------------------------------


class TestBase64EncodeBom:
    def test_output_is_valid_base64(self):
        encoded = _base64_encode_bom(SAMPLE_BOM)
        decoded = base64.b64decode(encoded).decode("utf-8")
        assert json.loads(decoded)["bomFormat"] == "CycloneDX"

    def test_roundtrip(self):
        encoded = _base64_encode_bom(SAMPLE_BOM)
        decoded = json.loads(base64.b64decode(encoded))
        assert decoded["specVersion"] == "1.6"
        assert len(decoded["components"]) == 1


# ---------------------------------------------------------------------------
# upload_bom
# ---------------------------------------------------------------------------


class TestUploadBom:
    def test_successful_upload_by_name(self):
        response_body = {"token": "abc-token-123"}
        with patch(
            "urllib.request.urlopen", return_value=_mock_response(response_body)
        ):
            result = upload_bom(
                SAMPLE_BOM,
                base_url=BASE_URL,
                api_key=API_KEY,
                project_name="myapp",
                project_version="1.0.0",
            )
        assert isinstance(result, UploadResult)
        assert result.token == "abc-token-123"
        assert result.status_code == 200

    def test_successful_upload_by_uuid(self):
        response_body = {"token": "uuid-token-456"}
        with patch(
            "urllib.request.urlopen", return_value=_mock_response(response_body)
        ):
            result = upload_bom(
                SAMPLE_BOM,
                base_url=BASE_URL,
                api_key=API_KEY,
                project_name="myapp",
                project_uuid="f90934f5-cb88-47ce-81cb-db06fc67d4b4",
            )
        assert result.token == "uuid-token-456"
        assert result.project_uuid == "f90934f5-cb88-47ce-81cb-db06fc67d4b4"

    def test_payload_contains_base64_bom(self):
        captured: list[bytes] = []

        def fake_urlopen(req, timeout=None):
            captured.append(req.data)
            return _mock_response({"token": "t"})

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            upload_bom(
                SAMPLE_BOM,
                base_url=BASE_URL,
                api_key=API_KEY,
                project_name="p",
            )

        payload = json.loads(captured[0])
        assert "bom" in payload
        decoded = json.loads(base64.b64decode(payload["bom"]))
        assert decoded["bomFormat"] == "CycloneDX"

    def test_payload_by_name_sets_autocreate(self):
        captured: list[bytes] = []

        def fake_urlopen(req, timeout=None):
            captured.append(req.data)
            return _mock_response({"token": "t"})

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            upload_bom(
                SAMPLE_BOM,
                base_url=BASE_URL,
                api_key=API_KEY,
                project_name="myapp",
                project_version="2.0",
                auto_create=True,
            )

        payload = json.loads(captured[0])
        assert payload["projectName"] == "myapp"
        assert payload["projectVersion"] == "2.0"
        assert payload["autoCreate"] is True
        assert "project" not in payload

    def test_payload_by_uuid_does_not_include_name(self):
        captured: list[bytes] = []

        def fake_urlopen(req, timeout=None):
            captured.append(req.data)
            return _mock_response({"token": "t"})

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            upload_bom(
                SAMPLE_BOM,
                base_url=BASE_URL,
                api_key=API_KEY,
                project_name="ignored",
                project_uuid="aaaa-bbbb",
            )

        payload = json.loads(captured[0])
        assert payload["project"] == "aaaa-bbbb"
        assert "projectName" not in payload

    def test_api_key_header_is_set(self):
        captured: list = []

        def fake_urlopen(req, timeout=None):
            captured.append(req.headers)
            return _mock_response({"token": "t"})

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            upload_bom(
                SAMPLE_BOM,
                base_url=BASE_URL,
                api_key=API_KEY,
                project_name="p",
            )

        headers = captured[0]
        # urllib normalises header names to title-case
        assert headers.get("X-api-key") == API_KEY

    def test_http_error_raises_dtrack_error(self):
        with patch(
            "urllib.request.urlopen", side_effect=_mock_http_error(401, "Unauthorized")
        ):
            with pytest.raises(DependencyTrackError) as exc_info:
                upload_bom(
                    SAMPLE_BOM, base_url=BASE_URL, api_key="bad", project_name="p"
                )
        assert exc_info.value.status == 401

    def test_connection_error_raises_dtrack_error(self):
        url_err = urllib.error.URLError("Connection refused")
        with patch("urllib.request.urlopen", side_effect=url_err):
            with pytest.raises(DependencyTrackError) as exc_info:
                upload_bom(
                    SAMPLE_BOM, base_url=BASE_URL, api_key=API_KEY, project_name="p"
                )
        assert exc_info.value.status == 0

    def test_empty_base_url_raises_value_error(self):
        with pytest.raises(ValueError, match="base_url"):
            upload_bom(SAMPLE_BOM, base_url="", api_key=API_KEY, project_name="p")

    def test_non_cyclonedx_bom_raises_value_error(self):
        bad_bom = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}
        with pytest.raises(ValueError, match="CycloneDX"):
            upload_bom(bad_bom, base_url=BASE_URL, api_key=API_KEY, project_name="p")

    def test_trailing_slash_stripped_from_base_url(self):
        captured: list = []

        def fake_urlopen(req, timeout=None):
            captured.append(req.full_url)
            return _mock_response({"token": "t"})

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            upload_bom(
                SAMPLE_BOM,
                base_url="https://dtrack.example.com/",
                api_key=API_KEY,
                project_name="p",
            )

        assert captured[0] == "https://dtrack.example.com/api/v1/bom"


# ---------------------------------------------------------------------------
# get_processing_status
# ---------------------------------------------------------------------------


class TestGetProcessingStatus:
    def test_returns_true_when_not_processing(self):
        with patch(
            "urllib.request.urlopen", return_value=_mock_response({"processing": False})
        ):
            done = get_processing_status("tok-123", base_url=BASE_URL, api_key=API_KEY)
        assert done is True

    def test_returns_false_when_still_processing(self):
        with patch(
            "urllib.request.urlopen", return_value=_mock_response({"processing": True})
        ):
            done = get_processing_status("tok-123", base_url=BASE_URL, api_key=API_KEY)
        assert done is False

    def test_http_error_raises(self):
        with patch("urllib.request.urlopen", side_effect=_mock_http_error(404)):
            with pytest.raises(DependencyTrackError) as exc_info:
                get_processing_status("bad-token", base_url=BASE_URL, api_key=API_KEY)
        assert exc_info.value.status == 404

    def test_correct_url_constructed(self):
        captured: list = []

        def fake_urlopen(req, timeout=None):
            captured.append(req.full_url)
            return _mock_response({"processing": False})

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            get_processing_status("my-token", base_url=BASE_URL, api_key=API_KEY)

        assert captured[0] == f"{BASE_URL}/api/v1/bom/token/my-token"


# ---------------------------------------------------------------------------
# lookup_project
# ---------------------------------------------------------------------------


class TestLookupProject:
    def test_returns_project_dict(self):
        project = {"uuid": "abc-123", "name": "myapp", "version": "1.0"}
        with patch("urllib.request.urlopen", return_value=_mock_response(project)):
            result = lookup_project("myapp", "1.0", base_url=BASE_URL, api_key=API_KEY)
        assert result == project

    def test_returns_none_on_404(self):
        with patch("urllib.request.urlopen", side_effect=_mock_http_error(404)):
            result = lookup_project(
                "missing", "0.0", base_url=BASE_URL, api_key=API_KEY
            )
        assert result is None

    def test_raises_on_other_http_errors(self):
        with patch(
            "urllib.request.urlopen", side_effect=_mock_http_error(403, "Forbidden")
        ):
            with pytest.raises(DependencyTrackError) as exc_info:
                lookup_project("p", "v", base_url=BASE_URL, api_key=API_KEY)
        assert exc_info.value.status == 403

    def test_url_contains_name_and_version(self):
        captured: list = []

        def fake_urlopen(req, timeout=None):
            captured.append(req.full_url)
            return _mock_response({"uuid": "x"})

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            lookup_project("my app", "1.2.3", base_url=BASE_URL, api_key=API_KEY)

        assert "name=my+app" in captured[0]
        assert "version=1.2.3" in captured[0]


# ---------------------------------------------------------------------------
# CLI integration — scan + upload flags
# ---------------------------------------------------------------------------


class TestCLIScanUpload:
    def test_scan_uploads_when_url_and_key_given(self, tmp_path):
        from click.testing import CliRunner
        from unravel_sbom.cli import cli

        fixtures = Path(__file__).parent / "fixtures"
        response_body = {"token": "cli-token-789"}

        with patch(
            "urllib.request.urlopen", return_value=_mock_response(response_body)
        ):
            runner = CliRunner(mix_stderr=False)
            result = runner.invoke(
                cli,
                [
                    "scan",
                    str(fixtures),
                    "-f",
                    "cyclonedx",
                    "-o",
                    str(tmp_path / "out.cdx.json"),
                    "--dtrack-url",
                    BASE_URL,
                    "--dtrack-key",
                    API_KEY,
                    "--dtrack-project",
                    "myapp",
                    "--dtrack-version",
                    "1.0.0",
                ],
            )

        assert result.exit_code == 0, result.stderr
        assert "cli-token-789" in result.stderr

    def test_upload_command_reads_existing_bom(self, tmp_path):
        from click.testing import CliRunner
        from unravel_sbom.cli import cli

        bom_file = tmp_path / "test.cdx.json"
        bom_file.write_text(json.dumps(SAMPLE_BOM))
        response_body = {"token": "upload-cmd-token"}

        with patch(
            "urllib.request.urlopen", return_value=_mock_response(response_body)
        ):
            runner = CliRunner(mix_stderr=False)
            result = runner.invoke(
                cli,
                [
                    "upload",
                    str(bom_file),
                    "--dtrack-url",
                    BASE_URL,
                    "--dtrack-key",
                    API_KEY,
                    "--dtrack-project",
                    "myapp",
                ],
            )

        assert result.exit_code == 0, result.stderr
        assert "upload-cmd-token" in result.stderr

    def test_upload_command_rejects_non_cyclonedx_file(self, tmp_path):
        from click.testing import CliRunner
        from unravel_sbom.cli import cli

        bad_file = tmp_path / "bad.json"
        bad_file.write_text(json.dumps({"spdxVersion": "SPDX-2.3"}))

        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(
            cli,
            [
                "upload",
                str(bad_file),
                "--url",
                BASE_URL,
                "--key",
                API_KEY,
            ],
        )
        assert result.exit_code != 0

    def test_scan_warns_when_only_url_given(self, tmp_path):
        from click.testing import CliRunner
        from unravel_sbom.cli import cli

        fixtures = Path(__file__).parent / "fixtures"
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(
            cli,
            [
                "scan",
                str(fixtures),
                "-f",
                "spdx",
                "-o",
                str(tmp_path / "out.spdx.json"),
                "--dtrack-url",
                BASE_URL,
                # missing --dtrack-key
            ],
        )
        assert result.exit_code == 0
        assert "--dtrack-key" in result.stderr
