from __future__ import annotations

import hashlib
import json
import socket
import stat
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
from ida_nexus.options import DatabaseOpenOptions
from zeromcp import McpToolError

from ida_mcp import mcp as mcp_api
from ida_mcp import uploads as uploads_api
from ida_mcp.uploads import UploadStore, sanitize_filename


@pytest.fixture
def inbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    path = tmp_path / "inbox"
    monkeypatch.setenv("IDA_MCP_INBOX", str(path))
    monkeypatch.delenv(uploads_api.TOKEN_ENVIRONMENT_VARIABLE, raising=False)
    monkeypatch.delenv(uploads_api.UPLOAD_MAX_BYTES_ENVIRONMENT_VARIABLE, raising=False)
    uploads_api.reset_upload_store()
    monkeypatch.setattr(
        mcp_api,
        "TRACE",
        SimpleNamespace(path=tmp_path / "trace.jsonl", emit=Mock()),
    )
    yield path
    uploads_api.reset_upload_store()
    uploads_api.clear_http_bind()
    mcp_api.mcp.stop()
    mcp_api.stop_http_server()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _http_json(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(url, data=data, method=method)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            body = response.read().decode("utf-8")
            payload = json.loads(body) if body else {}
            return response.status, payload
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8")
        try:
            payload = json.loads(raw) if raw else {"error": raw}
        except json.JSONDecodeError:
            payload = {"error": raw}
        return error.code, payload


def test_sanitize_filename_strips_path_components() -> None:
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("..\\..\\windows\\system32\\cmd.exe") == "cmd.exe"
    assert sanitize_filename("") == "sample.bin"
    assert sanitize_filename("..") == "sample.bin"
    assert sanitize_filename("/") == "sample.bin"


def test_upload_rejects_path_escape_via_upload_id(inbox: Path) -> None:
    store = UploadStore(inbox)
    with pytest.raises(ValueError, match="upload_id"):
        store.write_chunk("../etc/passwd", 0, b"x")
    with pytest.raises(ValueError, match="upload_id"):
        store.delete("../../etc/passwd")


def test_chunked_upload_lands_inside_inbox(inbox: Path) -> None:
    store = UploadStore(inbox)
    payload = b"MZ\x00IDA"
    begun = store.begin("../../tmp/evil.bin", len(payload), _sha256(payload))
    store.write_chunk(begun["upload_id"], 0, payload)
    finished = store.finish(begun["upload_id"])

    path = Path(finished["path"])
    assert path.resolve().is_relative_to(inbox.resolve())
    assert path.name == "evil.bin"
    assert path.read_bytes() == payload
    assert finished["size"] == len(payload)
    assert finished["sha256"] == _sha256(payload)
    assert (path.stat().st_mode & 0o111) == 0
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(inbox.stat().st_mode) == 0o700


def test_upload_chunk_retries_overwrite_the_same_range(inbox: Path) -> None:
    store = UploadStore(inbox)
    begun = store.begin("sample.bin", 4)
    store.write_chunk(begun["upload_id"], 0, b"xxxx")
    store.write_chunk(begun["upload_id"], 0, b"ABCD")
    finished = store.finish(begun["upload_id"])
    assert Path(finished["path"]).read_bytes() == b"ABCD"


def test_upload_rejects_oversize_and_oversize_chunks(
    inbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(uploads_api.UPLOAD_MAX_BYTES_ENVIRONMENT_VARIABLE, "8")
    store = UploadStore(inbox)
    with pytest.raises(ValueError, match="exceeds limit"):
        store.begin("sample.bin", 9)

    begun = store.begin("sample.bin", 8)
    too_big = b"x" * (uploads_api.MAX_CHUNK_BYTES + 1)
    with pytest.raises(ValueError, match="max_chunk_bytes"):
        store.write_chunk(begun["upload_id"], 0, too_big)
    with pytest.raises(ValueError, match="declared"):
        store.write_chunk(begun["upload_id"], 0, b"012345678")


def test_upload_finish_rejects_sha256_mismatch(inbox: Path) -> None:
    store = UploadStore(inbox)
    payload = b"sample-bytes"
    begun = store.begin("sample.bin", len(payload), "0" * 64)
    store.write_chunk(begun["upload_id"], 0, payload)
    with pytest.raises(ValueError, match="sha256 mismatch"):
        store.finish(begun["upload_id"])
    with pytest.raises(ValueError, match="sha256 mismatch"):
        store.finish(begun["upload_id"], sha256="1" * 64)


def test_unfinished_upload_survives_store_reopen(inbox: Path) -> None:
    first = UploadStore(inbox)
    payload = b"abcd"
    begun = first.begin("resume.bin", len(payload))
    first.write_chunk(begun["upload_id"], 0, b"ab")

    second = UploadStore(inbox)
    listed = second.list_uploads()["uploads"]
    assert listed[0]["upload_id"] == begun["upload_id"]
    assert listed[0]["status"] == "pending"
    second.write_chunk(begun["upload_id"], 2, b"cd")
    finished = second.finish(begun["upload_id"])
    assert Path(finished["path"]).read_bytes() == payload
    assert second.list_uploads()["uploads"][0]["status"] == "complete"


def test_delete_upload_refuses_leased_inbox_path(inbox: Path) -> None:
    store = UploadStore(inbox)
    payload = b"leased"
    begun = store.begin("held.bin", len(payload))
    store.write_chunk(begun["upload_id"], 0, payload)
    finished = store.finish(begun["upload_id"])

    with pytest.raises(ValueError, match="close_database"):
        store.delete(begun["upload_id"], leased_paths=[finished["path"]])
    assert Path(finished["path"]).is_file()

    deleted = store.delete(begun["upload_id"], leased_paths=["/tmp/other.bin"])
    assert deleted["deleted"] is True
    assert not Path(finished["path"]).exists()


def test_upload_info_is_unavailable_without_http(inbox: Path) -> None:
    info = mcp_api.upload_info()
    assert info["available"] is False
    assert info["url"] is None
    assert "ida-mcp http" in info["hint"]
    assert "secret" not in json.dumps(info)


def test_http_upload_then_confirm_is_usable_by_open_database(
    inbox: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mcp_api, "_HTTP_SERVER_STARTED", False)
    port = _free_port()
    mcp_api.serve_http("127.0.0.1", port, background=True)
    try:
        _wait_for_port(port)
        info = mcp_api.upload_info()
        assert info["available"] is True
        assert info["url"] == f"http://127.0.0.1:{port}/uploads"
        assert info["method"] == "POST"
        assert info["auth_required"] is False
        assert "Bearer" not in info["curl"]
        assert "secret-token" not in json.dumps(info)

        payload = b"\x7fELFsample"
        status, posted = _http_json(
            info["url"] or "",
            method="POST",
            data=payload,
            headers={
                "X-Filename": "remote.elf",
                "Content-Type": "application/octet-stream",
            },
        )
        assert status == 200
        confirmed = mcp_api.confirm_upload(posted["upload_id"], posted["sha256"])
        path = Path(confirmed["path"])
        assert path.resolve().is_relative_to(inbox.resolve())
        assert path.read_bytes() == payload

        manager = Mock()
        manager.open_database.return_value = {
            "instance_id": "worker-1",
            "backend": "idalib",
            "status": "current",
            "recovery": "none",
        }
        monkeypatch.setattr(mcp_api, "DATABASE_MANAGER", manager)
        opened = mcp_api.open_database(confirmed["path"])
        assert opened["instance_id"] == "worker-1"
        manager.open_database.assert_called_once_with(
            confirmed["path"],
            set_current=True,
            options=DatabaseOpenOptions(),
        )
    finally:
        mcp_api.stop_http_server()


def test_upload_info_does_not_return_token(
    inbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(uploads_api.TOKEN_ENVIRONMENT_VARIABLE, "secret-token")
    info = mcp_api.upload_info()
    dumped = json.dumps(info)
    assert "secret-token" not in dumped
    assert info["auth_required"] is True
    if info["curl"]:
        assert "$IDA_MCP_TOKEN" in info["curl"]


def test_confirm_upload_rejects_sha256_mismatch(inbox: Path) -> None:
    stored = UploadStore(inbox).store_bytes("sample.bin", b"abc")
    with pytest.raises(McpToolError, match="sha256 mismatch"):
        mcp_api.confirm_upload(stored["upload_id"], "0" * 64)


def test_upload_tools_are_registered_after_existing_tools() -> None:
    names = [tool["name"] for tool in mcp_api.mcp._mcp_tools_list()["tools"]]
    assert names[:6] == [
        "open_database",
        "execute_python",
        "reference",
        "list_databases",
        "save_database",
        "close_database",
    ]
    for name in (
        "upload_info",
        "confirm_upload",
        "list_uploads",
        "delete_upload",
    ):
        assert name in names
    for name in ("upload_begin", "upload_chunk", "upload_finish"):
        assert name not in names


def test_non_loopback_http_requires_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(uploads_api.TOKEN_ENVIRONMENT_VARIABLE, raising=False)
    with pytest.raises(ValueError, match="IDA_MCP_TOKEN"):
        mcp_api.serve_http("0.0.0.0", 18737)


def test_http_uploads_and_mcp_share_port(
    inbox: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mcp_api, "_HTTP_SERVER_STARTED", False)
    port = _free_port()
    mcp_api.serve_http("127.0.0.1", port, background=True)
    try:
        _wait_for_port(port)
        payload = b"http-sample"
        status, body = _http_json(
            f"http://127.0.0.1:{port}/uploads",
            method="POST",
            data=payload,
            headers={
                "X-Filename": "via-http.bin",
                "Content-Type": "application/octet-stream",
            },
        )
        assert status == 200
        assert body["size"] == len(payload)
        assert body["sha256"] == _sha256(payload)
        assert Path(body["path"]).resolve().is_relative_to(inbox.resolve())
        assert _payload_hides_secrets(body)

        listed_status, listed = _http_json(f"http://127.0.0.1:{port}/uploads")
        assert listed_status == 200
        assert listed["uploads"][0]["upload_id"] == body["upload_id"]
        confirmed = mcp_api.confirm_upload(body["upload_id"])
        assert confirmed["path"] == body["path"]

        mcp_status, mcp_body = _http_json(
            f"http://127.0.0.1:{port}/mcp",
            method="POST",
            data=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "initialize",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "upload-test", "version": "1.0"},
                    },
                }
            ).encode(),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        assert mcp_status == 200
        assert mcp_body["result"]["serverInfo"]["name"] == "ida"

        deleted_status, deleted = _http_json(
            f"http://127.0.0.1:{port}/uploads/{body['upload_id']}",
            method="DELETE",
        )
        assert deleted_status == 200
        assert deleted["deleted"] is True
    finally:
        mcp_api.stop_http_server()


def test_http_multipart_upload(inbox: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp_api, "_HTTP_SERVER_STARTED", False)
    port = _free_port()
    mcp_api.serve_http("127.0.0.1", port, background=True)
    try:
        _wait_for_port(port)
        boundary = "----ida-mcp-test"
        payload = b"PE\x00\x00"
        body = (
            (
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="file"; filename="app.exe"\r\n'
                "Content-Type: application/octet-stream\r\n"
                "\r\n"
            ).encode()
            + payload
            + f"\r\n--{boundary}--\r\n".encode()
        )
        status, result = _http_json(
            f"http://127.0.0.1:{port}/uploads",
            method="POST",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        assert status == 200
        assert Path(result["path"]).name == "app.exe"
        assert Path(result["path"]).read_bytes() == payload
    finally:
        mcp_api.stop_http_server()


def test_token_rejects_uploads_and_mcp_without_bearer(
    inbox: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(uploads_api.TOKEN_ENVIRONMENT_VARIABLE, "secret-token")
    monkeypatch.setattr(mcp_api, "_HTTP_SERVER_STARTED", False)
    port = _free_port()
    mcp_api.serve_http("127.0.0.1", port, background=True)
    try:
        _wait_for_port(port)
        denied, denied_body = _http_json(f"http://127.0.0.1:{port}/uploads")
        assert denied == 401
        assert "secret-token" not in json.dumps(denied_body)

        mcp_denied, mcp_denied_body = _http_json(
            f"http://127.0.0.1:{port}/mcp",
            method="POST",
            data=b"{}",
            headers={"Content-Type": "application/json"},
        )
        assert mcp_denied == 401
        assert "secret-token" not in json.dumps(mcp_denied_body)

        allowed, listed = _http_json(
            f"http://127.0.0.1:{port}/uploads",
            headers={"Authorization": "Bearer secret-token"},
        )
        assert allowed == 200
        assert listed["uploads"] == []
        assert "secret-token" not in json.dumps(listed)
    finally:
        mcp_api.stop_http_server()


def test_http_delete_rejects_path_traversal(
    inbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mcp_api, "_HTTP_SERVER_STARTED", False)
    port = _free_port()
    mcp_api.serve_http("127.0.0.1", port, background=True)
    try:
        _wait_for_port(port)
        status, body = _http_json(
            f"http://127.0.0.1:{port}/uploads/..%2F..%2Fetc%2Fpasswd",
            method="DELETE",
        )
        assert status in {400, 404}
        assert "error" in body
    finally:
        mcp_api.stop_http_server()


def _payload_hides_secrets(payload: dict[str, Any]) -> bool:
    dumped = json.dumps(payload)
    return "secret-token" not in dumped and "IDA_MCP_TOKEN" not in dumped


def _wait_for_port(port: int) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"HTTP server did not start on port {port}")


def test_delete_upload_tool_uses_lease_paths(
    inbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b"open-me"
    stored = UploadStore(inbox).store_bytes("held.bin", payload)
    manager = Mock()
    manager.list_databases.return_value = {"instances": [{"path": stored["path"]}]}
    manager._instances = {}
    monkeypatch.setattr(mcp_api, "DATABASE_MANAGER", manager)
    with pytest.raises(McpToolError, match="close_database"):
        mcp_api.delete_upload(stored["upload_id"])


def test_uuid_directory_layout(inbox: Path) -> None:
    store = UploadStore(inbox)
    begun = store.begin("nested/name.bin", 1)
    uuid.UUID(begun["upload_id"], version=4)
    store.write_chunk(begun["upload_id"], 0, b"A")
    finished = store.finish(begun["upload_id"])
    path = Path(finished["path"])
    assert path.parent.name == begun["upload_id"]
    assert path.parent.parent == inbox.resolve()
    assert path.name == "name.bin"
