from __future__ import annotations

import base64
import hashlib
import json
import socket
import stat
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
    monkeypatch.delenv(uploads_api.PUBLIC_URL_ENVIRONMENT_VARIABLE, raising=False)
    monkeypatch.delenv(uploads_api.WEBDAV_URL_ENVIRONMENT_VARIABLE, raising=False)
    monkeypatch.delenv(uploads_api.WEBDAV_USER_ENVIRONMENT_VARIABLE, raising=False)
    monkeypatch.delenv(uploads_api.WEBDAV_PASSWORD_ENVIRONMENT_VARIABLE, raising=False)
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
    assert info["path"] == ""
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
        assert info["path"] == "/uploads"
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


def test_public_base_from_request_uses_forwarded_headers() -> None:
    assert (
        uploads_api.public_base_from_request(
            {
                "Host": "127.0.0.1:8737",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "ida.example.com",
            },
            request_path="/mcp",
        )
        == "https://ida.example.com"
    )
    assert (
        uploads_api.public_base_from_request(
            {
                "Host": "127.0.0.1:8737",
                "Forwarded": 'for=10.0.0.1;proto=https;host="ida.example.com"',
            },
            request_path="/mcp",
        )
        == "https://ida.example.com"
    )
    assert (
        uploads_api.public_base_from_request(
            {
                "Host": "127.0.0.1:8737",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "ida.example.com",
                "X-Forwarded-Prefix": "/hex-rays",
            },
            request_path="/mcp",
        )
        == "https://ida.example.com/hex-rays"
    )
    assert (
        uploads_api.public_base_from_request(
            {"Host": "127.0.0.1:8737"},
            request_path="/hex-rays/mcp",
            path_prefix="/hex-rays",
        )
        == "http://127.0.0.1:8737/hex-rays"
    )
    assert (
        uploads_api.public_base_from_request(
            {"Host": "evil.example/steal"},
            request_path="/mcp",
        )
        is None
    )


def test_upload_info_skips_wildcard_bind_without_request(inbox: Path) -> None:
    uploads_api.set_http_bind("0.0.0.0", 8737)
    info = mcp_api.upload_info()
    assert info["available"] is True
    assert info["url"] is None
    assert info["path"] == "/uploads"
    assert "$MCP_ORIGIN/uploads" in info["curl"]


def test_upload_info_uses_request_origin_behind_proxy(inbox: Path) -> None:
    uploads_api.set_http_bind("0.0.0.0", 8737)
    with uploads_api.request_public_base_scope("https://ida.example.com"):
        info = mcp_api.upload_info()
    assert info["url"] == "https://ida.example.com/uploads"
    assert info["path"] == "/uploads"


def test_upload_info_keeps_path_prefix_in_url_and_path(inbox: Path) -> None:
    uploads_api.set_http_bind("127.0.0.1", 8737, "/hex-rays")
    with uploads_api.request_public_base_scope("https://ida.example.com/hex-rays"):
        info = mcp_api.upload_info()
    assert info["url"] == "https://ida.example.com/hex-rays/uploads"
    assert info["path"] == "/hex-rays/uploads"


def test_upload_info_public_url_overrides_forwarded_origin(
    inbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        uploads_api.PUBLIC_URL_ENVIRONMENT_VARIABLE,
        "https://forced.example/ida",
    )
    uploads_api.set_http_bind("127.0.0.1", 8737)
    with uploads_api.request_public_base_scope("https://ida.example.com"):
        info = mcp_api.upload_info()
    assert info["url"] == "https://forced.example/ida/uploads"
    assert info["path"] == "/ida/uploads"


def test_upload_info_ignores_invalid_public_url(
    inbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(uploads_api.PUBLIC_URL_ENVIRONMENT_VARIABLE, "not-a-url")
    uploads_api.set_http_bind("127.0.0.1", 8737)
    info = mcp_api.upload_info()
    assert info["url"] == "http://127.0.0.1:8737/uploads"


def _mcp_structured_tool(
    port: int,
    name: str,
    *,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    request_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    request_headers.update(headers or {})
    status, body = _http_json(
        f"http://127.0.0.1:{port}/mcp",
        method="POST",
        data=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": name,
                "method": "tools/call",
                "params": {"name": name, "arguments": {}},
            }
        ).encode(),
        headers=request_headers,
    )
    assert status == 200, body
    assert "error" not in body, body
    result = body["result"]
    assert result["isError"] is False
    structured = result["structuredContent"]
    assert isinstance(structured, dict)
    return structured


def test_upload_info_http_call_uses_forwarded_headers(
    inbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mcp_api, "_HTTP_SERVER_STARTED", False)
    port = _free_port()
    mcp_api.serve_http("127.0.0.1", port, background=True)
    try:
        _wait_for_port(port)
        info = _mcp_structured_tool(
            port,
            "upload_info",
            headers={
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "ida.example.com",
            },
        )
        assert info["available"] is True
        assert info["url"] == "https://ida.example.com/uploads"
        assert info["path"] == "/uploads"
        assert "secret-token" not in json.dumps(info)

        via_host = _mcp_structured_tool(port, "upload_info")
        assert via_host["url"] == f"http://127.0.0.1:{port}/uploads"
    finally:
        mcp_api.stop_http_server()


def test_upload_info_http_call_public_url_overrides_host(
    inbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        uploads_api.PUBLIC_URL_ENVIRONMENT_VARIABLE, "https://forced.example"
    )
    monkeypatch.setattr(mcp_api, "_HTTP_SERVER_STARTED", False)
    port = _free_port()
    mcp_api.serve_http("127.0.0.1", port, background=True)
    try:
        _wait_for_port(port)
        info = _mcp_structured_tool(
            port,
            "upload_info",
            headers={
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "ida.example.com",
            },
        )
        assert info["url"] == "https://forced.example/uploads"
    finally:
        mcp_api.stop_http_server()


def _start_webdav(
    objects: dict[str, bytes],
    *,
    user: str | None = None,
    password: str = "",
    oversize_path: str | None = None,
) -> tuple[str, ThreadingHTTPServer]:
    port = _free_port()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if user is not None:
                token = base64.b64encode(f"{user}:{password}".encode()).decode()
                if self.headers.get("Authorization") != f"Basic {token}":
                    self.send_response(401)
                    self.end_headers()
                    return
            if self.path.endswith("/redirect"):
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/stolen")
                self.end_headers()
                return
            if oversize_path is not None and self.path == oversize_path:
                self.send_response(200)
                self.send_header("Content-Length", "9")
                self.end_headers()
                self.wfile.write(b"012345678")
                return
            payload = objects.get(self.path)
            if payload is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{port}", server


def test_webdav_object_url_stays_under_configured_prefix(
    inbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        uploads_api.WEBDAV_URL_ENVIRONMENT_VARIABLE,
        "https://dav.example.com/ida-inbox/",
    )
    assert (
        uploads_api.webdav_object_url("sample.elf")
        == "https://dav.example.com/ida-inbox/sample.elf"
    )
    assert (
        uploads_api.webdav_object_url("../etc/passwd")
        == "https://dav.example.com/ida-inbox/passwd"
    )
    with pytest.raises(ValueError, match="filename, not a URL"):
        uploads_api.webdav_object_url("https://evil.example/sample.elf")
    with pytest.raises(ValueError, match="filename, not a URL"):
        uploads_api.webdav_object_url("//evil.example/sample.elf")


def test_upload_info_advertises_webdav_put_without_secrets(
    inbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        uploads_api.WEBDAV_URL_ENVIRONMENT_VARIABLE,
        "https://dav.example.com/ida-inbox",
    )
    monkeypatch.setenv(uploads_api.WEBDAV_USER_ENVIRONMENT_VARIABLE, "dav-user")
    monkeypatch.setenv(uploads_api.WEBDAV_PASSWORD_ENVIRONMENT_VARIABLE, "dav-secret")
    info = mcp_api.upload_info()
    dumped = json.dumps(info)
    assert info["available"] is True
    assert info["method"] == "PUT"
    assert info["url"] == "https://dav.example.com/ida-inbox"
    assert info["path"] == "/ida-inbox"
    assert info["auth_required"] is True
    assert "-T sample.bin" in info["curl"]
    assert "$IDA_MCP_WEBDAV_PASSWORD" in info["curl"]
    assert "dav-secret" not in dumped
    assert "dav-user" not in dumped


def test_confirm_upload_pulls_webdav_object_into_inbox(
    inbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b"MZ-from-dav"
    origin, server = _start_webdav({"/ida-inbox/sample.elf": payload})
    monkeypatch.setenv(
        uploads_api.WEBDAV_URL_ENVIRONMENT_VARIABLE, f"{origin}/ida-inbox"
    )
    try:
        confirmed = mcp_api.confirm_upload("sample.elf")
        path = Path(confirmed["path"])
        assert path.resolve().is_relative_to(inbox.resolve())
        assert path.name == "sample.elf"
        assert path.read_bytes() == payload
        assert confirmed["size"] == len(payload)
        assert confirmed["sha256"] == _sha256(payload)
    finally:
        server.shutdown()
        server.server_close()


def test_confirm_upload_rejects_webdav_url_and_redirect(
    inbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    origin, server = _start_webdav({})
    monkeypatch.setenv(
        uploads_api.WEBDAV_URL_ENVIRONMENT_VARIABLE, f"{origin}/ida-inbox"
    )
    try:
        with pytest.raises(McpToolError, match="filename, not a URL"):
            mcp_api.confirm_upload("https://evil.example/sample.elf")
        with pytest.raises(McpToolError, match="redirect"):
            mcp_api.confirm_upload("redirect")
    finally:
        server.shutdown()
        server.server_close()


def test_confirm_upload_webdav_enforces_size_and_sha256(
    inbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    origin, server = _start_webdav(
        {},
        oversize_path="/ida-inbox/too-big.bin",
    )
    monkeypatch.setenv(
        uploads_api.WEBDAV_URL_ENVIRONMENT_VARIABLE, f"{origin}/ida-inbox"
    )
    monkeypatch.setenv(uploads_api.UPLOAD_MAX_BYTES_ENVIRONMENT_VARIABLE, "8")
    try:
        with pytest.raises(McpToolError, match="exceeds limit"):
            mcp_api.confirm_upload("too-big.bin")
        origin2, server2 = _start_webdav({"/ida-inbox/sample.bin": b"abc"})
        monkeypatch.setenv(
            uploads_api.WEBDAV_URL_ENVIRONMENT_VARIABLE, f"{origin2}/ida-inbox"
        )
        try:
            with pytest.raises(McpToolError, match="sha256 mismatch"):
                mcp_api.confirm_upload("sample.bin", "0" * 64)
        finally:
            server2.shutdown()
            server2.server_close()
    finally:
        server.shutdown()
        server.server_close()


def test_confirm_upload_prefers_local_inbox_over_webdav(
    inbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stored = UploadStore(inbox).store_bytes("local.bin", b"local-bytes")
    origin, server = _start_webdav({f"/ida-inbox/{stored['upload_id']}": b"from-dav"})
    monkeypatch.setenv(
        uploads_api.WEBDAV_URL_ENVIRONMENT_VARIABLE, f"{origin}/ida-inbox"
    )
    try:
        confirmed = mcp_api.confirm_upload(stored["upload_id"])
        assert Path(confirmed["path"]).read_bytes() == b"local-bytes"
    finally:
        server.shutdown()
        server.server_close()


def test_webdav_get_sends_basic_auth(
    inbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b"auth-ok"
    origin, server = _start_webdav(
        {"/ida-inbox/held.bin": payload},
        user="dav-user",
        password="dav-secret",
    )
    monkeypatch.setenv(
        uploads_api.WEBDAV_URL_ENVIRONMENT_VARIABLE, f"{origin}/ida-inbox"
    )
    monkeypatch.setenv(uploads_api.WEBDAV_USER_ENVIRONMENT_VARIABLE, "dav-user")
    monkeypatch.setenv(uploads_api.WEBDAV_PASSWORD_ENVIRONMENT_VARIABLE, "dav-secret")
    try:
        confirmed = mcp_api.confirm_upload("held.bin")
        assert Path(confirmed["path"]).read_bytes() == payload
        monkeypatch.setenv(uploads_api.WEBDAV_PASSWORD_ENVIRONMENT_VARIABLE, "wrong")
        with pytest.raises(McpToolError, match="authentication failed"):
            mcp_api.confirm_upload("held.bin")
    finally:
        server.shutdown()
        server.server_close()
