"""Streamable HTTP extras: bearer auth and the raw sample-upload API."""

from __future__ import annotations

import hmac
import json
from collections.abc import Mapping
from email.message import Message
from typing import Any
from urllib.parse import unquote, urlparse

from zeromcp import McpHttpRequestHandler

from ida_mcp.uploads import (
    get_mcp_token,
    get_upload_max_bytes,
    get_upload_store,
    leased_database_paths,
    public_base_from_request,
    request_public_base_scope,
    sanitize_filename,
)


class IdaMcpHttpRequestHandler(McpHttpRequestHandler):
    """ZeroMCP handler plus ``/uploads`` and optional bearer authentication."""

    def send_cors_headers(self, *, preflight: bool = False) -> None:
        origin = self.headers.get("Origin", "")
        if not origin:
            return
        from zeromcp.mcp import _origin_allowed_by_policy

        if not _origin_allowed_by_policy(self.mcp_server.cors_allowed_origins, origin):
            return
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header(
            "Access-Control-Expose-Headers",
            "Mcp-Session-Id, MCP-Protocol-Version, WWW-Authenticate",
        )
        if preflight:
            methods = "POST, GET, DELETE, OPTIONS"
            headers = (
                "Content-Type, Accept, Authorization, X-Requested-With, "
                "Mcp-Session-Id, MCP-Protocol-Version, X-Filename"
            )
            self.send_header("Access-Control-Allow-Methods", methods)
            self.send_header("Access-Control-Allow-Headers", headers)
            if self.headers.get("Access-Control-Request-Private-Network") == "true":
                self.send_header("Access-Control-Allow-Private-Network", "true")

    def _body_limit(self) -> int:
        if self.command == "POST" and self._uploads_route() == ("collection", None):
            return get_upload_max_bytes()
        return self.mcp_server.post_body_limit

    def _request_body_framing(self) -> tuple[bool, int] | None:
        transfer_values = self.headers.get_all("Transfer-Encoding", [])
        length_values = self.headers.get_all("Content-Length", [])

        if transfer_values and length_values:
            self.close_connection = True
            self.send_error(400, "Conflicting request framing")
            return None

        if transfer_values:
            encodings = [
                item.strip().lower()
                for value in transfer_values
                for item in value.split(",")
                if item.strip()
            ]
            if encodings != ["chunked"]:
                self.close_connection = True
                self.send_error(400, "Unsupported Transfer-Encoding")
                return None
            return True, 0

        if len(length_values) > 1:
            self.close_connection = True
            self.send_error(400, "Ambiguous Content-Length")
            return None
        if not length_values:
            return False, 0

        length_text = length_values[0].strip(" \t")
        if not length_text or any(char not in "0123456789" for char in length_text):
            self.close_connection = True
            self.send_error(400, "Invalid Content-Length")
            return None

        normalized_length = length_text.lstrip("0") or "0"
        limit_text = str(self._body_limit())
        if len(normalized_length) > len(limit_text) or (
            len(normalized_length) == len(limit_text) and normalized_length > limit_text
        ):
            self._send_payload_too_large()
            return None
        return False, int(normalized_length)

    def _send_payload_too_large(self) -> None:
        self.close_connection = True
        self.send_error(413, f"Payload Too Large: exceeds {self._body_limit()} bytes")

    def _read_chunked(self) -> bytes | None:
        chunks: list[bytes] = []
        total = 0
        limit = self._body_limit()
        while True:
            line = self._readline_bounded(8192)
            if line is None:
                return None
            size_text = line.split(b";", 1)[0].strip()
            if not size_text or any(
                byte not in b"0123456789abcdefABCDEF" for byte in size_text
            ):
                self.close_connection = True
                self.send_error(400, "Malformed chunked encoding")
                return None
            chunk_size = int(size_text, 16)
            if chunk_size == 0:
                while True:
                    trailer = self._readline_bounded(8192)
                    if trailer is None:
                        return None
                    if trailer in (b"\r\n", b"\n"):
                        return b"".join(chunks)
            if total + chunk_size > limit:
                self._send_payload_too_large()
                return None
            chunk = self.rfile.read(chunk_size)
            if len(chunk) != chunk_size or self.rfile.read(2) != b"\r\n":
                self.close_connection = True
                self.send_error(400, "Malformed chunked encoding")
                return None
            chunks.append(chunk)
            total += chunk_size

    def _read_body(self) -> bytes | None:
        framing = self._request_body_framing()
        if framing is None:
            return None
        chunked, content_length = framing

        if chunked:
            raw = self._read_chunked()
            if raw is None:
                return None
        else:
            raw = self.rfile.read(content_length) if content_length else b""
            if len(raw) != content_length:
                self.close_connection = True
                self.send_error(400, "Truncated request body")
                return None

        if len(raw) > self._body_limit():
            self._send_payload_too_large()
            return None

        if self._uploads_route() == ("collection", None):
            return raw
        return self._decompress_body(raw)

    def handle_expect_100(self) -> bool:
        if not self._check_api_request():
            return False
        framing = self._request_body_framing()
        if framing is None:
            return False
        chunked, content_length = framing
        if self.command != "POST" and (chunked or content_length):
            self.send_error(400, "Request body is not allowed")
            return False
        path = urlparse(self.path).path
        if not self._check_bearer():
            return False
        ok, auth_info = self._check_oauth_for_path(path)
        if not ok:
            return False
        self._expect_auth = (path, auth_info)
        self.send_response_only(100)
        self.end_headers()
        return True

    def _check_bearer(self) -> bool:
        token = get_mcp_token()
        if token is None:
            return True
        auth = self.headers.get("Authorization", "")
        scheme, _, value = auth.partition(" ")
        provided = value.strip()
        if scheme.lower() != "bearer" or not provided:
            self._send_unauthorized("Authorization required")
            return False
        if not hmac.compare_digest(provided, token):
            self._send_unauthorized("Invalid access token")
            return False
        return True

    def _send_unauthorized(self, message: str) -> None:
        self.close_connection = True
        body = f"{message}\n".encode()
        self.send_response(401)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("WWW-Authenticate", 'Bearer realm="ida-mcp"')
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _uploads_route(self) -> tuple[str, str | None] | None:
        path = urlparse(self.path).path
        prefix = self.mcp_server.path_prefix
        candidates = [path]
        if prefix and path.startswith(f"{prefix}/"):
            candidates.append(path[len(prefix) :])
        for candidate in candidates:
            if candidate == "/uploads":
                return "collection", None
            if candidate.startswith("/uploads/"):
                rest = unquote(candidate[len("/uploads/") :])
                if rest:
                    return "item", rest
        return None

    def do_OPTIONS(self) -> None:
        if not self._check_api_request():
            return
        if self._has_unexpected_body():
            self.send_error(400, "Request body is not allowed")
            return
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.send_cors_headers(preflight=True)
        self.end_headers()

    def _forwarded_headers(self) -> dict[str, str]:
        names = (
            "Host",
            "Forwarded",
            "X-Forwarded-Host",
            "X-Forwarded-Proto",
            "X-Forwarded-Prefix",
        )
        return {name: self.headers.get(name, "") or "" for name in names}

    def _request_public_base(self) -> str | None:
        return public_base_from_request(
            self._forwarded_headers(),
            request_path=urlparse(self.path).path,
            path_prefix=self.mcp_server.path_prefix,
        )

    def do_GET(self) -> None:
        with request_public_base_scope(self._request_public_base()):
            self._do_GET()

    def _do_GET(self) -> None:
        route = self._uploads_route()
        if route == ("collection", None):
            if not self._check_api_request():
                return
            if self._has_unexpected_body():
                self.send_error(400, "Request body is not allowed")
                return
            if not self._check_bearer():
                return
            self._send_json(200, get_upload_store().list_uploads())
            return
        if not self._check_bearer():
            return
        super().do_GET()

    def do_POST(self) -> None:
        with request_public_base_scope(self._request_public_base()):
            self._do_POST()

    def _do_POST(self) -> None:
        if self._uploads_route() == ("collection", None):
            if not self._check_api_request():
                return
            if not self._check_bearer():
                return
            body = self._read_body()
            if body is None:
                return
            self._handle_post_upload(body)
            return
        if not self._check_bearer():
            return
        super().do_POST()

    def do_DELETE(self) -> None:
        with request_public_base_scope(self._request_public_base()):
            self._do_DELETE()

    def _do_DELETE(self) -> None:
        route = self._uploads_route()
        if route is not None and route[0] == "item":
            if not self._check_api_request():
                return
            if self._has_unexpected_body():
                self.send_error(400, "Request body is not allowed")
                return
            if not self._check_bearer():
                return
            self._handle_delete_upload(route[1] or "")
            return
        if not self._check_bearer():
            return
        super().do_DELETE()

    def _handle_post_upload(self, body: bytes) -> None:
        try:
            filename, payload = _parse_upload_body(self.headers, body)
            result = get_upload_store().store_bytes(filename, payload)
        except ValueError as error:
            self._send_json(400, {"error": str(error)})
            return
        self._send_json(200, result)

    def _handle_delete_upload(self, upload_id: str) -> None:
        from ida_mcp.mcp import DATABASE_MANAGER

        try:
            result = get_upload_store().delete(
                upload_id,
                leased_paths=leased_database_paths(DATABASE_MANAGER),
            )
        except ValueError as error:
            status = 409 if "lease" in str(error) else 400
            self._send_json(status, {"error": str(error)})
            return
        self._send_json(200, result)

    def _send_json(self, status: int, payload: Mapping[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(body)


def _header_filename(headers: Message) -> str:
    raw = headers.get("X-Filename")
    if isinstance(raw, str) and raw.strip():
        return raw
    return "sample.bin"


def _parse_upload_body(headers: Message, body: bytes) -> tuple[str, bytes]:
    content_type = headers.get("Content-Type", "")
    if isinstance(content_type, str) and content_type.lower().startswith(
        "multipart/form-data"
    ):
        return _parse_multipart_file(content_type, body)
    return sanitize_filename(_header_filename(headers)), body


def _content_type_boundary(content_type: str) -> bytes:
    message = Message()
    message["Content-Type"] = content_type
    boundary = message.get_param("boundary", header="Content-Type")
    if not isinstance(boundary, str) or not boundary:
        raise ValueError("multipart body is missing a boundary")
    return boundary.encode("ascii", "strict")


def _parse_multipart_file(content_type: str, body: bytes) -> tuple[str, bytes]:
    boundary = _content_type_boundary(content_type)
    delimiter = b"--" + boundary
    for part in body.split(delimiter):
        if part.startswith(b"\r\n"):
            part = part[2:]
        if not part or part == b"--" or part.startswith(b"--"):
            continue
        header_blob, separator, payload = part.partition(b"\r\n\r\n")
        if not separator:
            continue
        header_message = Message()
        for line in header_blob.decode("utf-8", "replace").split("\r\n"):
            if ":" in line:
                name, value = line.split(":", 1)
                header_message[name.strip()] = value.strip()
        disposition = header_message.get("Content-Disposition", "")
        if _disposition_name(disposition) != "file":
            continue
        filename = sanitize_filename(_disposition_filename(disposition))
        if payload.endswith(b"\r\n"):
            payload = payload[:-2]
        return filename, payload
    raise ValueError("multipart body has no file field")


def _disposition_name(disposition: str) -> str | None:
    message = Message()
    message["Content-Disposition"] = disposition
    name = message.get_param("name", header="Content-Disposition")
    return name if isinstance(name, str) else None


def _disposition_filename(disposition: str) -> str:
    message = Message()
    message["Content-Disposition"] = disposition
    filename = message.get_param("filename", header="Content-Disposition")
    return filename if isinstance(filename, str) else "sample.bin"
