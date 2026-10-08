"""Server-local sample inbox for remote MCP agents and HTTP clients.

Remote agents cannot reach files on their own disks through ``open_database``.
Uploads land under the inbox as ``<upload_id>/<filename>`` so the returned
absolute path can be passed to the existing open tool unchanged.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import threading
import uuid
from collections.abc import Iterable
from contextlib import suppress
from pathlib import Path
from typing import TypedDict

from ida_mcp.paths import get_mcp_inbox_dir

TOKEN_ENVIRONMENT_VARIABLE = "IDA_MCP_TOKEN"
UPLOAD_MAX_BYTES_ENVIRONMENT_VARIABLE = "IDA_MCP_UPLOAD_MAX_BYTES"

MAX_CHUNK_BYTES = 1 * 1024 * 1024
DEFAULT_UPLOAD_MAX_BYTES = 256 * 1024 * 1024
DEFAULT_SAMPLE_FILENAME = "sample.bin"
_UPLOAD_ID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_META_NAME = "meta.json"

_STORE: UploadStore | None = None
_STORE_LOCK = threading.Lock()


class UploadBeginResult(TypedDict):
    upload_id: str
    max_chunk_bytes: int


class UploadChunkResult(TypedDict):
    upload_id: str
    offset: int
    written: int
    received_size: int


class UploadFinishResult(TypedDict):
    path: str
    size: int
    sha256: str


class StoredUploadResult(UploadFinishResult):
    upload_id: str


class UploadListItem(TypedDict):
    upload_id: str
    filename: str
    path: str
    size: int
    declared_size: int
    sha256: str | None
    status: str


class ListUploadsResult(TypedDict):
    uploads: list[UploadListItem]


class DeleteUploadResult(TypedDict):
    deleted: bool
    upload_id: str


def get_mcp_token() -> str | None:
    """Return the configured bearer token, or None when HTTP auth is disabled."""
    token = os.environ.get(TOKEN_ENVIRONMENT_VARIABLE)
    if token is None or not token.strip():
        return None
    return token


def get_upload_max_bytes() -> int:
    raw_value = os.environ.get(UPLOAD_MAX_BYTES_ENVIRONMENT_VARIABLE)
    if raw_value is None or not raw_value.strip():
        return DEFAULT_UPLOAD_MAX_BYTES
    try:
        value = int(raw_value, 10)
    except ValueError as exc:
        raise ValueError(
            f"{UPLOAD_MAX_BYTES_ENVIRONMENT_VARIABLE} must be an integer"
        ) from exc
    if value <= 0:
        raise ValueError(f"{UPLOAD_MAX_BYTES_ENVIRONMENT_VARIABLE} must be positive")
    return value


def sanitize_filename(filename: str | None) -> str:
    """Keep a basename only; drop separators and ``..``; empty names become sample.bin."""
    raw = "" if filename is None else str(filename).replace("\x00", "")
    normalized = raw.replace("\\", "/")
    name = posixpath.basename(normalized)
    name = name.replace("/", "").replace("\\", "")
    if name in {"", ".", ".."} or name.replace(".", "") == "":
        return DEFAULT_SAMPLE_FILENAME
    if ".." in name:
        name = name.replace("..", "")
    name = name.strip(" .")
    return name or DEFAULT_SAMPLE_FILENAME


def parse_upload_id(upload_id: str) -> str:
    if not isinstance(upload_id, str) or not _UPLOAD_ID_PATTERN.fullmatch(upload_id):
        raise ValueError("upload_id must be a UUID4")
    return str(uuid.UUID(upload_id))


def normalize_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    digest = value.strip().lower()
    if not digest:
        return None
    if not _SHA256_PATTERN.fullmatch(digest):
        raise ValueError("sha256 must be a 64-character hex digest")
    return digest


def ensure_directory(path: Path, mode: int = 0o700) -> Path:
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    try:
        os.chmod(path, mode)
    except OSError:
        if os.name != "nt":
            raise
    return path


def ensure_inbox_dir(inbox: Path | None = None) -> Path:
    return ensure_directory(Path(inbox) if inbox is not None else get_mcp_inbox_dir())


def realpath(path: Path | str) -> Path:
    return Path(os.path.realpath(os.path.abspath(os.fspath(path))))


def path_is_inside(path: Path, directory: Path) -> bool:
    real_path = realpath(path)
    real_directory = realpath(directory)
    return real_path == real_directory or real_path.is_relative_to(real_directory)


def assert_inside_inbox(path: Path, inbox: Path) -> Path:
    real_path = realpath(path)
    if not path_is_inside(real_path, inbox):
        raise ValueError("upload path escapes the inbox")
    return real_path


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(MAX_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict[str, object]) -> None:
    encoded = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        with suppress(OSError):
            tmp.unlink()
        raise
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def create_private_file(path: Path) -> None:
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    os.close(fd)
    os.chmod(path, 0o600)


class UploadStore:
    """Filesystem-backed inbox. Unfinished uploads survive process restart."""

    def __init__(self, inbox: Path | None = None) -> None:
        self.inbox = ensure_inbox_dir(inbox)
        self._lock = threading.Lock()

    def begin(
        self,
        filename: str,
        size: int,
        sha256: str | None = None,
    ) -> UploadBeginResult:
        declared_size = _require_non_negative_int(size, "size")
        max_bytes = get_upload_max_bytes()
        if declared_size > max_bytes:
            raise ValueError(
                f"upload size {declared_size} exceeds limit of {max_bytes} bytes"
            )
        safe_name = sanitize_filename(filename)
        expected = normalize_sha256(sha256)
        upload_id = str(uuid.uuid4())
        with self._lock:
            upload_dir = self._create_upload_dir(upload_id)
            sample_path = assert_inside_inbox(upload_dir / safe_name, self.inbox)
            create_private_file(sample_path)
            self._write_meta(
                upload_dir,
                {
                    "schema": 1,
                    "upload_id": upload_id,
                    "filename": safe_name,
                    "declared_size": declared_size,
                    "expected_sha256": expected,
                    "finished": False,
                },
            )
        return UploadBeginResult(
            upload_id=upload_id,
            max_chunk_bytes=MAX_CHUNK_BYTES,
        )

    def write_chunk(
        self,
        upload_id: str,
        offset: int,
        data: bytes,
        *,
        max_chunk_bytes: int | None = MAX_CHUNK_BYTES,
    ) -> UploadChunkResult:
        parsed_id = parse_upload_id(upload_id)
        start = _require_non_negative_int(offset, "offset")
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError("chunk data must be bytes")  # noqa: TRY004
        payload = bytes(data)
        if max_chunk_bytes is not None and len(payload) > max_chunk_bytes:
            raise ValueError(f"chunk exceeds max_chunk_bytes ({max_chunk_bytes})")
        with self._lock:
            meta, _upload_dir, sample_path = self._load(parsed_id)
            if meta.get("finished"):
                raise ValueError("upload is already finished")
            declared_size = _declared_size(meta)
            end = start + len(payload)
            max_bytes = get_upload_max_bytes()
            if end > declared_size:
                raise ValueError("chunk extends past the declared upload size")
            if end > max_bytes:
                raise ValueError(
                    f"upload size {end} exceeds limit of {max_bytes} bytes"
                )
            self._write_range(sample_path, start, payload)
            received = sample_path.stat().st_size
        return UploadChunkResult(
            upload_id=parsed_id,
            offset=start,
            written=len(payload),
            received_size=received,
        )

    def finish(
        self,
        upload_id: str,
        sha256: str | None = None,
    ) -> UploadFinishResult:
        parsed_id = parse_upload_id(upload_id)
        provided = normalize_sha256(sha256)
        with self._lock:
            meta, upload_dir, sample_path = self._load(parsed_id)
            size = sample_path.stat().st_size
            declared_size = _declared_size(meta)
            if size != declared_size:
                raise ValueError(
                    f"upload size mismatch: received {size} bytes, "
                    f"declared {declared_size}"
                )
            digest = file_sha256(sample_path)
            stored = meta.get("expected_sha256")
            stored_digest = stored if isinstance(stored, str) else None
            expected = provided or normalize_sha256(stored_digest)
            if expected is not None and digest != expected:
                raise ValueError("sha256 mismatch")
            os.chmod(sample_path, 0o600)
            meta["finished"] = True
            meta["sha256"] = digest
            meta["size"] = size
            self._write_meta(upload_dir, meta)
            path = str(assert_inside_inbox(sample_path, self.inbox))
        return UploadFinishResult(path=path, size=size, sha256=digest)

    def store_bytes(
        self,
        filename: str,
        data: bytes,
        sha256: str | None = None,
    ) -> StoredUploadResult:
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError("upload body must be bytes")  # noqa: TRY004
        payload = bytes(data)
        begun = self.begin(filename, len(payload), sha256)
        if payload:
            self.write_chunk(
                begun["upload_id"],
                0,
                payload,
                max_chunk_bytes=None,
            )
        finished = self.finish(begun["upload_id"], sha256)
        return StoredUploadResult(upload_id=begun["upload_id"], **finished)

    def list_uploads(self) -> ListUploadsResult:
        with self._lock:
            items = [
                item
                for upload_id in self._existing_upload_ids()
                if (item := self._list_item(upload_id)) is not None
            ]
        items.sort(key=lambda item: item["upload_id"])
        return ListUploadsResult(uploads=items)

    def delete(
        self, upload_id: str, *, leased_paths: Iterable[str] = ()
    ) -> DeleteUploadResult:
        parsed_id = parse_upload_id(upload_id)
        with self._lock:
            _meta, upload_dir, sample_path = self._load(parsed_id)
            assert_inside_inbox(upload_dir, self.inbox)
            assert_inside_inbox(sample_path, self.inbox)
            if _path_is_leased(sample_path, upload_dir, leased_paths):
                raise ValueError(
                    "upload is in use by a database lease; call close_database first"
                )
            _remove_tree(upload_dir)
        return DeleteUploadResult(deleted=True, upload_id=parsed_id)

    def sample_path(self, upload_id: str) -> Path:
        parsed_id = parse_upload_id(upload_id)
        with self._lock:
            _meta, _upload_dir, sample_path = self._load(parsed_id)
            return sample_path

    def _create_upload_dir(self, upload_id: str) -> Path:
        upload_dir = self.inbox / upload_id
        if upload_dir.exists():
            raise ValueError("upload_id already exists")
        ensure_directory(upload_dir, 0o700)
        return assert_inside_inbox(upload_dir, self.inbox)

    def _write_meta(self, upload_dir: Path, meta: dict[str, object]) -> None:
        meta_path = assert_inside_inbox(upload_dir / _META_NAME, self.inbox)
        _write_json(meta_path, meta)

    def _load(self, upload_id: str) -> tuple[dict[str, object], Path, Path]:
        upload_dir = assert_inside_inbox(self.inbox / upload_id, self.inbox)
        if not upload_dir.is_dir():
            raise ValueError(f"unknown upload_id: {upload_id}")
        meta_path = upload_dir / _META_NAME
        if meta_path.is_file():
            loaded = _read_json(meta_path)
            if not isinstance(loaded, dict):
                raise ValueError(f"corrupt upload metadata: {upload_id}")
            raw_name = loaded.get("filename")
            filename = sanitize_filename(
                raw_name if isinstance(raw_name, str) else None
            )
            sample_path = assert_inside_inbox(upload_dir / filename, self.inbox)
            if not sample_path.is_file():
                raise ValueError(f"upload sample is missing: {upload_id}")
            return loaded, upload_dir, sample_path
        sample_path = _first_sample(upload_dir)
        if sample_path is None:
            raise ValueError(f"unknown upload_id: {upload_id}")
        sample_path = assert_inside_inbox(sample_path, self.inbox)
        meta: dict[str, object] = {
            "schema": 1,
            "upload_id": upload_id,
            "filename": sample_path.name,
            "declared_size": sample_path.stat().st_size,
            "expected_sha256": None,
            "finished": False,
        }
        return meta, upload_dir, sample_path

    def _list_item(self, upload_id: str) -> UploadListItem | None:
        try:
            meta, _upload_dir, sample_path = self._load(upload_id)
        except ValueError:
            return None
        size = sample_path.stat().st_size
        finished = bool(meta.get("finished"))
        digest = meta.get("sha256") if finished else None
        declared = meta.get("declared_size")
        return UploadListItem(
            upload_id=upload_id,
            filename=str(meta.get("filename") or sample_path.name),
            path=str(sample_path),
            size=size,
            declared_size=int(declared) if isinstance(declared, int) else size,
            sha256=digest if isinstance(digest, str) else None,
            status="complete" if finished else "pending",
        )

    def _existing_upload_ids(self) -> list[str]:
        if not self.inbox.exists():
            return []
        found: list[str] = []
        for entry in self.inbox.iterdir():
            if entry.is_dir() and _UPLOAD_ID_PATTERN.fullmatch(entry.name):
                found.append(str(uuid.UUID(entry.name)))
        return found

    def _write_range(self, path: Path, offset: int, data: bytes) -> None:
        assert_inside_inbox(path, self.inbox)
        fd = os.open(path, os.O_RDWR)
        try:
            os.lseek(fd, offset, os.SEEK_SET)
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(path, 0o600)


def _declared_size(meta: dict[str, object]) -> int:
    declared = meta.get("declared_size")
    if not isinstance(declared, int) or isinstance(declared, bool):
        raise ValueError("upload metadata is missing declared_size")  # noqa: TRY004  # noqa: TRY004
    return declared


def _require_non_negative_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _first_sample(upload_dir: Path) -> Path | None:
    for entry in sorted(upload_dir.iterdir()):
        if (
            entry.is_file()
            and entry.name != _META_NAME
            and not entry.name.endswith(".tmp")
        ):
            return entry
    return None


def _path_is_leased(
    sample_path: Path,
    upload_dir: Path,
    leased_paths: Iterable[str],
) -> bool:
    sample_real = realpath(sample_path)
    upload_real = realpath(upload_dir)
    for raw in leased_paths:
        if not raw:
            continue
        candidate = realpath(raw)
        if candidate == sample_real or candidate == upload_real:
            return True
        if path_is_inside(candidate, upload_real):
            return True
    return False


def _remove_tree(path: Path) -> None:
    if path.is_dir():
        for child in path.iterdir():
            if child.is_dir():
                _remove_tree(child)
            else:
                child.unlink()
        path.rmdir()
        return
    path.unlink()


def get_upload_store() -> UploadStore:
    global _STORE
    with _STORE_LOCK:
        if _STORE is None:
            _STORE = UploadStore()
        return _STORE


def reset_upload_store() -> None:
    global _STORE
    with _STORE_LOCK:
        _STORE = None


def leased_database_paths(manager: object) -> list[str]:
    """Collect paths held by this process's database leases."""
    paths: list[str] = []
    list_databases = getattr(manager, "list_databases", None)
    if callable(list_databases):
        listing = list_databases()
        instances = listing.get("instances") if isinstance(listing, dict) else None
        if isinstance(instances, list):
            for instance in instances:
                if isinstance(instance, dict):
                    path = instance.get("path")
                    if isinstance(path, str):
                        paths.append(path)
    sessions = getattr(manager, "_instances", None)
    if isinstance(sessions, dict):
        for session in sessions.values():
            requested = getattr(session, "requested_path", None)
            if isinstance(requested, str):
                paths.append(requested)
            handle = getattr(session, "handle", None)
            instance = getattr(handle, "instance", None)
            for attr in ("exe_path", "idb_path"):
                value = getattr(instance, attr, None)
                if isinstance(value, str):
                    paths.append(value)
    return paths
