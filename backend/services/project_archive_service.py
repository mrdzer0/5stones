"""Validated, account-portable archive format for one threat-model project."""
from __future__ import annotations

import hashlib
import io
import json
import re
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import PurePosixPath

from pydantic import ValidationError

from backend.models.schemas import ProjectCreate

ARCHIVE_FORMAT = "5stones-project-archive"
ARCHIVE_VERSION = 1
MAX_ARCHIVE_BYTES = 5 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 1000
MAX_ENTRY_UNCOMPRESSED_BYTES = 10 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 25 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
PROJECT_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
REVISION_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class ProjectArchiveError(ValueError):
    """The uploaded archive is invalid or unsupported."""


class ProjectArchiveTooLargeError(ProjectArchiveError):
    """The archive exceeds an upload or expansion limit."""


def _json_bytes(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2, default=str).encode("utf-8")


def _revision_path(revision: dict) -> str:
    revision_id = str(revision.get("revision_id") or "")
    if not REVISION_ID_PATTERN.fullmatch(revision_id):
        raise ProjectArchiveError("Archive contains an invalid report revision ID")
    return f"report_revisions/{revision_id}.json"


def build_project_archive(snapshot: dict) -> bytes:
    """Serialize a storage snapshot and attach per-entry integrity digests."""
    project = snapshot.get("project") if isinstance(snapshot, dict) else None
    if not isinstance(project, dict):
        raise ProjectArchiveError("Project data is unavailable")
    project_id = str(project.get("project_id") or "")
    if not PROJECT_ID_PATTERN.fullmatch(project_id):
        raise ProjectArchiveError("Project ID is invalid")

    export_project = dict(project)
    # Workspace ownership belongs to the current server, not to an archive
    # that may be restored into another account.
    export_project.pop("workspace_id", None)
    payloads: dict[str, bytes] = {"project.json": _json_bytes(export_project)}
    for key, filename in (
        ("report", "report.json"),
        ("dfd_model", "dfd_model.json"),
        ("analysis_progress", "analysis_progress.json"),
    ):
        value = snapshot.get(key)
        if value is not None:
            if not isinstance(value, dict):
                raise ProjectArchiveError(f"{filename} must contain a JSON object")
            payloads[filename] = _json_bytes(value)

    revisions = snapshot.get("report_revisions") or []
    if not isinstance(revisions, list):
        raise ProjectArchiveError("Report revision history must be a list")
    for revision in revisions:
        if not isinstance(revision, dict):
            raise ProjectArchiveError("Report revision entries must be JSON objects")
        payloads[_revision_path(revision)] = _json_bytes(revision)

    manifest = {
        "format": ARCHIVE_FORMAT,
        "version": ARCHIVE_VERSION,
        "project_id": project_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "files": [
            {"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for path, data in sorted(payloads.items())
        ],
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr("manifest.json", _json_bytes(manifest))
        for path, data in sorted(payloads.items()):
            archive.writestr(path, data)
    result = output.getvalue()
    if len(result) > MAX_ARCHIVE_BYTES:
        raise ProjectArchiveTooLargeError("Project archive is larger than the 5 MiB download limit")
    return result


def _safe_member_name(name: str) -> bool:
    if not name or "\\" in name or "\x00" in name:
        return False
    path = PurePosixPath(name)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def _allowed_member(name: str) -> bool:
    if name in {"manifest.json", "project.json", "report.json", "dfd_model.json", "analysis_progress.json"}:
        return True
    if not name.startswith("report_revisions/") or name.count("/") != 1 or not name.endswith(".json"):
        return False
    revision_id = name[len("report_revisions/"):-len(".json")]
    return bool(REVISION_ID_PATTERN.fullmatch(revision_id))


def _load_json_object(path: str, payload: bytes) -> dict:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProjectArchiveError(f"Archive entry {path} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ProjectArchiveError(f"Archive entry {path} must contain a JSON object")
    return value


def _read_member(archive: zipfile.ZipFile, path: str) -> bytes:
    try:
        return archive.read(path)
    except Exception as exc:
        # ZIP readers can raise several decompressor/CRC exceptions for hostile
        # or truncated archives. Keep those failures inside the validation API.
        raise ProjectArchiveError(f"Archive entry {path} could not be read") from exc


def parse_project_archive(content: bytes) -> dict:
    """Validate ZIP structure, expansion bounds, manifest hashes, and IDs."""
    if len(content) > MAX_ARCHIVE_BYTES:
        raise ProjectArchiveTooLargeError("Project archive exceeds the 5 MiB upload limit")
    if not content or not zipfile.is_zipfile(io.BytesIO(content)):
        raise ProjectArchiveError("Choose a valid 5STONES project archive (.zip)")

    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except (OSError, zipfile.BadZipFile) as exc:
        raise ProjectArchiveError("Project archive could not be opened") from exc

    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_ENTRIES:
            raise ProjectArchiveTooLargeError("Project archive contains too many entries")
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise ProjectArchiveError("Project archive contains duplicate file names")
        total_size = 0
        for info in infos:
            if not _safe_member_name(info.filename) or not _allowed_member(info.filename) or info.is_dir():
                raise ProjectArchiveError("Project archive contains an unsupported file path")
            unix_mode = (info.external_attr >> 16) & 0o170000
            if unix_mode not in {0, stat.S_IFREG}:
                raise ProjectArchiveError("Project archive contains a non-regular file")
            if info.file_size > MAX_ENTRY_UNCOMPRESSED_BYTES:
                raise ProjectArchiveTooLargeError("Project archive contains an oversized entry")
            total_size += info.file_size
            if total_size > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise ProjectArchiveTooLargeError("Project archive expands beyond the 25 MiB safety limit")

        if "manifest.json" not in names or "project.json" not in names:
            raise ProjectArchiveError("Archive is missing its manifest or project record")
        if archive.getinfo("manifest.json").file_size > MAX_MANIFEST_BYTES:
            raise ProjectArchiveTooLargeError("Project archive manifest is too large")
        manifest = _load_json_object("manifest.json", _read_member(archive, "manifest.json"))
        if manifest.get("format") != ARCHIVE_FORMAT or type(manifest.get("version")) is not int or manifest.get("version") != ARCHIVE_VERSION:
            raise ProjectArchiveError("This project archive format is not supported")
        declared_files = manifest.get("files")
        if not isinstance(declared_files, list):
            raise ProjectArchiveError("Project archive manifest is invalid")

        expected: dict[str, tuple[int, str]] = {}
        for entry in declared_files:
            if not isinstance(entry, dict):
                raise ProjectArchiveError("Project archive manifest is invalid")
            path = entry.get("path")
            size = entry.get("size")
            digest = entry.get("sha256")
            if not isinstance(path, str) or path == "manifest.json" or not _allowed_member(path):
                raise ProjectArchiveError("Project archive manifest contains an invalid path")
            if type(size) is not int or size < 0 or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
                raise ProjectArchiveError("Project archive manifest contains invalid integrity metadata")
            if path in expected:
                raise ProjectArchiveError("Project archive manifest contains duplicate entries")
            expected[path] = (size, digest)

        actual_names = set(names) - {"manifest.json"}
        if actual_names != set(expected):
            raise ProjectArchiveError("Project archive files do not match its manifest")
        payloads: dict[str, dict] = {}
        for path, (expected_size, expected_hash) in expected.items():
            raw = _read_member(archive, path)
            if len(raw) != expected_size or hashlib.sha256(raw).hexdigest() != expected_hash:
                raise ProjectArchiveError(f"Integrity check failed for {path}")
            payloads[path] = _load_json_object(path, raw)

    project = payloads.get("project.json")
    project_id = str(project.get("project_id") or "")
    if not PROJECT_ID_PATTERN.fullmatch(project_id) or manifest.get("project_id") != project_id:
        raise ProjectArchiveError("Project ID does not match the archive manifest")
    try:
        ProjectCreate.model_validate({
            field: project[field]
            for field in ProjectCreate.model_fields
            if field in project
        })
    except ValidationError as exc:
        raise ProjectArchiveError("Project record does not match the supported project schema") from exc

    report = payloads.get("report.json")
    if report and report.get("project_id") not in (None, project_id):
        raise ProjectArchiveError("Report belongs to a different project")
    progress = payloads.get("analysis_progress.json")
    if progress and progress.get("project_id") not in (None, project_id):
        raise ProjectArchiveError("Analysis history belongs to a different project")
    dfd_model = payloads.get("dfd_model.json")
    if dfd_model and dfd_model.get("project_id") not in (None, project_id):
        raise ProjectArchiveError("Canonical DFD belongs to a different project")

    revisions = []
    for path, revision in payloads.items():
        if not path.startswith("report_revisions/"):
            continue
        expected_id = path[len("report_revisions/"):-len(".json")]
        if revision.get("revision_id") != expected_id:
            raise ProjectArchiveError("Report revision ID does not match its archive path")
        nested_report = revision.get("report")
        if isinstance(nested_report, dict) and nested_report.get("project_id") not in (None, project_id):
            raise ProjectArchiveError("Report revision belongs to a different project")
        revisions.append(revision)

    return {
        "project": project,
        "report": report,
        "dfd_model": dfd_model,
        "analysis_progress": progress,
        "report_revisions": sorted(revisions, key=lambda item: str(item.get("revision_id") or "")),
    }
