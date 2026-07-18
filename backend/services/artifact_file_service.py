"""Secure artifact file validation and text extraction."""
from __future__ import annotations
import io
import json
import zipfile
from pathlib import Path
from typing import Iterable
from fastapi import HTTPException, UploadFile


MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_EXTRACTED_CHARS = 120_000
MAX_DOCX_UNCOMPRESSED_BYTES = 25 * 1024 * 1024
MAX_DOCX_ENTRIES = 1000

ALLOWED_EXTENSIONS = {
    "prd": {".pdf", ".docx", ".md", ".markdown", ".txt"},
    "openapi": {".json", ".yaml", ".yml"},
    "postman": {".json"},
    "markdown": {".md", ".markdown", ".txt"},
    "database_schema": {".sql", ".txt"},
    "csv": {".csv", ".txt"},
    "har": {".har", ".json"},
    "text": {".txt", ".md", ".markdown"},
}

ARTIFACT_LABELS = {
    "prd": "PRD / product requirements",
    "openapi": "OpenAPI / Swagger specification",
    "postman": "Postman collection",
    "markdown": "Markdown documentation",
    "database_schema": "Database schema",
    "csv": "CSV API list",
    "har": "HTTP archive",
    "text": "Plain text notes",
}


async def read_validated_artifact_file(artifact_type: str, file: UploadFile) -> dict:
    """Validate a user-uploaded artifact and extract bounded text for analysis."""
    if artifact_type not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Unsupported artifact_type")

    filename = Path(file.filename or "").name
    suffix = Path(filename).suffix.lower()
    allowed = ALLOWED_EXTENSIONS[artifact_type]
    if suffix not in allowed:
        allowed_text = ", ".join(sorted(allowed))
        raise HTTPException(
            status_code=415,
            detail=f"File type {suffix or '(none)'} is not allowed for {ARTIFACT_LABELS[artifact_type]}. Allowed: {allowed_text}",
        )

    content = await _read_limited(file)
    _reject_empty(content)

    text = _extract_text(suffix, content)
    text = _clean_text(text)
    if not text:
        raise HTTPException(status_code=422, detail="Could not extract readable text from the uploaded artifact")

    return {
        "filename": filename,
        "content": text[:MAX_EXTRACTED_CHARS],
        "size_bytes": len(content),
        "truncated": len(text) > MAX_EXTRACTED_CHARS,
    }


def allowed_file_policy() -> dict:
    return {
        "max_upload_mb": round(MAX_UPLOAD_BYTES / 1024 / 1024),
        "max_extracted_chars": MAX_EXTRACTED_CHARS,
        "allowed_extensions": {k: sorted(v) for k, v in ALLOWED_EXTENSIONS.items()},
    }


async def _read_limited(file: UploadFile) -> bytes:
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File too large. Maximum allowed size is {MAX_UPLOAD_BYTES // 1024 // 1024} MB")
    return content


def _reject_empty(content: bytes):
    if not content or not content.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty")


def _extract_text(suffix: str, content: bytes) -> str:
    if suffix == ".pdf":
        return _extract_pdf(content)
    if suffix == ".docx":
        return _extract_docx(content)
    if suffix in {".json", ".har"}:
        return _extract_json(content)
    return _decode_text(content)


def _extract_pdf(content: bytes) -> str:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise HTTPException(status_code=500, detail="PDF support requires pypdf. Install requirements.txt.") from exc

    try:
        reader = PdfReader(io.BytesIO(content))
        if reader.is_encrypted:
            raise HTTPException(status_code=415, detail="Encrypted PDF files are not supported")
        pages = []
        for page in reader.pages[:80]:
            pages.append(page.extract_text() or "")
        return "\n\n".join(pages)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=422, detail="Could not parse PDF artifact") from exc


def _extract_docx(content: bytes) -> str:
    buffer = io.BytesIO(content)
    if not zipfile.is_zipfile(buffer):
        raise HTTPException(status_code=415, detail="Invalid DOCX file")
    _validate_zip_bounds(content)
    try:
        from docx import Document
    except ImportError as exc:
        raise HTTPException(status_code=500, detail="DOCX support requires python-docx. Install requirements.txt.") from exc

    try:
        doc = Document(io.BytesIO(content))
        parts = [p.text for p in doc.paragraphs if p.text.strip()]
        for table in doc.tables[:20]:
            for row in table.rows:
                values = [cell.text.strip() for cell in row.cells if cell.text.strip()]
                if values:
                    parts.append(" | ".join(values))
        return "\n".join(parts)
    except Exception as exc:
        raise HTTPException(status_code=422, detail="Could not parse DOCX artifact") from exc


def _validate_zip_bounds(content: bytes):
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_DOCX_ENTRIES:
                raise HTTPException(status_code=413, detail="DOCX file contains too many entries")
            total = sum(info.file_size for info in infos)
            if total > MAX_DOCX_UNCOMPRESSED_BYTES:
                raise HTTPException(status_code=413, detail="DOCX uncompressed content is too large")
    except HTTPException:
        raise
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=415, detail="Invalid DOCX file") from exc


def _extract_json(content: bytes) -> str:
    text = _decode_text(content)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return text
    return json.dumps(_redact_large_values(parsed), indent=2, ensure_ascii=False)


def _decode_text(content: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return content.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise HTTPException(status_code=415, detail="Unsupported text encoding")


def _clean_text(text: str) -> str:
    lines = []
    for line in text.replace("\x00", "").splitlines():
        clean = " ".join(line.split())
        if clean:
            lines.append(clean)
    return "\n".join(lines)


def _redact_large_values(value):
    if isinstance(value, dict):
        return {str(k)[:120]: _redact_large_values(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_large_values(v) for v in value[:500]]
    if isinstance(value, str):
        return value[:2000]
    return value
