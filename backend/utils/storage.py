"""File-based JSON storage for 5STONES MVP."""
from __future__ import annotations
import json
import os
import hashlib
import tempfile
import fcntl
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, List, Any, Dict
from datetime import datetime

DATA_DIR = Path(os.getenv("DATA_DIR", "./backend/data"))
PROJECTS_DIR = DATA_DIR / "projects"
REPORTS_DIR = DATA_DIR / "reports"
DFD_MODELS_DIR = DATA_DIR / "dfd_models"
ANALYSIS_RUNS_DIR = DATA_DIR / "analysis_runs"
REPORT_REVISIONS_DIR = DATA_DIR / "report_revisions"
SETTINGS_FILE = DATA_DIR / "settings.json"
WORKSPACE_SETTINGS_DIR = DATA_DIR / "workspace_settings"
_PROJECT_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def _ensure_dirs():
    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    DFD_MODELS_DIR.mkdir(parents=True, exist_ok=True)
    ANALYSIS_RUNS_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_REVISIONS_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)


_ensure_dirs()


# ── Generic helpers ──────────────────────────────────────────────────────────

def _read_json(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary_path, path)
        try:
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError:
            # Some filesystems do not support syncing directory descriptors;
            # the atomic replace still prevents readers from seeing partial JSON.
            pass
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


class RevisionConflict(RuntimeError):
    """A report write was based on a revision that is no longer current."""

    def __init__(self, project_id: str, expected_revision: int, current_revision: int):
        self.project_id = project_id
        self.expected_revision = expected_revision
        self.current_revision = current_revision
        super().__init__(
            f"Report revision conflict for {project_id}: expected {expected_revision}, current {current_revision}"
        )


class DfdRevisionConflict(RuntimeError):
    """A canonical DFD write was based on a revision that is no longer current."""

    def __init__(self, project_id: str, expected_revision: int, current_revision: int):
        self.project_id = project_id
        self.expected_revision = expected_revision
        self.current_revision = current_revision
        super().__init__(
            f"DFD revision conflict for {project_id}: expected {expected_revision}, current {current_revision}"
        )


class ProjectRevisionConflict(RuntimeError):
    """A project write was based on a revision that is no longer current."""

    def __init__(self, project_id: str, expected_revision: int, current_revision: int):
        self.project_id = project_id
        self.expected_revision = expected_revision
        self.current_revision = current_revision
        super().__init__(
            f"Project revision conflict for {project_id}: expected {expected_revision}, current {current_revision}"
        )


class ProjectNotFoundError(RuntimeError):
    """A dependent project resource cannot be persisted after project deletion."""

    def __init__(self, project_id: str):
        self.project_id = project_id
        super().__init__(f"Project {project_id} no longer exists")


class ProjectAlreadyExistsError(RuntimeError):
    """An imported project ID already exists in local storage."""

    def __init__(self, project_id: str):
        self.project_id = project_id
        super().__init__(f"Project {project_id} already exists")


@contextmanager
def _project_file_lock(project_id: str, *, shared: bool = False):
    """Serialize a project's project, report, DFD, and revision-snapshot operations."""
    if not _valid_project_id(project_id):
        raise ValueError("Invalid project id")
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = REPORTS_DIR / f".{project_id}.project.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(descriptor, "a+b") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _valid_project_id(project_id: Any) -> bool:
    return isinstance(project_id, str) and bool(_PROJECT_ID_PATTERN.fullmatch(project_id))


# ── Projects ─────────────────────────────────────────────────────────────────

def save_project(project: dict, expected_revision: int | None = None) -> dict:
    project_id = str(project["project_id"])
    path = PROJECTS_DIR / f"{project_id}.json"
    try:
        expected = _safe_revision(project.get("project_revision", 0)) if expected_revision is None else int(expected_revision)
    except (TypeError, ValueError) as exc:
        raise ValueError("expected_revision must be an integer") from exc
    with _project_file_lock(project_id):
        previous = _read_json(path)
        current_revision = _safe_revision((previous or {}).get("project_revision", 0))
        if expected != current_revision:
            raise ProjectRevisionConflict(project_id, expected, current_revision)
        # Do not recreate an object deleted after a stale reader fetched it.
        if previous is None and (project.get("updated_at") or expected > 0):
            raise ProjectRevisionConflict(project_id, expected, current_revision)
        project["project_revision"] = current_revision + 1
        project["updated_at"] = datetime.utcnow().isoformat()
        _write_json(path, project)
    return project


def get_project(project_id: str) -> Optional[dict]:
    if not _valid_project_id(project_id):
        return None
    with _project_file_lock(project_id, shared=True):
        return _read_json(PROJECTS_DIR / f"{project_id}.json")


def list_projects() -> List[dict]:
    projects = []
    for f in sorted(PROJECTS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        data = get_project(f.stem)
        if data:
            projects.append(data)
    return projects


def list_unscoped_projects() -> List[dict]:
    """Return legacy projects that have not been assigned to an account."""
    return [project for project in list_projects() if not project.get("workspace_id")]


def claim_legacy_project(project_id: str, workspace_id: str) -> dict | None:
    """Assign one unscoped legacy project to a verified account workspace.

    The pre-change record is backed up before its ownership metadata changes.
    Existing scoped projects are never transferred.
    """
    if not _valid_project_id(project_id) or not str(workspace_id or "").strip():
        return None
    path = PROJECTS_DIR / f"{project_id}.json"
    with _project_file_lock(project_id):
        project = _read_json(path)
        if not isinstance(project, dict) or project.get("workspace_id"):
            return None

        backup_dir = DATA_DIR / "backups" / "legacy-recovery"
        backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(backup_dir.parent, 0o700)
            os.chmod(backup_dir, 0o700)
        except OSError:
            pass
        backup_path = backup_dir / f"{project_id}.json"
        if not backup_path.exists():
            _write_json(backup_path, project)
            try:
                os.chmod(backup_path, 0o600)
            except OSError:
                pass

        project["workspace_id"] = str(workspace_id).strip()
        project["project_revision"] = _safe_revision(project.get("project_revision", 0)) + 1
        project["updated_at"] = datetime.utcnow().isoformat()
        _write_json(path, project)
        return project


def delete_project(project_id: str, expected_revision: int | None = None) -> bool:
    if not _valid_project_id(project_id):
        return False
    path = PROJECTS_DIR / f"{project_id}.json"
    with _project_file_lock(project_id):
        current = _read_json(path)
        if current is None:
            return False
        current_revision = _safe_revision(current.get("project_revision", 0))
        if expected_revision is not None and int(expected_revision) != current_revision:
            raise ProjectRevisionConflict(project_id, int(expected_revision), current_revision)
        path.unlink()
        # Also remove dependent state while holding the same per-project lock.
        for dependent in (
            REPORTS_DIR / f"{project_id}.json",
            DFD_MODELS_DIR / f"{project_id}.json",
            ANALYSIS_RUNS_DIR / f"{project_id}.json",
        ):
            if dependent.exists():
                dependent.unlink()
        revision_path = REPORT_REVISIONS_DIR / project_id
        if revision_path.exists():
            import shutil
            shutil.rmtree(revision_path)
        return True


# ── Reports ──────────────────────────────────────────────────────────────────

def save_report(project_id: str, report: dict, expected_revision: int | None = None) -> dict:
    path = REPORTS_DIR / f"{project_id}.json"
    try:
        expected = int(report.get("report_revision", 0) or 0) if expected_revision is None else int(expected_revision)
    except (TypeError, ValueError) as exc:
        raise ValueError("expected_revision must be an integer") from exc
    with _project_file_lock(project_id):
        if _read_json(PROJECTS_DIR / f"{project_id}.json") is None:
            raise ProjectNotFoundError(project_id)
        previous = _read_json(path) or {}
        previous_revision = _safe_revision(previous.get("report_revision", 0))
        if expected != previous_revision:
            raise RevisionConflict(project_id, expected, previous_revision)
        _prepare_report_revision(report, previous, previous_revision + 1)
        _write_json(path, report)
    return report


def _safe_revision(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _prepare_report_revision(report: dict, previous: dict, next_revision: int) -> None:
    previous_formal = previous.get("formal_report") if isinstance(previous.get("formal_report"), dict) else {}
    # Signed snapshots are immutable. Any subsequent persisted report change
    # creates a new draft state and marks the signed revision superseded.
    if previous_formal.get("status") == "signed":
        current_formal = report.get("formal_report") if isinstance(report.get("formal_report"), dict) else previous_formal
        report["formal_report"] = {
            **previous_formal,
            **current_formal,
            "status": "superseded",
            "superseded_at": datetime.utcnow().isoformat(),
            "superseded_by_revision": next_revision,
        }
    report["report_revision"] = next_revision
    report["report_updated_at"] = datetime.utcnow().isoformat()


def get_report(project_id: str) -> Optional[dict]:
    if not _valid_project_id(project_id):
        return None
    with _project_file_lock(project_id, shared=True):
        return _read_json(REPORTS_DIR / f"{project_id}.json")


def get_project_report_and_dfd(project_id: str) -> tuple[Optional[dict], Optional[dict]]:
    """Read the report and canonical DFD from one consistent project snapshot."""
    if not _valid_project_id(project_id):
        return None, None
    with _project_file_lock(project_id, shared=True):
        report = _read_json(REPORTS_DIR / f"{project_id}.json")
        dfd_model = _read_json(DFD_MODELS_DIR / f"{project_id}.json")
        return report, dfd_model


def get_project_archive_snapshot(project_id: str) -> dict | None:
    """Read all transferable project state under one consistent file lock."""
    if not _valid_project_id(project_id):
        return None
    with _project_file_lock(project_id, shared=True):
        project = _read_json(PROJECTS_DIR / f"{project_id}.json")
        if not isinstance(project, dict):
            return None
        revisions = []
        revision_dir = REPORT_REVISIONS_DIR / project_id
        if revision_dir.exists():
            for path in sorted(revision_dir.glob("*.json"), key=lambda item: item.name):
                revision = _read_json(path)
                if isinstance(revision, dict):
                    revisions.append(revision)
        return {
            "project": project,
            "report": _read_json(REPORTS_DIR / f"{project_id}.json"),
            "dfd_model": _read_json(DFD_MODELS_DIR / f"{project_id}.json"),
            "analysis_progress": _read_json(ANALYSIS_RUNS_DIR / f"{project_id}.json"),
            "report_revisions": revisions,
        }


def import_project_archive_snapshot(snapshot: dict, workspace_id: str) -> dict:
    """Create a project from a validated archive without replacing existing data.

    Dependent files are written first and the project record is committed last,
    so normal readers cannot observe a project whose history is only partly
    imported. A failed write removes any newly written dependent state.
    """
    raw_project = snapshot.get("project") if isinstance(snapshot, dict) else None
    if not isinstance(raw_project, dict):
        raise ValueError("Archive is missing a project record")
    project_id = str(raw_project.get("project_id") or "")
    if not _valid_project_id(project_id):
        raise ValueError("Invalid project ID")
    workspace_id = str(workspace_id or "").strip()
    if not workspace_id:
        raise ValueError("A destination workspace is required")

    project_path = PROJECTS_DIR / f"{project_id}.json"
    report_path = REPORTS_DIR / f"{project_id}.json"
    dfd_path = DFD_MODELS_DIR / f"{project_id}.json"
    progress_path = ANALYSIS_RUNS_DIR / f"{project_id}.json"
    revision_dir = REPORT_REVISIONS_DIR / project_id
    now = datetime.utcnow().isoformat()

    with _project_file_lock(project_id):
        if any(path.exists() for path in (project_path, report_path, dfd_path, progress_path, revision_dir)):
            raise ProjectAlreadyExistsError(project_id)

        project = dict(raw_project)
        # Never trust ownership or revision metadata carried by an archive.
        project["workspace_id"] = workspace_id
        project["project_revision"] = 1
        project["updated_at"] = now
        revisions = snapshot.get("report_revisions") or []
        written_paths: list[Path] = []
        created_revision_dir = False
        try:
            for key, path in (
                ("report", report_path),
                ("dfd_model", dfd_path),
                ("analysis_progress", progress_path),
            ):
                value = snapshot.get(key)
                if value is not None:
                    _write_json(path, value)
                    written_paths.append(path)

            if revisions:
                revision_dir.mkdir(parents=True, exist_ok=False)
                created_revision_dir = True
                for revision in revisions:
                    revision_id = str(revision.get("revision_id") or "")
                    if not revision_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in revision_id):
                        raise ValueError("Invalid report revision ID")
                    revision_path = revision_dir / f"{revision_id}.json"
                    _write_json(revision_path, revision)

            _write_json(project_path, project)
            written_paths.append(project_path)
        except Exception:
            for path in written_paths:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
            if created_revision_dir:
                import shutil
                shutil.rmtree(revision_dir, ignore_errors=True)
            raise
    return project


def save_report_and_dfd(
    project_id: str,
    report: dict,
    dfd_model: dict,
    *,
    expected_report_revision: int,
    expected_dfd_revision: int,
) -> tuple[dict, dict]:
    """CAS and persist a report plus its canonical DFD under one project lock."""
    report_path = REPORTS_DIR / f"{project_id}.json"
    dfd_path = DFD_MODELS_DIR / f"{project_id}.json"
    expected_report = int(expected_report_revision)
    expected_dfd = int(expected_dfd_revision)
    with _project_file_lock(project_id):
        if _read_json(PROJECTS_DIR / f"{project_id}.json") is None:
            raise ProjectNotFoundError(project_id)
        previous_report = _read_json(report_path) or {}
        previous_dfd = _read_json(dfd_path)
        current_report_revision = _safe_revision(previous_report.get("report_revision", 0))
        current_dfd_payload = previous_dfd or (previous_report.get("dfd_model") if isinstance(previous_report.get("dfd_model"), dict) else {})
        current_dfd_revision = _safe_revision(current_dfd_payload.get("revision", 0))
        if expected_report != current_report_revision:
            raise RevisionConflict(project_id, expected_report, current_report_revision)
        if expected_dfd != current_dfd_revision:
            raise DfdRevisionConflict(project_id, expected_dfd, current_dfd_revision)
        candidate_dfd_revision = _safe_revision(dfd_model.get("revision", 0))
        if candidate_dfd_revision < current_dfd_revision:
            raise DfdRevisionConflict(project_id, candidate_dfd_revision, current_dfd_revision)

        report["dfd_model"] = dfd_model
        _prepare_report_revision(report, previous_report, current_report_revision + 1)
        # Readers that need both files take this same project lock. If the
        # process stops between replaces, startup/reconciliation can detect the
        # mismatch; this local JSON store is not a crash-atomic database.
        _write_json(dfd_path, dfd_model)
        _write_json(report_path, report)
    return report, dfd_model


def save_report_revision(project_id: str, snapshot: dict) -> dict:
    """Persist a report snapshot without replacing an existing signed snapshot."""
    revision_id = str(snapshot.get("revision_id") or "").strip()
    if not revision_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in revision_id):
        raise ValueError("Invalid report revision id")
    path = REPORT_REVISIONS_DIR / project_id / f"{revision_id}.json"
    with _project_file_lock(project_id):
        if _read_json(PROJECTS_DIR / f"{project_id}.json") is None:
            raise ProjectNotFoundError(project_id)
        existing = _read_json(path)
        if existing and (snapshot.get("status") == "signed" or existing.get("status") == "signed"):
            return existing
        _write_json(path, snapshot)
    return snapshot


def list_report_revisions(project_id: str) -> list[dict]:
    if not _valid_project_id(project_id):
        return []
    directory = REPORT_REVISIONS_DIR / project_id
    if not directory.exists():
        return []
    with _project_file_lock(project_id, shared=True):
        result = []
        for path in sorted(directory.glob("*.json"), reverse=True):
            item = _read_json(path)
            if item:
                result.append(item)
        return result


def get_report_revision(project_id: str, revision_id: str) -> Optional[dict]:
    if not _valid_project_id(project_id) or not revision_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in revision_id):
        return None
    with _project_file_lock(project_id, shared=True):
        return _read_json(REPORT_REVISIONS_DIR / project_id / f"{revision_id}.json")


def save_analysis_progress(project_id: str, progress: dict) -> dict:
    with _project_file_lock(project_id):
        if _read_json(PROJECTS_DIR / f"{project_id}.json") is None:
            raise ProjectNotFoundError(project_id)
        _write_json(ANALYSIS_RUNS_DIR / f"{project_id}.json", progress)
    return progress


def get_analysis_progress(project_id: str) -> Optional[dict]:
    if not _valid_project_id(project_id):
        return None
    with _project_file_lock(project_id, shared=True):
        return _read_json(ANALYSIS_RUNS_DIR / f"{project_id}.json")


# ── Canonical DFD models ─────────────────────────────────────────────────────

def save_dfd_model(project_id: str, model: dict, expected_revision: int | None = None) -> dict:
    """Persist the canonical DFD independently from the analysis report."""
    dfd_path = DFD_MODELS_DIR / f"{project_id}.json"
    with _project_file_lock(project_id):
        if _read_json(PROJECTS_DIR / f"{project_id}.json") is None:
            raise ProjectNotFoundError(project_id)
        current = _read_json(dfd_path)
        if current is None:
            report = _read_json(REPORTS_DIR / f"{project_id}.json") or {}
            current = report.get("dfd_model") if isinstance(report.get("dfd_model"), dict) else {}
        current_revision = _safe_revision(current.get("revision", 0))
        if expected_revision is not None and int(expected_revision) != current_revision:
            raise DfdRevisionConflict(project_id, int(expected_revision), current_revision)
        _write_json(dfd_path, model)
    return model


def get_dfd_model(project_id: str) -> Optional[dict]:
    if not _valid_project_id(project_id):
        return None
    with _project_file_lock(project_id, shared=True):
        return _read_json(DFD_MODELS_DIR / f"{project_id}.json")


# ── Settings ─────────────────────────────────────────────────────────────────

def _default_settings() -> dict:
    return {
        "active_provider_id": None,
        "providers": [],
        "local_llm_endpoint": None,
        "local_llm_model": None,
        "default_data_policy": "byok_allowed",
        "mcp_servers": [],
    }


def _current_workspace_id(workspace_id: str | None = None) -> str | None:
    if workspace_id:
        return str(workspace_id).strip() or None
    try:
        from backend.utils.access_control import current_workspace_context
        return current_workspace_context()
    except Exception:
        return None


def _workspace_settings_path(workspace_id: str) -> Path:
    key = hashlib.sha256(workspace_id.encode("utf-8")).hexdigest()
    return WORKSPACE_SETTINGS_DIR / f"{key}.json"


def get_settings(workspace_id: str | None = None) -> dict:
    workspace_id = _current_workspace_id(workspace_id)
    if workspace_id:
        envelope = _read_json(_workspace_settings_path(workspace_id))
        if not isinstance(envelope, dict) or envelope.get("workspace_id") != workspace_id:
            return _default_settings()
        settings = envelope.get("settings")
        return settings if isinstance(settings, dict) else _default_settings()

    data = _read_json(SETTINGS_FILE)
    if data is None:
        return _default_settings()
    return data


def save_settings(settings: dict, workspace_id: str | None = None) -> dict:
    workspace_id = _current_workspace_id(workspace_id)
    if workspace_id:
        _write_json(_workspace_settings_path(workspace_id), {
            "workspace_id": workspace_id,
            "settings": settings,
        })
        return settings
    _write_json(SETTINGS_FILE, settings)
    return settings


# ── Controls catalog ─────────────────────────────────────────────────────────

def get_controls_catalog() -> List[dict]:
    path = DATA_DIR / "controls_catalog.json"
    data = _read_json(path)
    if data is not None:
        return data if isinstance(data, list) else []
    # DATA_DIR may point at an isolated workspace or a mounted volume. The
    # reviewed default catalog is application code, not per-project state.
    bundled = Path(__file__).resolve().parents[1] / "data" / "controls_catalog.json"
    if bundled != path:
        return _read_json(bundled) or []
    return []
