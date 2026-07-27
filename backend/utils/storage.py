"""File-based JSON storage for 5STONES MVP."""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Optional, List, Any, Dict
from datetime import datetime

DATA_DIR = Path(os.getenv("DATA_DIR", "./backend/data"))
PROJECTS_DIR = DATA_DIR / "projects"
REPORTS_DIR = DATA_DIR / "reports"
SETTINGS_FILE = DATA_DIR / "settings.json"


def _ensure_dirs():
    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
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
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


# ── Projects ─────────────────────────────────────────────────────────────────

def save_project(project: dict) -> dict:
    project["updated_at"] = datetime.utcnow().isoformat()
    path = PROJECTS_DIR / f"{project['project_id']}.json"
    _write_json(path, project)
    return project


def get_project(project_id: str) -> Optional[dict]:
    return _read_json(PROJECTS_DIR / f"{project_id}.json")


def list_projects() -> List[dict]:
    projects = []
    for f in sorted(PROJECTS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        data = _read_json(f)
        if data:
            projects.append(data)
    return projects


def delete_project(project_id: str) -> bool:
    path = PROJECTS_DIR / f"{project_id}.json"
    if path.exists():
        path.unlink()
        # Also remove report if exists
        report_path = REPORTS_DIR / f"{project_id}.json"
        if report_path.exists():
            report_path.unlink()
        return True
    return False


# ── Reports ──────────────────────────────────────────────────────────────────

def save_report(project_id: str, report: dict) -> dict:
    path = REPORTS_DIR / f"{project_id}.json"
    _write_json(path, report)
    return report


def get_report(project_id: str) -> Optional[dict]:
    return _read_json(REPORTS_DIR / f"{project_id}.json")


# ── Settings ─────────────────────────────────────────────────────────────────

def get_settings() -> dict:
    data = _read_json(SETTINGS_FILE)
    if data is None:
        return {
            "active_provider_id": None,
            "providers": [],
            "local_llm_endpoint": None,
            "local_llm_model": None,
            "default_data_policy": "byok_allowed",
            "mcp_servers": []
        }
    return data


def save_settings(settings: dict) -> dict:
    _write_json(SETTINGS_FILE, settings)
    return settings


# ── Controls catalog ─────────────────────────────────────────────────────────

def get_controls_catalog() -> List[dict]:
    path = DATA_DIR / "controls_catalog.json"
    data = _read_json(path)
    return data if data else []
