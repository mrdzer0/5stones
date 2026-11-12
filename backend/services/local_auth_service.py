"""Local-only user and session storage backed by SQLite.

Passwords use salted PBKDF2-HMAC-SHA256. Session credentials are random,
opaque values; only their SHA-256 digests are persisted in the database.
This adapter is intended for a loopback local deployment. Enterprise
deployments continue to authenticate through the configured OIDC provider.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PASSWORD_ITERATIONS = 600_000
PASSWORD_MIN_LENGTH = 12
SESSION_TTL_SECONDS = 8 * 60 * 60
EMAIL_PATTERN = re.compile(r"^[^\s@]{1,128}@[^\s@]{1,190}\.[^\s@]{2,63}$")
ALLOWED_ROLES = {"analyst", "reviewer", "admin"}


class DuplicateUserError(ValueError):
    """The normalized email is already registered."""


class InvalidCredentialsError(ValueError):
    """The credentials do not identify an active account."""


class LoginRateLimitedError(ValueError):
    """Too many recent login failures for this account or client address."""


class InvalidUserInputError(ValueError):
    """Email, password, role, or workspace values are invalid."""


def new_account_workspace_id() -> str:
    """Return an unguessable workspace identifier reserved for one account."""
    return f"user:{uuid.uuid4()}"


def database_path() -> Path:
    configured = os.getenv("AUTH_DB_PATH", "").strip()
    if configured:
        path = Path(configured).expanduser()
    else:
        path = Path(os.getenv("DATA_DIR", "./backend/data")) / "auth" / "auth.sqlite3"
    if not path.is_absolute():
        path = Path.cwd() / path
    return path


def _connect() -> sqlite3.Connection:
    path = database_path()
    if not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass
    connection = sqlite3.connect(path, timeout=10, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return connection


@contextmanager
def _connection():
    connection = _connect()
    try:
        yield connection
    finally:
        connection.close()


def initialize_database() -> Path:
    path = database_path()
    with _connection() as connection:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS auth_users (
                user_id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                email_normalized TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('analyst', 'reviewer', 'admin')),
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                password_iterations INTEGER NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auth_sessions (
                session_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES auth_users(user_id) ON DELETE CASCADE,
                csrf_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked_at TEXT
            );
            CREATE INDEX IF NOT EXISTS auth_sessions_user_idx ON auth_sessions(user_id);
            CREATE INDEX IF NOT EXISTS auth_sessions_expiry_idx ON auth_sessions(expires_at);
            CREATE TABLE IF NOT EXISTS auth_login_buckets (
                bucket_hash TEXT PRIMARY KEY,
                failures INTEGER NOT NULL,
                window_started REAL NOT NULL,
                locked_until REAL NOT NULL DEFAULT 0
            );
        """)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def normalize_email(email: str) -> tuple[str, str]:
    display = str(email or "").strip()
    normalized = display.casefold()
    if len(display) > 320 or not EMAIL_PATTERN.fullmatch(display):
        raise InvalidUserInputError("Enter a valid email address.")
    return display, normalized


def validate_password(password: str) -> str:
    value = str(password or "")
    if len(value) < PASSWORD_MIN_LENGTH:
        raise InvalidUserInputError(f"Password must contain at least {PASSWORD_MIN_LENGTH} characters.")
    if len(value) > 256:
        raise InvalidUserInputError("Password must contain no more than 256 characters.")
    if not value.strip():
        raise InvalidUserInputError("Password cannot be blank.")
    return value


def _password_digest(password: str, salt: bytes, iterations: int = PASSWORD_ITERATIONS) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _public_user(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return {
        "user_id": row["user_id"],
        "email": row["email"],
        "display_name": row["display_name"],
        "workspace_id": row["workspace_id"],
        "role": row["role"],
        "is_active": bool(row["is_active"]),
        "created_at": row["created_at"],
    }


def create_user(
    email: str,
    password: str,
    *,
    workspace_id: str,
    role: str = "analyst",
    display_name: str = "",
) -> dict[str, Any]:
    display_email, normalized = normalize_email(email)
    password = validate_password(password)
    workspace = str(workspace_id or "").strip()
    if not workspace or len(workspace) > 128 or any(ord(char) < 32 for char in workspace):
        raise InvalidUserInputError("Workspace ID must be 1 to 128 printable characters.")
    normalized_role = str(role or "").strip().casefold()
    if normalized_role not in ALLOWED_ROLES:
        raise InvalidUserInputError("Role must be analyst, reviewer, or admin.")
    safe_name = " ".join(str(display_name or "").split())[:120] or display_email.split("@", 1)[0]
    salt = secrets.token_bytes(16)
    password_hash = _password_digest(password, salt)
    now = _now_iso()
    user = {
        "user_id": str(uuid.uuid4()),
        "email": display_email,
        "email_normalized": normalized,
        "display_name": safe_name,
        "workspace_id": workspace,
        "role": normalized_role,
        "password_salt": salt,
        "password_hash": password_hash,
        "password_iterations": PASSWORD_ITERATIONS,
        "is_active": 1,
        "created_at": now,
        "updated_at": now,
    }
    initialize_database()
    connection = _connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        existing_workspace = connection.execute(
            "SELECT user_id FROM auth_users WHERE workspace_id = ? LIMIT 1",
            (workspace,),
        ).fetchone()
        if existing_workspace:
            connection.rollback()
            raise InvalidUserInputError("Each local account must use a unique workspace ID.")
        connection.execute("""
            INSERT INTO auth_users (
                user_id, email, email_normalized, display_name, workspace_id, role,
                password_salt, password_hash, password_iterations, is_active,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, tuple(user[key] for key in (
            "user_id", "email", "email_normalized", "display_name", "workspace_id", "role",
            "password_salt", "password_hash", "password_iterations", "is_active", "created_at", "updated_at",
        )))
        connection.commit()
    except sqlite3.IntegrityError as exc:
        connection.rollback()
        if "email_normalized" in str(exc).casefold() or "unique" in str(exc).casefold():
            raise DuplicateUserError("An account with this email already exists.") from exc
        raise
    finally:
        connection.close()
    return {key: value for key, value in user.items() if not key.startswith("password_") and key != "email_normalized"}


def user_count() -> int:
    initialize_database()
    with _connection() as connection:
        row = connection.execute("SELECT COUNT(*) AS total FROM auth_users").fetchone()
        return int(row["total"])


def is_sole_admin_user(user_id: str) -> bool:
    """Return true only when the active admin is the database's sole account."""
    initialize_database()
    with _connection() as connection:
        row = connection.execute("""
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN user_id = ? AND role = 'admin' AND is_active = 1 THEN 1 ELSE 0 END) AS eligible
            FROM auth_users
        """, (str(user_id),)).fetchone()
        return int(row["total"] or 0) == 1 and int(row["eligible"] or 0) == 1


def _bucket_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _login_bucket_keys(normalized_email: str, remote_addr: str) -> tuple[str, str]:
    return (
        _bucket_hash(f"email\0{normalized_email}"),
        _bucket_hash(f"ip\0{remote_addr or 'unknown'}"),
    )


def _is_login_limited(email_key: str, ip_key: str, now: float) -> bool:
    with _connection() as connection:
        rows = connection.execute(
            "SELECT bucket_hash, locked_until FROM auth_login_buckets WHERE bucket_hash IN (?, ?)",
            (email_key, ip_key),
        ).fetchall()
    return any(float(row["locked_until"]) > now for row in rows)


def _record_login_failure(email_key: str, ip_key: str, now: float) -> None:
    connection = _connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DELETE FROM auth_login_buckets WHERE window_started < ?", (now - 900,))
        for bucket_key, limit in ((email_key, 5), (ip_key, 20)):
            row = connection.execute(
                "SELECT failures, window_started FROM auth_login_buckets WHERE bucket_hash = ?",
                (bucket_key,),
            ).fetchone()
            if row is None or float(row["window_started"]) < now - 900:
                failures = 1
                window_started = now
            else:
                failures = int(row["failures"]) + 1
                window_started = float(row["window_started"])
            locked_until = now + 900 if failures >= limit else 0
            connection.execute("""
                INSERT INTO auth_login_buckets (bucket_hash, failures, window_started, locked_until)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(bucket_hash) DO UPDATE SET
                    failures = excluded.failures,
                    window_started = excluded.window_started,
                    locked_until = excluded.locked_until
            """, (bucket_key, failures, window_started, locked_until))
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _clear_email_login_failures(email_key: str) -> None:
    with _connection() as connection:
        connection.execute("DELETE FROM auth_login_buckets WHERE bucket_hash = ?", (email_key,))


def _dummy_password_check(password: str) -> None:
    # Keep unknown-account failures close to the real password-check cost.
    salt = bytes.fromhex("9f" * 16)
    expected = bytes.fromhex("5a" * 32)
    actual = _password_digest(password, salt)
    hmac.compare_digest(actual, expected)


def login(email: str, password: str, remote_addr: str) -> tuple[dict[str, Any], str, str, int]:
    _display_email, normalized = normalize_email(email)
    password = validate_password(password)
    initialize_database()
    email_key, ip_key = _login_bucket_keys(normalized, str(remote_addr or "unknown"))
    now_epoch = time.time()
    if _is_login_limited(email_key, ip_key, now_epoch):
        raise LoginRateLimitedError("Too many login attempts. Try again in 15 minutes.")
    with _connection() as connection:
        row = connection.execute(
            "SELECT * FROM auth_users WHERE email_normalized = ?", (normalized,)
        ).fetchone()
    if row is None:
        _dummy_password_check(password)
        _record_login_failure(email_key, ip_key, now_epoch)
        raise InvalidCredentialsError("Email or password is incorrect.")
    actual = _password_digest(password, bytes(row["password_salt"]), int(row["password_iterations"]))
    valid_password = hmac.compare_digest(actual, bytes(row["password_hash"]))
    if not valid_password or not row["is_active"]:
        _record_login_failure(email_key, ip_key, now_epoch)
        raise InvalidCredentialsError("Email or password is incorrect.")
    _clear_email_login_failures(email_key)
    return create_session_for_user(str(row["user_id"]))


def create_session_for_user(user_id: str) -> tuple[dict[str, Any], str, str, int]:
    initialize_database()
    with _connection() as connection:
        row = connection.execute(
            "SELECT * FROM auth_users WHERE user_id = ? AND is_active = 1", (str(user_id),)
        ).fetchone()
    if row is None:
        raise InvalidCredentialsError("Account is unavailable.")
    user = _public_user(row)
    raw_session = secrets.token_urlsafe(48)
    csrf_token = secrets.token_urlsafe(32)
    now_epoch = time.time()
    expires_at = int(now_epoch) + SESSION_TTL_SECONDS
    connection = _connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DELETE FROM auth_sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL", (int(now_epoch),))
        connection.execute(
            "INSERT INTO auth_sessions (session_hash, user_id, csrf_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (hashlib.sha256(raw_session.encode()).hexdigest(), user["user_id"], hashlib.sha256(csrf_token.encode()).hexdigest(), _now_iso(), expires_at),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return user, raw_session, csrf_token, expires_at


def authenticate_session(raw_session: str) -> dict[str, Any] | None:
    if not raw_session:
        return None
    session_hash = hashlib.sha256(raw_session.encode()).hexdigest()
    with _connection() as connection:
        row = connection.execute("""
            SELECT u.*, s.csrf_hash, s.expires_at, s.revoked_at
            FROM auth_sessions s JOIN auth_users u ON u.user_id = s.user_id
            WHERE s.session_hash = ?
        """, (session_hash,)).fetchone()
    if row is None or row["revoked_at"] is not None or not row["is_active"] or int(row["expires_at"]) <= int(time.time()):
        return None
    return _public_user(row)


def validate_session_csrf(raw_session: str, csrf_token: str | None, csrf_header: str | None) -> bool:
    if not raw_session or not csrf_token or not csrf_header or not hmac.compare_digest(csrf_token, csrf_header):
        return False
    session_hash = hashlib.sha256(raw_session.encode()).hexdigest()
    with _connection() as connection:
        row = connection.execute(
            "SELECT csrf_hash FROM auth_sessions WHERE session_hash = ? AND revoked_at IS NULL AND expires_at > ?",
            (session_hash, int(time.time())),
        ).fetchone()
    if row is None:
        return False
    provided_hash = hashlib.sha256(csrf_header.encode()).hexdigest()
    return hmac.compare_digest(provided_hash, str(row["csrf_hash"]))


def revoke_session(raw_session: str) -> bool:
    if not raw_session:
        return False
    with _connection() as connection:
        cursor = connection.execute(
            "UPDATE auth_sessions SET revoked_at = ? WHERE session_hash = ? AND revoked_at IS NULL",
            (_now_iso(), hashlib.sha256(raw_session.encode()).hexdigest()),
        )
        return cursor.rowcount == 1
