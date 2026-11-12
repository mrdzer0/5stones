#!/usr/bin/env python3
"""Create a local 5STONES user in the SQLite auth database.

Password input is hidden and never accepted as a command-line argument.
Run from the repository root with: python3 scripts/seed_local_user.py
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

from backend.services import local_auth_service


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a local account in the 5STONES SQLite auth database.")
    parser.add_argument("--email", help="Account email; prompted when omitted.")
    parser.add_argument("--display-name", default="", help="Optional display name.")
    parser.add_argument(
        "--workspace-id",
        default="",
        help="Optional unique workspace override (defaults to a new account-specific ID).",
    )
    parser.add_argument(
        "--role",
        choices=sorted(local_auth_service.ALLOWED_ROLES),
        default="admin",
        help="Initial role. Defaults to admin for first-time local setup.",
    )
    parser.add_argument(
        "--adopt-legacy-projects",
        action="store_true",
        help="Assign projects without a workspace_id to this workspace.",
    )
    return parser.parse_args()


def adopt_legacy_projects(workspace_id: str) -> int:
    from backend.utils.storage import claim_legacy_project, list_unscoped_projects

    adopted = 0
    for project in list_unscoped_projects():
        if claim_legacy_project(str(project.get("project_id") or ""), workspace_id):
            adopted += 1
    return adopted


def main() -> int:
    args = parse_args()
    if os.getenv("APP_ENV", "local_dev").strip().casefold() == "enterprise":
        print("Refusing to create a local account while APP_ENV=enterprise; use the configured OIDC identity provider.", file=sys.stderr)
        return 2
    if args.adopt_legacy_projects and local_auth_service.user_count() != 0:
        print("Legacy adoption is available only while creating the first local account. Use the dashboard recovery action for the existing sole admin account.", file=sys.stderr)
        return 2
    if args.adopt_legacy_projects and args.role != "admin":
        print("Legacy adoption requires the initial account to have the admin role.", file=sys.stderr)
        return 2
    email = (args.email or input("Email: ")).strip()
    password = getpass.getpass("Password (minimum 12 characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        print("Passwords do not match; no account was created.", file=sys.stderr)
        return 2
    try:
        workspace_id = args.workspace_id.strip() or local_auth_service.new_account_workspace_id()
        user = local_auth_service.create_user(
            email,
            password,
            workspace_id=workspace_id,
            role=args.role,
            display_name=args.display_name,
        )
    except (local_auth_service.DuplicateUserError, local_auth_service.InvalidUserInputError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    adopted = adopt_legacy_projects(workspace_id) if args.adopt_legacy_projects else 0
    print(f"Created {user['role']} account {user['email']} in workspace {user['workspace_id']}.")
    print(f"Auth database: {local_auth_service.database_path()}")
    if args.adopt_legacy_projects:
        print(f"Legacy projects assigned to workspace: {adopted}")
    print("The password is stored as a salted PBKDF2-HMAC-SHA256 hash.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
