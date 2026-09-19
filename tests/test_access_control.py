import os
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from backend.utils.access_control import (
    authorize_project,
    require_workspace_access,
    workspace_id_for_request,
)


def request_with_headers(**headers) -> Request:
    encoded = [(key.replace("_", "-").encode(), value.encode()) for key, value in headers.items()]
    return Request({
        "type": "http",
        "method": "GET",
        "path": "/api/projects/project-1",
        "headers": encoded,
    })


class AccessControlTests(unittest.TestCase):
    def test_local_mode_keeps_existing_mvp_access(self):
        request = request_with_headers()
        with patch.dict(os.environ, {"WORKSPACE_AUTH_REQUIRED": "false"}, clear=False):
            self.assertIsNone(require_workspace_access(request))
            self.assertEqual(workspace_id_for_request(request), None)
            self.assertEqual(authorize_project(request, {"project_id": "project-1"})["project_id"], "project-1")

    def test_enabled_mode_requires_matching_workspace_token(self):
        request = request_with_headers(
            x_workspace_id="team-a",
            authorization="Bearer token-a",
        )
        env = {
            "WORKSPACE_AUTH_REQUIRED": "true",
            "WORKSPACE_AUTH_TOKENS_JSON": '{"team-a":"token-a","team-b":"token-b"}',
        }
        with patch.dict(os.environ, env, clear=False):
            self.assertEqual(require_workspace_access(request), "team-a")
            self.assertEqual(workspace_id_for_request(request), "team-a")
            project = {"project_id": "project-1", "workspace_id": "team-a"}
            self.assertIs(authorize_project(request, project), project)

    def test_cross_workspace_project_is_hidden(self):
        request = request_with_headers(
            x_workspace_id="team-a",
            authorization="Bearer token-a",
        )
        env = {
            "WORKSPACE_AUTH_REQUIRED": "true",
            "WORKSPACE_AUTH_TOKENS_JSON": '{"team-a":"token-a"}',
        }
        with patch.dict(os.environ, env, clear=False):
            require_workspace_access(request)
            with self.assertRaisesRegex(HTTPException, "Project not found") as raised:
                authorize_project(request, {"project_id": "project-2", "workspace_id": "team-b"})
            self.assertEqual(raised.exception.status_code, 404)

    def test_enabled_mode_fails_closed_without_token_configuration(self):
        request = request_with_headers(
            x_workspace_id="team-a",
            authorization="Bearer token-a",
        )
        env = {
            "WORKSPACE_AUTH_REQUIRED": "true",
            "WORKSPACE_AUTH_TOKENS_JSON": "",
        }
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaisesRegex(HTTPException, "no tokens are configured") as raised:
                require_workspace_access(request)
            self.assertEqual(raised.exception.status_code, 503)


if __name__ == "__main__":
    unittest.main()
