import copy
import json
import unittest

from backend.services.artifact_reconciliation_service import (
    capture_manual_context,
    rebuild_project_from_artifacts,
)
from backend.services.parser_service import parse_openapi_document, parse_postman_document


OPENAPI = {
    "openapi": "3.0.1",
    "info": {"title": "Identity API", "version": "1"},
    "security": [{"bearerAuth": []}],
    "paths": {
        "/identity/api/auth/login": {
            "post": {
                "tags": ["Identity / Auth"],
                "summary": "Authenticate a user with email and password",
                "security": [],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/LoginRequest"}
                        }
                    }
                },
                "responses": {"200": {"description": "OK"}},
            }
        },
        "/identity/api/v2/user/{userId}": {
            "get": {
                "tags": ["Identity / User"],
                "summary": "Retrieve the current user profile securely",
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/User"}
                            }
                        },
                    }
                },
            }
        },
    },
    "components": {
        "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
        "schemas": {
            "LoginRequest": {
                "type": "object",
                "properties": {"email": {"type": "string"}, "password": {"type": "string"}},
            },
            "User": {
                "type": "object",
                "properties": {"id": {"type": "string"}, "email": {"type": "string"}},
            },
        },
    },
}

POSTMAN = {
    "collection": {
        "info": {
            "name": "Identity scenarios",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "never-store-this"}]},
        "item": [
            {
                "name": "Authentication",
                "item": [
                    {
                        "name": "Valid login",
                        "request": {
                            "method": "POST",
                            "auth": {"type": "noauth"},
                            "url": {"raw": "{{url}}/identity/api/auth/login", "path": ["identity", "api", "auth", "login"]},
                            "body": {"mode": "raw", "raw": json.dumps({"email": "user@example.test", "password": "top-secret"})},
                        },
                    },
                    {
                        "name": "Invalid login",
                        "request": {
                            "method": "POST",
                            "auth": {"type": "noauth"},
                            "url": {"raw": "{{url}}/identity/api/auth/login", "path": ["identity", "api", "auth", "login"]},
                            "body": {"mode": "raw", "raw": json.dumps({"email": "bad@example.test", "password": "wrong"})},
                        },
                    },
                ],
            },
            {
                "name": "Get profile",
                "request": {
                    "method": "GET",
                    "url": {
                        "raw": "{{url}}/identity/api/v2/user/{{user_id}}",
                        "path": ["identity", "api", "v2", "user", "{{user_id}}"],
                    },
                },
            },
            {
                "name": "Undocumented health",
                "request": {"method": "GET", "auth": {"type": "noauth"}, "url": "{{url}}/health"},
            },
        ],
    }
}


class StructuredArtifactParsingTests(unittest.TestCase):
    def test_openapi_parser_extracts_contract_semantics(self):
        result = parse_openapi_document(copy.deepcopy(OPENAPI))
        self.assertEqual(result["stats"]["operation_count"], 2)
        self.assertEqual(result["operations"][0]["security_status"], "public")
        secured = next(item for item in result["operations"] if item["method"] == "GET")
        self.assertEqual(secured["security_status"], "secured")
        self.assertIn("email", result["data_fields"])
        self.assertIn("http bearer", result["auth_methods"])

    def test_postman_parser_unwraps_collection_and_keeps_scenarios(self):
        result = parse_postman_document(copy.deepcopy(POSTMAN))
        self.assertTrue(result["parser"]["wrapped"])
        self.assertEqual(result["stats"]["request_count"], 4)
        self.assertEqual(result["stats"]["operation_count"], 3)
        self.assertEqual(result["stats"]["duplicate_scenario_count"], 1)
        login = next(item for item in result["operations"] if item["path"].endswith("/login"))
        self.assertEqual(len(login["scenarios"]), 2)
        profile = next(item for item in result["operations"] if "user_id" in item["path"])
        self.assertEqual(profile["security_status"], "secured")
        serialized = json.dumps(result)
        self.assertNotIn("top-secret", serialized)
        self.assertNotIn("never-store-this", serialized)
        self.assertNotIn("{{url}}", serialized)

    def test_postman_parser_preserves_safe_variable_and_response_metadata(self):
        document = copy.deepcopy(POSTMAN)
        document["collection"]["event"] = [{
            "listen": "test",
            "script": {"exec": ["pm.environment.set('token', 'secret-response-token')"]},
        }]
        document["collection"]["item"][1]["response"] = [{
            "name": "Profile response",
            "status": "OK",
            "code": 200,
            "header": [{"key": "Content-Type", "value": "application/json"}],
            "body": json.dumps({"user": {"id": "user-1", "email": "secret@example.test"}}),
        }]

        result = parse_postman_document(document)
        profile = next(item for item in result["operations"] if "user_id" in item["path"])
        serialized = json.dumps(result)

        self.assertIn("url", profile["unresolved_variable_refs"])
        self.assertIn("user_id", profile["unresolved_variable_refs"])
        self.assertEqual(profile["response_fields"], ["user", "user.id", "user.email"])
        self.assertEqual(profile["saved_response_examples"][0]["header_names"], ["Content-Type"])
        self.assertEqual(result["stats"]["ignored_script_count"], 1)
        self.assertTrue(any("not executed" in warning for warning in result["warnings"]))
        self.assertNotIn("secret-response-token", serialized)
        self.assertNotIn("secret@example.test", serialized)

    def test_generic_route_prefixes_do_not_become_fake_services(self):
        document = {
            "info": {"name": "Generic API routes"},
            "item": [
                {
                    "name": "OpenID configuration",
                    "request": {"method": "GET", "url": "{{url}}/.well-known/openid-configuration"},
                },
                {
                    "name": "Health check",
                    "request": {"method": "GET", "url": "{{url}}/api/health"},
                },
            ],
        }

        result = parse_postman_document(document)

        self.assertEqual(
            {operation["service"] for operation in result["operations"]},
            {"Application API"},
        )
        self.assertEqual(
            {flow["destination"] for flow in result["data_flows"]},
            {"Application API"},
        )

    def test_reconciliation_is_order_independent_and_preserves_manual_context(self):
        openapi = parse_openapi_document(copy.deepcopy(OPENAPI))
        postman = parse_postman_document(copy.deepcopy(POSTMAN))
        sources = [
            {
                "artifact_id": "oas",
                "artifact_type": "openapi",
                "filename": "api.json",
                "content_hash": "a",
                "active": True,
                "contribution": openapi,
            },
            {
                "artifact_id": "postman",
                "artifact_type": "postman",
                "filename": "collection.json",
                "content_hash": "b",
                "active": True,
                "contribution": postman,
            },
        ]
        base = {
            "actors": ["Customer"],
            "components": [],
            "entry_points": ["Web App"],
            "data_involved": [],
            "external_systems": [],
            "critical_actions": [],
            "existing_controls": [],
            "auth_method": "",
            "artifact_sources": [],
        }
        capture_manual_context(base)
        first = rebuild_project_from_artifacts({**copy.deepcopy(base), "artifact_sources": copy.deepcopy(sources)})
        second = rebuild_project_from_artifacts({**copy.deepcopy(base), "artifact_sources": list(reversed(copy.deepcopy(sources)))})

        self.assertEqual(first["canonical_operations"], second["canonical_operations"])
        self.assertEqual(first["entry_points"], second["entry_points"])
        self.assertEqual(first["artifact_inventory"]["operation_count"], 3)
        self.assertEqual(first["artifact_inventory"]["overlap_count"], 2)
        self.assertIn("Web App", first["entry_points"])
        self.assertNotIn("API", first["entry_points"])
        self.assertTrue(any(item["coverage"] == "collection_only" for item in first["canonical_operations"]))


if __name__ == "__main__":
    unittest.main()
