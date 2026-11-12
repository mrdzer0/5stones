"""Contract tests for the application-wide HTTP request body cap."""
from __future__ import annotations

import asyncio
import json
import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.main import app
from backend.utils.request_limits import MAX_HTTP_REQUEST_BYTES, RequestBodyLimitMiddleware


class RequestBodyLimitMiddlewareTests(unittest.TestCase):
    def invoke(self, messages, *, headers=(), max_bytes=4):
        received = list(messages)
        receive_count = 0
        sent = []
        application_called = False

        async def receive():
            nonlocal receive_count
            receive_count += 1
            if received:
                return received.pop(0)
            return {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        async def downstream(_scope, downstream_receive, downstream_send):
            nonlocal application_called
            application_called = True
            body_chunks = []
            while True:
                replayed = await downstream_receive()
                if replayed.get("type") == "http.disconnect":
                    break
                body_chunks.append(replayed.get("body", b""))
                if not replayed.get("more_body", False):
                    break
            body = b"".join(body_chunks)
            await downstream_send({
                "type": "http.response.start", "status": 200, "headers": [],
            })
            await downstream_send({
                "type": "http.response.body", "body": body, "more_body": False,
            })

        scope = {"type": "http", "method": "POST", "path": "/api/test", "headers": list(headers)}
        middleware = RequestBodyLimitMiddleware(downstream, max_bytes=max_bytes)
        asyncio.run(middleware(scope, receive, send))
        status = next(item["status"] for item in sent if item["type"] == "http.response.start")
        body = b"".join(item.get("body", b"") for item in sent if item["type"] == "http.response.body")
        return status, body, receive_count, application_called

    def test_accepts_request_exactly_at_limit_and_replays_chunked_body(self):
        status, body, _receive_count, application_called = self.invoke([
            {"type": "http.request", "body": b"ab", "more_body": True},
            {"type": "http.request", "body": b"cd", "more_body": False},
        ])
        self.assertEqual(status, 200)
        self.assertEqual(body, b"abcd")
        self.assertTrue(application_called)

    def test_rejects_declared_oversize_before_reading_body(self):
        status, body, receive_count, application_called = self.invoke(
            [{"type": "http.request", "body": b"xxxxx", "more_body": False}],
            headers=[(b"content-length", b"5")],
        )
        self.assertEqual(status, 413)
        self.assertEqual(json.loads(body), {"detail": "Request body too large"})
        self.assertEqual(receive_count, 0)
        self.assertFalse(application_called)

    def test_rejects_streamed_oversize_without_content_length(self):
        status, body, receive_count, application_called = self.invoke([
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.request", "body": b"de", "more_body": True},
            {"type": "http.request", "body": b"ignored", "more_body": False},
        ])
        self.assertEqual(status, 413)
        self.assertEqual(json.loads(body), {"detail": "Request body too large"})
        self.assertEqual(receive_count, 2)
        self.assertTrue(application_called)  # It consumed the stream; its response was replaced by 413.

    def test_streamed_size_limit_catches_body_larger_than_declared_length(self):
        status, body, receive_count, _application_called = self.invoke([
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.request", "body": b"de", "more_body": False},
        ], headers=[(b"content-length", b"3")])
        self.assertEqual(status, 413)
        self.assertEqual(json.loads(body), {"detail": "Request body too large"})
        self.assertEqual(receive_count, 2)

    def test_rejects_malformed_or_ambiguous_content_length(self):
        for headers in (
            [(b"content-length", b"four")],
            [(b"content-length", b"4"), (b"content-length", b"4")],
        ):
            with self.subTest(headers=headers):
                status, body, receive_count, application_called = self.invoke(
                    [], headers=headers,
                )
                self.assertEqual(status, 400)
                self.assertEqual(json.loads(body), {"detail": "Malformed Content-Length"})
                self.assertEqual(receive_count, 0)
                self.assertFalse(application_called)

    def test_application_rejects_oversized_api_body_before_auth_or_endpoint(self):
        with patch.dict(os.environ, {
            "APP_ENV": "local_dev", "AUTH_MODE": "disabled", "HOST": "127.0.0.1",
        }, clear=False), TestClient(app) as client:
            response = client.post(
                "/api/projects",
                content=b"x" * (MAX_HTTP_REQUEST_BYTES + 1),
            )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json(), {"detail": "Request body too large"})


if __name__ == "__main__":
    unittest.main()
