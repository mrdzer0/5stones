"""Bound HTTP request bodies before endpoint parsing or persistence."""
from __future__ import annotations

import json
from typing import Any


# Uploads are capped at 5 MiB in artifact_file_service. The additional 1 MiB
# accommodates multipart boundaries and form fields without permitting an
# unbounded JSON/API request body.
MAX_HTTP_REQUEST_BYTES = 6 * 1024 * 1024


class RequestBodyLimitMiddleware:
    """Bound request bodies at the ASGI receive boundary.

    Bodies are counted as downstream code consumes them; oversized chunked
    requests trigger a disconnect that is translated into a generic 413. This
    avoids buffering uploaded documents in this middleware. It is not a
    substitute for gateway rate/concurrency controls in a multi-worker
    deployment.
    """

    def __init__(self, app, *, max_bytes: int = MAX_HTTP_REQUEST_BYTES):
        if not isinstance(max_bytes, int) or max_bytes <= 0:
            raise ValueError("max_bytes must be a positive integer")
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict[str, Any], receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        lengths = [value for key, value in scope.get("headers", []) if key.lower() == b"content-length"]
        if len(lengths) > 1:
            await self._respond(send, 400, "Malformed Content-Length")
            return
        if lengths:
            if not lengths[0].isdigit():
                await self._respond(send, 400, "Malformed Content-Length")
                return
            try:
                declared_length = int(lengths[0].decode("ascii"))
            except (UnicodeDecodeError, ValueError):
                await self._respond(send, 400, "Malformed Content-Length")
                return
            if declared_length > self.max_bytes:
                await self._respond(send, 413, "Request body too large")
                return

        total = 0
        too_large = False
        response_started = False

        async def limited_receive():
            nonlocal total, too_large
            if too_large:
                return {"type": "http.disconnect"}
            message = await receive()
            if message.get("type") == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_bytes:
                    too_large = True
                    return {"type": "http.disconnect"}
            return message

        async def limited_send(message: dict[str, Any]) -> None:
            nonlocal response_started
            if not too_large:
                await send(message)
                if message.get("type") == "http.response.start":
                    response_started = True
                return
            if message.get("type") == "http.response.start" and not response_started:
                response_started = True
                body = json.dumps(
                    {"detail": "Request body too large"}, separators=(",", ":")
                ).encode("utf-8")
                await send({
                    "type": "http.response.start",
                    "status": 413,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode("ascii")),
                    ],
                })
                await send({"type": "http.response.body", "body": body, "more_body": False})

        try:
            await self.app(scope, limited_receive, limited_send)
        except Exception:
            if not too_large:
                raise
            if not response_started:
                await self._respond(send, 413, "Request body too large")
            return
        if too_large and not response_started:
            await self._respond(send, 413, "Request body too large")

    @staticmethod
    async def _respond(send, status_code: int, detail: str) -> None:
        body = json.dumps({"detail": detail}, separators=(",", ":")).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": body, "more_body": False})
