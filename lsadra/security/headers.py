"""Security headers, request IDs and generic errors (G-11, ASVS 5.0 V3.4, V16.5.1).

``SecurityHeadersMiddleware`` is a plain ASGI middleware (no response
buffering, so streaming and WebSockets are untouched). On every HTTP response
it sets:

* ``Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; ...``
  The API returns JSON and files, never pages, so nothing may load or frame it.
  The OpenAPI pages (dev mode only) get no CSP, since they load their own assets.
* ``X-Content-Type-Options: nosniff``, ``X-Frame-Options: DENY``,
  ``Referrer-Policy: no-referrer``, ``Permissions-Policy`` (no camera,
  microphone or location), ``Cross-Origin-Opener-Policy: same-origin``.
* ``Cache-Control: no-store`` on /api/ responses, which carry security data.
* ``Strict-Transport-Security`` when the request arrived over HTTPS.
* ``X-Request-ID``: echoed from a well-formed incoming header or generated.

``install_error_handlers`` replaces the default 500 body with a generic message
plus that request ID, and logs the exception under the same ID, so no stack or
exception text reaches a client.
"""

import logging
import re
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from lsadra import config

logger = logging.getLogger(__name__)

API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
_DOC_PATHS = ("/docs", "/redoc", "/openapi.json")
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")

_STATIC_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
    (b"cross-origin-opener-policy", b"same-origin"),
]


def _is_https(scope) -> bool:
    if scope.get("scheme") == "https":
        return True
    client = scope.get("client")
    if client and client[0] in config.TRUSTED_PROXY_IPS:
        for name, value in scope.get("headers", []):
            if name == b"x-forwarded-proto":
                return value.decode("latin-1").strip().lower() == "https"
    return False


class SecurityHeadersMiddleware:
    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        incoming = ""
        for name, value in scope.get("headers", []):
            if name == b"x-request-id":
                incoming = value.decode("latin-1")
                break
        request_id = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        https = _is_https(scope)

        async def _send(message):
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", [])]
                present = {k.lower() for k, _ in headers}
                extra = list(_STATIC_HEADERS)
                if not path.startswith(_DOC_PATHS):
                    extra.append((b"content-security-policy", API_CSP.encode()))
                if path.startswith("/api/"):
                    extra.append((b"cache-control", b"no-store"))
                if https:
                    extra.append((
                        b"strict-transport-security",
                        f"max-age={config.HSTS_MAX_AGE_SECONDS}; includeSubDomains".encode(),
                    ))
                extra.append((b"x-request-id", request_id.encode()))
                headers.extend((k, v) for k, v in extra if k not in present)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, _send)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):  # pragma: no cover - exercised in tests
        request_id = getattr(request.state, "request_id", None) or uuid.uuid4().hex
        logger.error("Unhandled error [request %s] on %s %s", request_id, request.method,
                     request.url.path, exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error.", "request_id": request_id},
            headers={"X-Request-ID": request_id},
        )
