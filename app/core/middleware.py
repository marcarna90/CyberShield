"""HTTP hardening middlewares: security headers, request IDs, body size limits."""

from __future__ import annotations

import logging
import re
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

logger = logging.getLogger("cybershield.http")
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9\-]{8,64}$")

_API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
# Swagger UI / ReDoc load assets from a CDN; keep a constrained policy for them.
_DOCS_CSP = (
    "default-src 'self'; img-src 'self' data: https://fastapi.tiangolo.com; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; frame-ancestors 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add OWASP-recommended response headers."""

    def __init__(self, app: ASGIApp, docs_paths: tuple[str, ...] = ()) -> None:
        super().__init__(app)
        self.docs_paths = docs_paths

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        is_docs = request.url.path in self.docs_paths
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Content-Security-Policy", _DOCS_CSP if is_docs else _API_CSP)
        if not is_docs:
            response.headers.setdefault("Cache-Control", "no-store")
        if request.url.scheme == "https":
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Propagate/assign ``X-Request-ID`` and log one access line per request."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming = request.headers.get("X-Request-ID", "")
        request_id = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex
        request.state.request_id = request_id
        started = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "%s %s -> %s",
            request.method,
            request.url.path,
            response.status_code,
            extra={
                "request_id": request_id,
                "client_ip": request.client.host if request.client else None,
                "duration_ms": elapsed_ms,
            },
        )
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests whose declared Content-Length exceeds ``max_bytes``."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                too_big = int(declared) > self.max_bytes
            except ValueError:
                return JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)
            if too_big:
                return JSONResponse({"detail": "Request body too large"}, status_code=413)
        return await call_next(request)
