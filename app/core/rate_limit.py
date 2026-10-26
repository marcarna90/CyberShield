"""In-process sliding-window rate limiting (OWASP ASVS 11.1.4 / 2.2.1).

Two buckets are used: a general limit per client IP and a stricter limit for
authentication endpoints (brute-force protection, complementary to account
lockout). For multi-instance deployments put a shared limiter (e.g. Redis or
the reverse proxy) in front - this one is per process.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp


class SlidingWindowRateLimiter:
    """Thread-safe sliding window limiter keyed by an arbitrary string."""

    def __init__(
        self,
        limit: int,
        window_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 50_000,
    ) -> None:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        self.limit = limit
        self.window = window_seconds
        self._clock = clock
        self._max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str) -> tuple[bool, float]:
        """Register a hit. Returns ``(allowed, retry_after_seconds)``."""
        now = self._clock()
        with self._lock:
            if len(self._hits) > self._max_keys:
                self._evict(now)
            bucket = self._hits.setdefault(key, deque())
            while bucket and now - bucket[0] >= self.window:
                bucket.popleft()
            if len(bucket) >= self.limit:
                retry_after = self.window - (now - bucket[0])
                return False, max(retry_after, 0.0)
            bucket.append(now)
            return True, 0.0

    def _evict(self, now: float) -> None:
        stale = [k for k, b in self._hits.items() if not b or now - b[-1] >= self.window]
        for key in stale:
            del self._hits[key]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Apply per-IP limits; stricter bucket for authentication paths."""

    def __init__(
        self,
        app: ASGIApp,
        general: SlidingWindowRateLimiter,
        auth: SlidingWindowRateLimiter,
        auth_paths: tuple[str, ...],
        exempt_paths: tuple[str, ...] = (),
    ) -> None:
        super().__init__(app)
        self.general = general
        self.auth = auth
        self.auth_paths = auth_paths
        self.exempt_paths = exempt_paths

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path
        if path in self.exempt_paths:
            return await call_next(request)
        client = request.client.host if request.client else "unknown"
        limiter, bucket = (self.auth, "auth") if path in self.auth_paths else (self.general, "api")
        allowed, retry_after = limiter.hit(f"{bucket}:{client}")
        if not allowed:
            return JSONResponse(
                {"detail": "Too many requests. Please retry later."},
                status_code=429,
                headers={"Retry-After": str(int(retry_after) + 1)},
            )
        return await call_next(request)
