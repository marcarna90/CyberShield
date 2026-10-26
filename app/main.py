"""FastAPI application factory.

Run with ``uvicorn app.main:app`` (Docker does this for you).
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.api.router import api_router
from app.core.config import Settings, get_settings
from app.core.logging import setup_logging
from app.core.middleware import BodySizeLimitMiddleware, RequestContextMiddleware, SecurityHeadersMiddleware
from app.core.rate_limit import RateLimitMiddleware, SlidingWindowRateLimiter
from app.database.init_db import init_database
from app.database.session import configure_database, session_scope

logger = logging.getLogger("cybershield")

DESCRIPTION = """
**CyberShield Enterprise Security Platform** - defensive security automation.

* Host configuration auditing (firewall, accounts, passwords, sudo, SSH, kernel)
* Authorised network discovery and CVE-based vulnerability analysis
* Passive traffic analysis (PCAP upload / sensor)
* Compliance scoring: CIS Controls v8, NIST CSF 2.0, ISO/IEC 27001:2022
* Alerting (log, e-mail, dashboard) and PDF/HTML/JSON reporting

Authenticate with `POST /api/v1/auth/token` (OAuth2 password flow) and send
`Authorization: Bearer <token>`. Every state-changing call is recorded in a
hash-chained audit trail. **Only scan systems you are authorised to test.**
"""


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        settings.ensure_directories()
        setup_logging(settings)
        configure_database(settings.sqlalchemy_url)
        result = init_database(settings)
        if result.admin_created:
            logger.info("Bootstrap administrator created")
        if settings.seed_demo:
            from app.services import demo

            with session_scope() as db:
                if not demo.has_demo_data(db):
                    demo.seed_demo_data(db, settings)
                    logger.info("Demo dataset loaded (CYBERSHIELD_SEED_DEMO=true)")
        logger.info("CyberShield API %s started (%s)", __version__, settings.environment)
        yield

    docs = settings.enable_docs
    app = FastAPI(
        title="CyberShield Enterprise Security Platform",
        version=__version__,
        description=DESCRIPTION,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    prefix = settings.api_prefix

    # Middleware order: the last added runs first (outermost).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_upload_mb * 1024 * 1024 + 64 * 1024)
    app.add_middleware(
        RateLimitMiddleware,
        general=SlidingWindowRateLimiter(settings.rate_limit_per_minute),
        auth=SlidingWindowRateLimiter(settings.auth_rate_limit_per_minute),
        auth_paths=(f"{prefix}/auth/token",),
        exempt_paths=(f"{prefix}/health", f"{prefix}/health/ready"),
    )
    app.add_middleware(SecurityHeadersMiddleware, docs_paths=("/docs", "/redoc", "/docs/oauth2-redirect"))
    app.add_middleware(RequestContextMiddleware)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Never leak stack traces or internals to clients (ASVS 7.4.1).
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(
            {"detail": "Internal server error", "request_id": getattr(request.state, "request_id", None)},
            status_code=500,
        )

    @app.get("/", include_in_schema=False)
    def root() -> dict[str, str]:
        return {"name": "CyberShield", "version": __version__, "docs": "/docs" if docs else "disabled"}

    app.include_router(api_router, prefix=prefix)
    return app


app = create_app()
