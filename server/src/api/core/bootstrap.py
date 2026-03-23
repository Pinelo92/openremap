from fastapi import FastAPI, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from api.core.config import settings
from api.core.limiter import limiter
from api.core.logger import enable_async_logging, get_logger
from api.core.router_v1 import router_v1

logger = get_logger("app", file_output=True)


def setup_app(app: FastAPI):
    """
    Orchestrates the initialization of the FastAPI application.
    """
    # 1. Logging
    enable_async_logging()

    # 2. Rate Limiting
    app.state.limiter = limiter

    def _slowapi_rate_limit_handler(request: Request, exc: Exception):
        """
        Type-stable wrapper for slowapi's handler.

        FastAPI's add_exception_handler expects a handler typed to accept
        `Exception` as the second parameter. slowapi's `_rate_limit_exceeded_handler`
        is typed to accept `RateLimitExceeded`, which causes static type checkers
        to complain (incompatible function types). This wrapper accepts any
        Exception, checks it's the expected type at runtime, then delegates to
        slowapi's handler.
        """
        if isinstance(exc, RateLimitExceeded):
            return _rate_limit_exceeded_handler(request, exc)
        raise exc

    app.add_exception_handler(RateLimitExceeded, _slowapi_rate_limit_handler)
    logger.info(
        f"Rate limiter storage: {'redis' if settings.REDIS_ENABLED else 'memory'}"
    )

    # 3. Middleware
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 4. Routing
    app.include_router(router_v1)

    return app
