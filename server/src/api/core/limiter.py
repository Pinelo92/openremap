from slowapi import Limiter
from slowapi.util import get_remote_address

from api.core.config import settings

# --- Setup ---
_storage_uri = settings.REDIS_URL if settings.REDIS_ENABLED else None

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=_storage_uri,
    # This protects ANY endpoint we forgot to specifically limit
    default_limits=["200/hour"],
)


# --- Profiles ---
class AuthLimits:
    """Strict limits for sensitive security endpoints.
    STRICT: 5/minute
    STANDARD: 10/minute
    RECOVERY: 3/hour"""

    STRICT = "5/minute"  # For Registration
    STANDARD = "10/minute"  # For Login
    RECOVERY = "3/hour"  # For Forgot Password


class ApiLimits:
    """General limits for standard data operations."""

    READ = "100/minute"  # For GET requests
    WRITE = "30/minute"  # For POST/PUT requests
    SEARCH = "20/minute"  # For heavy DB queries
