from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.core.config import settings
from api.core.logger import get_logger

# from api.core.mongodb import database
from api.core.redis_client import redis_client

logger = get_logger("app", file_output=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown."""
    logger.info(f"Application Environment: ⭐ {settings.APP_ENV} ⭐")

    # --- MongoDB ---
    # try:
    #     await database.command("ping")
    #     logger.info("✅ MongoDB connection verified")
    # except Exception as e:
    #     logger.error(f"❌ MongoDB connection failed: {e}")
    #     raise

    # --- Redis ---
    # await redis_client.connect()

    yield

    # --- Shutdown ---
    # await redis_client.disconnect()
    logger.info("🛑 API shut down")
