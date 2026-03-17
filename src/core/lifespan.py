import asyncio
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI

# from app.cache.nation_geometries import get_all_nation_geometries_from_cache
from src.core.config import settings
from src.core.logger import get_logger

# from app.core.utils.populate_redis_nation_geometry import NationsGeometry
# from app.core.utils.populate_redis_district_geometries import (
#    populate_district_geometries_to_redis,
# )
# from app.core.websocket.ws_endpoint import start_websocket_engine
from src.core.mongodb import database
from src.core.redis_client import redis_client
# from engine.rasty_events import event_listener

logger = get_logger("app", file_output=True)

# try:
#     import rasty
# except ImportError:
#     rasty = None
#     logger.warning("Rasty not available in API")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown."""
    logger.info(f"Application Environment: ⭐ {settings.APP_ENV} ⭐")

    # --- Startup Logic ---
    try:
        await database.command("ping")
        logger.info("✅ MongoDB connection verified")
    except Exception as e:
        logger.error(f"❌ MongoDB connection failed: {e}")
        raise

    # Connect and Populate Cache
    await redis_client.connect()
    # await populate_district_geometries_to_redis()

    # Nation Geometry Logic
    # await NationsGeometry(redis_client).ensure_all_nations()

    # --- Start WebSocket Engine ---
    # await start_websocket_engine()
    # logger.info("⚡ WebSocket PubSub Engine started")

    # --- Initialize Rasty for Fast Queries (Read-Only) ---
    # if rasty:
    #     try:
    #         py_geometries = await get_all_nation_geometries_from_cache(
    #             redis_client.client
    #         )
    #         rust_payload = []
    #         if py_geometries:
    #             for code, geo_dict in py_geometries.items():
    #                 if geo_dict:
    #                     rust_payload.append((str(code), json.dumps(geo_dict)))

    #         app.state.rasty_map = rasty.WorldMap(rust_payload)

    #         from app.core.utils.rasty_integration import set_rasty_map

    #         set_rasty_map(app.state.rasty_map)

    #         logger.info(f"🦀 Rasty initialized in API ({len(rust_payload)} nations)")

    #         # Start listening for updates from Engine
    #         listener_task = asyncio.create_task(event_listener.start_listening())
    #         logger.info("🎧 Started listening for Rasty updates from Engine")

    #     except Exception as e:
    #         logger.error(f"Failed to initialize Rasty: {e}")
    #         app.state.rasty_map = None
    # else:
    #     app.state.rasty_map = None
    #     logger.warning("🦀 Rasty not available - queries will be slower")

    # Note: Game engine (Scheduler + Tasks) runs in separate service
    # Run with: python -m engine.main
    # logger.info("ℹ️  Game engine scheduler running separately (engine.main)")

    yield

    # Stop event listener
    # await event_listener.stop()

    # --- Shutdown Logic ---
    await redis_client.disconnect()
    logger.info("🛑 API shut down")
