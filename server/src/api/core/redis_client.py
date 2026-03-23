from typing import Any, Optional

import redis.asyncio as redis
import json

from api.core.config import settings
from api.core.logger import get_logger
from api.bg_tasks.redis_monitor import redis_memory_monitor

# Clean Redis bash command docker exec -it redis-cache redis-cli FLUSHALL


class RedisClient:
    """Redis client wrapper for caching operations."""

    def __init__(self):
        self.client: Optional[redis.Redis] = None
        self.enabled = settings.REDIS_ENABLED
        self.logger = get_logger("database", file_output=True)

    async def connect(self):
        """Connect to Redis server."""
        if not self.enabled:
            self.logger.info("Redis is disabled in configuration")
            return

        try:
            self.client = redis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
            )
            await self.client.ping()  # type: ignore[misc]  # returns coroutine at runtime despite not being async def
            self.logger.info(f"✅ Connected to Redis at {settings.REDIS_URL}")
            redis_memory_monitor.start(self.client)
        except Exception as e:
            self.logger.error(f"Failed to connect to Redis: {e}")
            self.enabled = False
            self.client = None

    async def disconnect(self):
        """Disconnect from Redis server."""
        if self.client:
            await redis_memory_monitor.stop()
            await self.client.aclose()
            self.logger.info("🛑 Disconnected from Redis")

    async def get(self, key: str) -> Optional[Any]:
        """Get a value from cache."""
        if not self.enabled or not self.client:
            return None
        try:
            value = await self.client.get(key)
            if value:
                self.logger.debug(f"Cache hit for key: {key}")
                return json.loads(value)
            self.logger.debug(f"Cache miss for key: {key}")
            return None
        except Exception as e:
            self.logger.error(f"Error getting key {key} from Redis: {e}")
            return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a value in cache with optional TTL. If ttl is 0 or None, key will not expire."""
        if not self.enabled or not self.client:
            return False
        try:
            serialized = json.dumps(value, default=str)
            if ttl is None or ttl == 0:
                await self.client.set(key, serialized)
                self.logger.debug(f"Cache set for key: {key} with NO TTL (persistent)")
            else:
                await self.client.setex(key, ttl, serialized)
                self.logger.debug(f"Cache set for key: {key} with TTL: {ttl}s")

            return True
        except Exception as e:
            self.logger.error(f"Error setting key {key} in Redis: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete a key from cache."""
        if not self.enabled or not self.client:
            return False
        try:
            await self.client.delete(key)
            self.logger.debug(f"Cache deleted for key: {key}")
            return True
        except Exception as e:
            self.logger.error(f"Error deleting key {key} from Redis: {e}")
            return False

    async def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching a pattern."""
        if not self.enabled or not self.client:
            return 0
        try:
            keys = []
            async for key in self.client.scan_iter(match=pattern):
                keys.append(key)
            if keys:
                deleted = await self.client.delete(*keys)
                self.logger.debug(f"Deleted {deleted} keys matching pattern: {pattern}")
                return deleted
            return 0
        except Exception as e:
            self.logger.error(f"Error deleting pattern {pattern} from Redis: {e}")
            return 0

    async def flush_all(self) -> bool:
        """Flush all keys from Redis (use with caution)."""
        if not self.enabled or not self.client:
            return False
        try:
            await self.client.flushdb()
            self.logger.warning("Flushed all keys from Redis")
            return True
        except Exception as e:
            self.logger.error(f"Error flushing Redis: {e}")
            return False


# Global Redis client instance
redis_client = RedisClient()
