import asyncio
from typing import TYPE_CHECKING, Optional

from api.core.logger import get_logger

if TYPE_CHECKING:
    import redis.asyncio as redis

logger = get_logger("redis_monitor", file_output=True)

MEMORY_WARNING_THRESHOLD_MB = 500
CHECK_INTERVAL_SECONDS = 60


class RedisMemoryMonitor:
    """
    Background task that periodically checks Redis memory usage.
    Completely decoupled from cache read/write operations.
    """

    def __init__(self):
        self._task: Optional[asyncio.Task] = None
        self._client: Optional["redis.Redis"] = None

    def start(self, client: "redis.Redis") -> None:
        """Start the background memory monitor task."""
        if self._task is not None and not self._task.done():
            logger.warning("Redis memory monitor is already running")
            return

        self._client = client
        self._task = asyncio.create_task(self._run(), name="redis_memory_monitor")
        logger.info(
            f"🔍 Redis memory monitor started "
            f"(interval: {CHECK_INTERVAL_SECONDS}s, threshold: {MEMORY_WARNING_THRESHOLD_MB}MB)"
        )

    async def stop(self) -> None:
        """Cancel the background monitor task cleanly."""
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            logger.info("🛑 Redis memory monitor stopped")
        self._task = None
        self._client = None

    async def _run(self) -> None:
        """Main loop — runs every CHECK_INTERVAL_SECONDS."""
        while True:
            await asyncio.sleep(CHECK_INTERVAL_SECONDS)
            await self._check_memory()

    async def _check_memory(self) -> None:
        """Fetch memory info from Redis and log a warning if threshold is exceeded."""
        if self._client is None:
            return
        try:
            memory_info = await self._client.info("memory")  # type: ignore[misc]
            used_mb = memory_info.get("used_memory", 0) / 1024 / 1024
            peak_mb = memory_info.get("used_memory_peak", 0) / 1024 / 1024
            logger.debug(f"Redis memory — used: {used_mb:.2f}MB, peak: {peak_mb:.2f}MB")
            if used_mb > MEMORY_WARNING_THRESHOLD_MB:
                logger.warning(
                    f"⚠️  Redis memory usage high: {used_mb:.2f}MB "
                    f"(threshold: {MEMORY_WARNING_THRESHOLD_MB}MB, peak: {peak_mb:.2f}MB)"
                )
        except Exception as e:
            logger.error(f"Failed to check Redis memory: {e}")


# Global monitor instance
redis_memory_monitor = RedisMemoryMonitor()
