import logging
import logging.handlers
import os
import threading
import queue
from typing import Optional


def _get_app_env():
    """Get APP_ENV from environment or config."""
    try:
        from src.core.config import settings

        return settings.APP_ENV
    except:
        return os.getenv("APP_ENV", "development")


# Centralized root logger configuration
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s [%(name)s]: %(message)s",
)

# Async logging support for production
_log_queue = None
_queue_listener = None


def enable_async_logging():
    """
    Call this once at app startup (in production) to enable async logging using QueueHandler.
    """
    global _log_queue, _queue_listener
    if _log_queue is not None:
        return  # Already enabled
    _log_queue = queue.Queue(-1)
    queue_handler = logging.handlers.QueueHandler(_log_queue)
    root_logger = logging.getLogger()
    # Remove existing handlers and add only the queue handler
    for h in root_logger.handlers[:]:
        root_logger.removeHandler(h)
    root_logger.addHandler(queue_handler)
    # Listener will forward logs to the original handlers
    handlers = []
    # Add a default StreamHandler if no handlers exist
    if not handlers:
        handlers.append(logging.StreamHandler())
    # Add file handlers for any loggers that have them
    for logger_name in logging.root.manager.loggerDict:
        logger = logging.getLogger(logger_name)
        for h in logger.handlers:
            if isinstance(h, logging.FileHandler):
                handlers.append(h)
    _queue_listener = logging.handlers.QueueListener(_log_queue, *handlers)
    _queue_listener.start()


def get_logger(
    name: Optional[str] = None,
    file_output: bool = False,
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 3,
) -> logging.Logger:
    """
    Returns a logger with the given name as a child of the root logger.
    If file_output is True, attaches a RotatingFileHandler to logs/<name>.log (creates logs/ if needed).
    max_bytes: maximum size in bytes before rotation (default 5MB)
    backup_count: number of backup files to keep (default 3)

    Logging levels based on APP_ENV:
    - production: console=WARNING, file=ERROR, logger=WARNING
    - development: console=INFO, file=WARNING, logger=INFO

    Example: get_logger("core", file_output=True)
    """
    is_production = _get_app_env() == "production"

    logger = logging.getLogger(name)

    # Always ensure a StreamHandler for console output first
    if not any(
        isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
        for h in logger.handlers
    ):
        stream_handler = logging.StreamHandler()
        # Production: WARNING, Development: INFO
        stream_handler.setLevel(logging.WARNING if is_production else logging.INFO)
        stream_handler.setFormatter(
            logging.Formatter("[%(asctime)s] %(levelname)s [%(name)s]: %(message)s")
        )
        logger.addHandler(stream_handler)

    if file_output and name:
        # logs/ is now relative to the core/ directory
        log_dir = os.path.join(os.path.dirname(__file__), "../../logs")
        log_dir = os.path.abspath(log_dir)
        log_path = os.path.join(log_dir, f"{name.replace('.', '_')}.log")
        # Ensure all parent directories for log_path exist
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        # Add a new RotatingFileHandler if not present
        if not any(
            isinstance(h, logging.handlers.RotatingFileHandler)
            and getattr(h, "baseFilename", None) == log_path
            for h in logger.handlers
        ):
            file_handler = logging.handlers.RotatingFileHandler(
                log_path, maxBytes=max_bytes, backupCount=backup_count
            )
            # Production: ERROR, Development: WARNING
            file_handler.setLevel(logging.ERROR if is_production else logging.WARNING)
            file_handler.setFormatter(
                logging.Formatter("[%(asctime)s] %(levelname)s [%(name)s]: %(message)s")
            )
            logger.addHandler(file_handler)

    # Don't propagate to avoid duplicate logs since we handle both console and file here
    logger.propagate = False

    # Production: WARNING, Development: INFO
    logger.setLevel(logging.WARNING if is_production else logging.INFO)
    return logger


# Example usage:
# logger = get_logger("core")
# logger.info("Core logger ready!")
