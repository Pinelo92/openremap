import logging
import logging.handlers
import os
import queue
from typing import Optional


def _get_app_env() -> str:
    """Get APP_ENV from environment or config."""
    try:
        from api.core.config import settings

        return settings.APP_ENV
    except Exception:
        return os.getenv("APP_ENV", "development")


# Centralized root logger configuration
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s [%(name)s]: %(message)s",
)

# Async logging state
_log_queue: Optional[queue.Queue] = None
_queue_listener: Optional[logging.handlers.QueueListener] = None


def enable_async_logging() -> None:
    """
    Upgrade all existing loggers to async queue-based I/O.

    Call once at app startup (inside setup_app), before serving requests.

    What this does
    --------------
    1. Creates a shared, unbounded Queue.
    2. Iterates the root logger and every named logger that has already been
       created (module-level ``get_logger()`` calls at import time).
    3. Collects all their direct output handlers (StreamHandler,
       RotatingFileHandler, …) and removes them from the loggers.
    4. Replaces each logger's handler list with a single QueueHandler that
       writes log records into the shared queue without blocking.
    5. Starts a QueueListener on a daemon background thread; the listener
       drains the queue and forwards records to all collected output handlers.

    After this call, ``get_logger()`` is also async-aware: any logger created
    later will receive a QueueHandler instead of direct handlers, and any
    requested file handler is registered with the running listener so that it
    is included in the background thread's output chain.
    """
    global _log_queue, _queue_listener

    if _log_queue is not None:
        return  # Already initialised

    q: queue.Queue = queue.Queue(-1)
    _log_queue = q

    collected: list[logging.Handler] = []
    seen_ids: set[int] = set()

    def _swap(lg: logging.Logger) -> None:
        """Replace lg's direct handlers with a QueueHandler; collect originals."""
        for h in lg.handlers[:]:
            if id(h) not in seen_ids:
                collected.append(h)
                seen_ids.add(id(h))
            lg.removeHandler(h)
        lg.addHandler(logging.handlers.QueueHandler(q))

    # Root logger
    _swap(logging.getLogger())

    # Every named logger that exists at startup time
    for logger_name in list(logging.root.manager.loggerDict.keys()):
        candidate = logging.root.manager.loggerDict[logger_name]
        # loggerDict may contain PlaceHolder instances — skip those
        if isinstance(candidate, logging.Logger):
            _swap(candidate)

    # Guarantee at least one output handler
    if not collected:
        collected.append(logging.StreamHandler())

    _queue_listener = logging.handlers.QueueListener(
        q,
        *collected,
        respect_handler_level=True,
    )
    _queue_listener.start()


def _register_file_handler_with_listener(
    log_path: str,
    max_bytes: int,
    backup_count: int,
    is_production: bool,
) -> None:
    """
    Create a RotatingFileHandler for ``log_path`` and attach it to the
    already-running QueueListener.

    The listener's ``handlers`` tuple is replaced atomically (one Python
    attribute write is safe under the GIL) so the background thread sees
    the new handler from the very next record it dequeues.

    No-op if the listener already has a handler for this path.
    """
    if _queue_listener is None:
        return

    existing_paths = {
        getattr(h, "baseFilename", None) for h in _queue_listener.handlers
    }
    if log_path in existing_paths:
        return

    fh = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=max_bytes, backupCount=backup_count
    )
    fh.setLevel(logging.ERROR if is_production else logging.WARNING)
    fh.setFormatter(
        logging.Formatter("[%(asctime)s] %(levelname)s [%(name)s]: %(message)s")
    )

    # Atomically extend the handler list on the live listener.
    # The attribute write is a single pointer swap — safe under the GIL.
    _queue_listener.handlers = tuple(list(_queue_listener.handlers) + [fh])


def get_logger(
    name: Optional[str] = None,
    file_output: bool = False,
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 3,
) -> logging.Logger:
    """
    Return a named logger configured for the current environment and logging mode.

    Async mode (after enable_async_logging() has been called)
    ---------------------------------------------------------
    The logger receives a single QueueHandler pointing at the shared queue.
    All real I/O happens on the background listener thread — request threads
    are never blocked by file or console writes.  If ``file_output=True``,
    the corresponding RotatingFileHandler is registered with the listener.

    Sync mode (CLI or before startup)
    ----------------------------------
    The logger receives direct StreamHandler and, if requested,
    RotatingFileHandler handlers.

    Logging levels based on APP_ENV
    --------------------------------
    - production : console=WARNING, file=ERROR,   logger=WARNING
    - development: console=INFO,    file=WARNING,  logger=INFO

    Example:
        logger = get_logger("core", file_output=True)
    """
    is_production = _get_app_env() == "production"
    logger = logging.getLogger(name)

    if _log_queue is not None:
        # ── Async mode ────────────────────────────────────────────────────
        # Only a QueueHandler on the logger itself; the QueueListener holds
        # all real output handlers.  Never add direct handlers here — they
        # would bypass the queue and write synchronously.
        has_queue_handler = any(
            isinstance(h, logging.handlers.QueueHandler) for h in logger.handlers
        )
        if not has_queue_handler:
            logger.addHandler(logging.handlers.QueueHandler(_log_queue))

        # File handler: register with the running listener (not the logger).
        if file_output and name:
            log_dir = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "../../../logs")
            )
            os.makedirs(log_dir, exist_ok=True)
            log_path = os.path.join(log_dir, f"{name.replace('.', '_')}.log")
            _register_file_handler_with_listener(
                log_path, max_bytes, backup_count, is_production
            )

    else:
        # ── Sync mode (CLI / before startup) ─────────────────────────────
        if not any(
            isinstance(h, logging.StreamHandler)
            and not isinstance(h, logging.FileHandler)
            for h in logger.handlers
        ):
            sh = logging.StreamHandler()
            sh.setLevel(logging.WARNING if is_production else logging.INFO)
            sh.setFormatter(
                logging.Formatter("[%(asctime)s] %(levelname)s [%(name)s]: %(message)s")
            )
            logger.addHandler(sh)

        if file_output and name:
            log_dir = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "../../../logs")
            )
            os.makedirs(log_dir, exist_ok=True)
            log_path = os.path.join(log_dir, f"{name.replace('.', '_')}.log")

            if not any(
                isinstance(h, logging.handlers.RotatingFileHandler)
                and getattr(h, "baseFilename", None) == log_path
                for h in logger.handlers
            ):
                fh = logging.handlers.RotatingFileHandler(
                    log_path, maxBytes=max_bytes, backupCount=backup_count
                )
                fh.setLevel(logging.ERROR if is_production else logging.WARNING)
                fh.setFormatter(
                    logging.Formatter(
                        "[%(asctime)s] %(levelname)s [%(name)s]: %(message)s"
                    )
                )
                logger.addHandler(fh)

    # Never propagate — each logger owns its own output path (queue or direct).
    logger.propagate = False
    logger.setLevel(logging.WARNING if is_production else logging.INFO)
    return logger
