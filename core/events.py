"""Lightweight pub/sub for application events.

The :class:`EventBus` is thread-safe. Handlers are called sequentially from
the emitter's thread; exceptions raised by a handler are logged and the
remaining handlers still run (Section 2 #8).
"""

import logging
import threading
from typing import Callable, Any
from collections import defaultdict

logger = logging.getLogger("wimirage")

__all__ = ["EventBus"]


class EventBus:
    """Thread-safe pub/sub. Iterates over a snapshot of subscribers per emit."""

    def __init__(self) -> None:
        self._listeners: dict[str, list[Callable]] = defaultdict(list)
        self._lock = threading.Lock()

    def on(self, event: str, callback: Callable) -> None:
        """Subscribe ``callback`` to ``event``."""
        with self._lock:
            self._listeners[event].append(callback)

    def off(self, event: str, callback: Callable) -> None:
        """Unsubscribe ``callback`` from ``event``. No-op if not subscribed."""
        with self._lock:
            if event in self._listeners:
                self._listeners[event] = [
                    cb for cb in self._listeners[event] if cb != callback
                ]

    def emit(self, event: str, *args: Any, **kwargs: Any) -> None:
        """Fire ``event`` to all subscribers; isolate each handler's exceptions.

        Handlers run sequentially on the caller's thread. A failing handler
        does NOT prevent later handlers from running, but is logged at ERROR.
        """
        with self._lock:
            callbacks = list(self._listeners.get(event, []))
        for callback in callbacks:
            try:
                callback(*args, **kwargs)
            except Exception as e:
                # Event handlers are user-supplied; we don't know which
                # exception types they may raise. Logging + continuing is
                # the right contract — one buggy listener must not silence
                # other listeners or crash the bus.
                logger.error(f"Event handler error for '{event}': {type(e).__name__}: {e}")
