"""
event_bus.py - In-Process Event Bus
----------------------------------------------------------------------------
A thread-safe broadcast queue that agents publish events to, and the
FastAPI WebSocket endpoint consumes from.

All agents import this module and call `publish(event)`.
The WebSocket handler subscribes with `subscribe()` / `unsubscribe()`.

Events are plain dicts with at minimum:
    {
        "type":      "ALERT" | "INVESTIGATION" | "RESPONSE" | "LOG" | "STATUS",
        "agent":     "SENTRY" | "INVESTIGATOR" | "RESPONDER" | "SYSTEM",
        "timestamp": "<ISO string>",
        "data":      { ... }    # event-specific payload
    }
----------------------------------------------------------------------------
"""

import queue
import threading
import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_subscribers: list[queue.Queue] = []


def publish(event: dict):
    """
    Broadcast an event to all active WebSocket subscribers.
    If `timestamp` is missing, it is added automatically.
    Non-blocking: uses put_nowait; full queues are silently dropped.
    """
    if "timestamp" not in event:
        event["timestamp"] = datetime.now().isoformat()

    with _lock:
        dead = []
        for q in _subscribers:
            try:
                q.put_nowait(event)
            except queue.Full:
                dead.append(q)   # subscriber too slow — remove
        for q in dead:
            _subscribers.remove(q)
            logger.debug("[EventBus] Removed slow subscriber.")


def subscribe(maxsize: int = 500) -> queue.Queue:
    """Register a new subscriber. Returns a Queue to read events from."""
    q: queue.Queue = queue.Queue(maxsize=maxsize)
    with _lock:
        _subscribers.append(q)
    logger.debug(f"[EventBus] New subscriber. Total: {len(_subscribers)}")
    return q


def unsubscribe(q: queue.Queue):
    """Deregister a subscriber when its WebSocket closes."""
    with _lock:
        try:
            _subscribers.remove(q)
        except ValueError:
            pass
    logger.debug(f"[EventBus] Subscriber removed. Total: {len(_subscribers)}")


def make_event(
    event_type: str,
    agent: str,
    data: Any,
    severity: str = "INFO",
) -> dict:
    """Convenience builder for a standard event dict."""
    return {
        "type":      event_type.upper(),
        "agent":     agent.upper(),
        "severity":  severity.upper(),
        "timestamp": datetime.now().isoformat(),
        "data":      data,
    }
