"""SSE (Server-Sent Events) publisher for real-time scan progress.

Keeps an in-memory dict of active report_id -> list[event]. The SSE
endpoint streams these events to the frontend via EventSource.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import defaultdict
from typing import Any, Optional

logger = logging.getLogger(__name__)


class SSEPublisher:
    """SSE event publisher keyed by report_id.

    emit() is called from background (non-async) threads.
    subscribe() is always called from an async context (the SSE endpoint).
    Thread-safety is achieved via loop.call_soon_threadsafe().
    """

    def __init__(self) -> None:
        self._events: dict[int, list[dict[str, Any]]] = defaultdict(list)
        self._subscribers: dict[int, list[asyncio.Queue]] = defaultdict(list)
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def emit(self, report_id: int, event_type: str, data: dict[str, Any]) -> None:
        """Publish an event. Safe to call from any thread."""
        event = {
            "event": event_type,
            "data": data,
            "timestamp": time.time(),
        }
        self._events[report_id].append(event)

        loop = self._loop
        for queue in self._subscribers.get(report_id, []):
            try:
                if loop is not None and loop.is_running():
                    loop.call_soon_threadsafe(queue.put_nowait, event)
                else:
                    queue.put_nowait(event)
            except Exception:
                logger.warning(
                    "SSE: failed to deliver event %s for report %d",
                    event_type, report_id,
                )

    def subscribe(self, report_id: int) -> asyncio.Queue:
        """Create a new subscriber queue. Must be called from an async context."""
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

        queue: asyncio.Queue = asyncio.Queue(maxsize=100)

        # Replay existing events so late-joining clients catch up
        for event in self._events.get(report_id, []):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                break

        self._subscribers[report_id].append(queue)
        return queue

    def unsubscribe(self, report_id: int, queue: asyncio.Queue) -> None:
        """Remove a subscriber queue."""
        subs = self._subscribers.get(report_id, [])
        if queue in subs:
            subs.remove(queue)

    def cleanup(self, report_id: int) -> None:
        """Remove all events and subscribers for a completed report."""
        self._events.pop(report_id, None)
        self._subscribers.pop(report_id, None)

    def get_history(self, report_id: int) -> list[dict[str, Any]]:
        """Get all events for a report (for late-joining clients)."""
        return list(self._events.get(report_id, []))


# Module-level singleton
sse_publisher = SSEPublisher()


def format_sse_message(event: dict[str, Any]) -> str:
    """Format an event dict as an SSE text message."""
    event_type = event.get("event", "message")
    data = json.dumps(event.get("data", {}))
    return f"event: {event_type}\ndata: {data}\n\n"
