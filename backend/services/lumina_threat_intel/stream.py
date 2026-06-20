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


import os
import redis

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

class SSEPublisher:
    """SSE event publisher keyed by report_id.

    Publishes events to a Redis Pub/Sub channel so any API worker can stream them.
    """

    def emit(self, report_id: int, event_type: str, data: dict[str, Any]) -> None:
        """Publish an event to Redis Pub/Sub. Safe to call from any thread."""
        event = {
            "event": event_type,
            "data": data,
            "timestamp": time.time(),
        }
        try:
            r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
            r.publish(f"sse_events:{report_id}", json.dumps(event))
            r.close()
        except Exception as e:
            logger.warning(
                "SSE: failed to publish event %s for report %d: %s",
                event_type, report_id, str(e)[:100]
            )

    def subscribe(self, report_id: int): pass
    def unsubscribe(self, report_id: int, queue): pass
    def cleanup(self, report_id: int) -> None: pass
    def get_history(self, report_id: int) -> list[dict[str, Any]]: return []


# Module-level singleton
sse_publisher = SSEPublisher()


def format_sse_message(event: dict[str, Any]) -> str:
    """Format an event dict as an SSE text message."""
    event_type = event.get("event", "message")
    data = json.dumps(event.get("data", {}))
    return f"event: {event_type}\ndata: {data}\n\n"
