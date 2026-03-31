"""
Async Pipeline: Queue Manager
services/honeypot/app/async_pipeline/queue_manager.py

Maintains a singleton asyncio.Queue to hold suspicious requests
waiting for AI classification.
"""

import asyncio
from dataclasses import dataclass

@dataclass
class ClassificationJob:
    request_id: int
    method: str
    endpoint: str
    headers: dict
    payload: str
    source_ip: str
    session_id: str

class QueueManager:
    def __init__(self):
        # Unbounded queue for suspicious requests
        self._queue: asyncio.Queue[ClassificationJob] = asyncio.Queue()

    def enqueue(self, job: ClassificationJob) -> None:
        """Push a suspicious request to the inference queue asynchronously."""
        self._queue.put_nowait(job)

    async def dequeue(self) -> ClassificationJob:
        """Wait for and retrieve the next job from the queue."""
        return await self._queue.get()

    def task_done(self) -> None:
        """Acknowledge job completion."""
        self._queue.task_done()

    def get_size(self) -> int:
        """Return the number of requests currently waiting in the queue."""
        return self._queue.qsize()

# Singleton instance
manager = QueueManager()
