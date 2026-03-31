"""
Rate Limiter for AI Adaptive Honeypot
Implements a sliding window to calculate requests per minute per IP.
"""
from collections import defaultdict
import time
import asyncio

# In-memory store: ip -> list of timestamps
_request_history: dict[str, list[float]] = defaultdict(list)
_lock = asyncio.Lock()

RATE_LIMIT_WINDOW_SECONDS = 60
MAX_REQUESTS_PER_WINDOW = 300 

async def is_rate_limited(ip: str) -> bool:
    """Returns True if the IP exceeds the request limit."""
    now = time.time()
    
    async with _lock:
        history = _request_history[ip]
        # Prune old timestamps
        _request_history[ip] = [t for t in history if now - t < RATE_LIMIT_WINDOW_SECONDS]
        _request_history[ip].append(now)
        
        return len(_request_history[ip]) > MAX_REQUESTS_PER_WINDOW
