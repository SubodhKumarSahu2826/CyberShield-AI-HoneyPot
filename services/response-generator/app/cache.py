"""
In-Memory Response Cache

Fast, deterministic caching for LLM-generated responses.
Key: SHA-256 hash of (payload + attack_type)
Value: {"response": str, "response_type": str}
Max entries: 1024 (LRU eviction via OrderedDict)
"""

import hashlib
import logging
from collections import OrderedDict
from typing import Optional

logger = logging.getLogger("response_generator")

# ---------------------------------------------------------------------------
# Configurable max cache size
# ---------------------------------------------------------------------------
MAX_CACHE_SIZE = 1024

_cache: OrderedDict[str, dict] = OrderedDict()


def _make_key(payload: str, attack_type: str) -> str:
    """Generate a deterministic cache key from payload + attack_type."""
    raw = f"{payload}::{attack_type}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def get_cached_response(payload: str, attack_type: str) -> Optional[dict]:
    """
    Look up a cached response.
    Returns {"response": str, "response_type": str} on hit, None on miss.
    Moves the entry to the end (most-recently-used) on hit.
    """
    key = _make_key(payload, attack_type)
    if key in _cache:
        _cache.move_to_end(key)
        logger.info(f"Cache HIT for key {key[:12]}...")
        return _cache[key]
    return None


def set_cached_response(payload: str, attack_type: str, response: str, response_type: str) -> None:
    """
    Store a response in the cache. Evicts the oldest entry if the cache
    exceeds MAX_CACHE_SIZE (LRU policy).
    """
    key = _make_key(payload, attack_type)
    _cache[key] = {"response": response, "response_type": response_type}
    _cache.move_to_end(key)

    # Evict oldest entries if over capacity
    while len(_cache) > MAX_CACHE_SIZE:
        evicted_key, _ = _cache.popitem(last=False)
        logger.debug(f"Cache evicted oldest entry {evicted_key[:12]}...")

    logger.info(f"Cache SET for key {key[:12]}... (size: {len(_cache)})")


def cache_size() -> int:
    """Return current number of cached entries."""
    return len(_cache)


def clear_cache() -> None:
    """Clear the entire cache."""
    _cache.clear()
    logger.info("Cache cleared")
