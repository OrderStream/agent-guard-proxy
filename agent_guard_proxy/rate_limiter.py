"""
Sliding-window token bucket rate limiter for MCP tool calls.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Dict, Optional


class RateLimitExceeded(Exception):
    def __init__(self, key: str, current_count: int, limit: int, window_seconds: float):
        super().__init__(
            f"Rate limit exceeded for '{key}': {current_count}/{limit} requests in {window_seconds}s"
        )
        self.key = key
        self.current_count = current_count
        self.limit = limit
        self.window_seconds = window_seconds


class SlidingWindowRateLimiter:
    """
    In-memory high-throughput sliding window rate limiter.
    """

    def __init__(self, max_requests: int = 60, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.buckets: Dict[str, deque[float]] = {}

    def is_allowed(self, key: str, timestamp: Optional[float] = None) -> bool:
        """Checks if a request under `key` is allowed without consuming quota."""
        now = timestamp if timestamp is not None else time.time()
        cutoff = now - self.window_seconds

        bucket = self.buckets.get(key)
        if not bucket:
            return True

        # Count entries newer than cutoff
        active_count = sum(1 for t in bucket if t > cutoff)
        return active_count < self.max_requests

    def record_request(self, key: str, timestamp: Optional[float] = None) -> None:
        """Consumes 1 request quota, raising RateLimitExceeded if limit reached."""
        now = timestamp if timestamp is not None else time.time()
        cutoff = now - self.window_seconds

        if key not in self.buckets:
            self.buckets[key] = deque()

        bucket = self.buckets[key]

        # Prune expired entries
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        if len(bucket) >= self.max_requests:
            raise RateLimitExceeded(key, len(bucket), self.max_requests, self.window_seconds)

        bucket.append(now)

    def reset(self, key: Optional[str] = None) -> None:
        if key:
            self.buckets.pop(key, None)
        else:
            self.buckets.clear()
