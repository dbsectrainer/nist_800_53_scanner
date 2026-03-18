import time
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass
from datetime import datetime
import threading
import json
from pathlib import Path
import logging


@dataclass
class RateLimit:
    """Rate limit configuration."""

    max_requests: int
    window_seconds: int
    block_duration: int = 300  # 5 minutes default block duration


@dataclass
class RateLimitState:
    """Rate limit state for a key."""

    requests: List[float]
    blocked_until: Optional[float] = None


class RateLimiter:
    def __init__(self, limits: Dict[str, RateLimit], persistent: bool = True):
        """
        Initialize rate limiter with multiple limit configurations.

        Args:
            limits: Dictionary of rate limit configurations by name
            persistent: Whether to persist rate limit state
        """
        self.limits = limits
        self.states: Dict[str, Dict[str, RateLimitState]] = {}
        self.lock = threading.Lock()
        self.persistent = persistent
        self.state_file = Path("rate_limit_state.json")

        # Load persistent state if enabled
        if self.persistent:
            self._load_state()

        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

    def _load_state(self):
        """Load rate limit state from file."""
        try:
            if self.state_file.exists():
                with open(self.state_file, "r") as f:
                    state_data = json.load(f)

                with self.lock:
                    for limit_name, keys in state_data.items():
                        self.states[limit_name] = {}
                        for key, state in keys.items():
                            self.states[limit_name][key] = RateLimitState(
                                requests=state["requests"], blocked_until=state.get("blocked_until")
                            )
        except Exception as e:
            logging.error(f"Error loading rate limit state: {str(e)}")

    def _save_state(self):
        """Save rate limit state to file."""
        if not self.persistent:
            return

        try:
            state_data = {}
            with self.lock:
                for limit_name, keys in self.states.items():
                    state_data[limit_name] = {}
                    for key, state in keys.items():
                        state_data[limit_name][key] = {"requests": state.requests, "blocked_until": state.blocked_until}

            # Write to temporary file first
            temp_file = self.state_file.with_suffix(".tmp")
            with open(temp_file, "w") as f:
                json.dump(state_data, f)

            # Atomic replace
            temp_file.replace(self.state_file)

        except Exception as e:
            logging.error(f"Error saving rate limit state: {str(e)}")

    def _cleanup_loop(self):
        """Background thread to clean up expired entries."""
        while True:
            time.sleep(60)  # Run cleanup every minute
            self._cleanup()

    def _cleanup(self):
        """Remove expired entries from state."""
        current_time = time.time()
        any_removed = False
        with self.lock:
            for limit_name, limit in self.limits.items():
                if limit_name not in self.states:
                    continue

                # Find expired entries
                expired_keys: List[str] = []
                for key, state in self.states[limit_name].items():
                    # Remove old requests
                    state.requests = [t for t in state.requests if current_time - t <= limit.window_seconds]

                    # Check if entry can be removed
                    if not state.requests and (not state.blocked_until or current_time > state.blocked_until):
                        expired_keys.append(key)

                # Remove expired entries
                for key in expired_keys:
                    del self.states[limit_name][key]

                if expired_keys:
                    any_removed = True

            if any_removed:
                self._save_state()

    def is_rate_limited(self, limit_name: str, key: str) -> Tuple[bool, Optional[float]]:
        """
        Check if a key is currently rate limited.

        Args:
            limit_name: Name of the rate limit configuration to use
            key: Key to check (e.g., IP address, user ID)

        Returns:
            Tuple of (is_limited, retry_after)
        """
        if limit_name not in self.limits:
            return False, None

        limit = self.limits[limit_name]
        current_time = time.time()

        with self.lock:
            # Initialize state for limit_name if needed
            if limit_name not in self.states:
                self.states[limit_name] = {}

            # Initialize state for key if needed
            if key not in self.states[limit_name]:
                self.states[limit_name][key] = RateLimitState(requests=[])

            state = self.states[limit_name][key]

            # Check if currently blocked
            if state.blocked_until and current_time < state.blocked_until:
                return True, state.blocked_until - current_time

            # Remove old requests
            state.requests = [t for t in state.requests if current_time - t <= limit.window_seconds]

            # Check rate limit
            if len(state.requests) >= limit.max_requests:
                # Block the key
                state.blocked_until = current_time + limit.block_duration
                self._save_state()
                return True, limit.block_duration

            # Add new request
            state.requests.append(current_time)
            self._save_state()

            return False, None

    def get_remaining(self, limit_name: str, key: str) -> Dict[str, float]:
        """
        Get remaining requests and reset time for a key.

        Args:
            limit_name: Name of the rate limit configuration
            key: Key to check

        Returns:
            Dictionary with remaining requests and reset time
        """
        if limit_name not in self.limits:
            return {"remaining": 0, "reset": 0}

        limit = self.limits[limit_name]
        current_time = time.time()

        with self.lock:
            if limit_name not in self.states or key not in self.states[limit_name]:
                return {"remaining": limit.max_requests, "reset": current_time + limit.window_seconds}

            state = self.states[limit_name][key]

            # Check if blocked
            if state.blocked_until and current_time < state.blocked_until:
                return {"remaining": 0, "reset": state.blocked_until}

            # Count valid requests
            valid_requests = [t for t in state.requests if current_time - t <= limit.window_seconds]

            return {
                "remaining": max(0, limit.max_requests - len(valid_requests)),
                "reset": current_time + limit.window_seconds,
            }

    def reset(self, limit_name: str, key: str):
        """
        Reset rate limit for a key.

        Args:
            limit_name: Name of the rate limit configuration
            key: Key to reset
        """
        with self.lock:
            if limit_name in self.states and key in self.states[limit_name]:
                del self.states[limit_name][key]
                self._save_state()


class RateLimitMiddleware:
    def __init__(self, rate_limiter: RateLimiter):
        """
        Initialize rate limit middleware.

        Args:
            rate_limiter: RateLimiter instance
        """
        self.rate_limiter = rate_limiter

    def process_request(self, request_data: Dict) -> Tuple[bool, Optional[Dict[str, str]]]:
        """
        Process request and apply rate limiting.

        Args:
            request_data: Dictionary containing request data

        Returns:
            Tuple of (is_allowed, response_headers)
        """
        # Get client IP
        client_ip = request_data.get("client_ip", "unknown")

        # Check rate limit
        is_limited, retry_after = self.rate_limiter.is_rate_limited("default", client_ip)

        if is_limited:
            retry_secs = float(retry_after) if retry_after is not None else 0.0
            headers = {
                "Retry-After": str(int(retry_secs)),
                "X-RateLimit-Reset": str(int(time.time() + retry_secs)),
            }
            return False, headers

        # Get remaining requests info
        remaining = self.rate_limiter.get_remaining("default", client_ip)

        headers = {
            "X-RateLimit-Remaining": str(remaining["remaining"]),
            "X-RateLimit-Reset": str(int(remaining["reset"])),
        }

        return True, headers


def create_default_rate_limiter() -> RateLimiter:
    """
    Create rate limiter with default configurations.

    Returns:
        Configured RateLimiter instance
    """
    return RateLimiter(
        {
            "default": RateLimit(max_requests=100, window_seconds=60, block_duration=300),
            "auth": RateLimit(max_requests=5, window_seconds=300, block_duration=900),
            "api": RateLimit(max_requests=1000, window_seconds=3600, block_duration=1800),
        }
    )
