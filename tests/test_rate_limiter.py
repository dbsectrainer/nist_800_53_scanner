import threading
import time

import pytest

from modules.rate_limiter import RateLimit, RateLimiter, RateLimitMiddleware

LIMIT = "default"


def make_limiter(max_requests=5, window_seconds=1, block_duration=1):
    return RateLimiter(
        {LIMIT: RateLimit(max_requests, window_seconds, block_duration=block_duration)},
        persistent=False,
    )


class TestRateLimiter:
    def setup_method(self):
        self.rate_limiter = make_limiter()

    def allowed(self, key, limiter=None):
        limited, _ = (limiter or self.rate_limiter).is_rate_limited(LIMIT, key)
        return not limited

    def test_basic_rate_limiting(self):
        for _ in range(5):
            assert self.allowed("test_user"), "First 5 requests should be allowed"
        assert not self.allowed("test_user"), "6th request should be denied"

    def test_denial_reports_retry_after(self):
        for _ in range(5):
            self.allowed("retry_user")
        limited, retry_after = self.rate_limiter.is_rate_limited(LIMIT, "retry_user")
        assert limited
        assert 0 < retry_after <= 1

    def test_unknown_limit_is_not_limited(self):
        assert self.rate_limiter.is_rate_limited("nonexistent", "user") == (False, None)

    def test_time_window_reset(self):
        for _ in range(5):
            assert self.allowed("window_user")
        assert not self.allowed("window_user")

        time.sleep(1.1)  # block_duration and window are both 1s

        assert self.allowed("window_user"), "Requests should be allowed after the block expires"

    def test_multiple_identifiers(self):
        for identifier in ("user1", "user2", "user3"):
            for _ in range(5):
                assert self.allowed(identifier), f"First 5 requests for {identifier} should be allowed"
            assert not self.allowed(identifier), f"6th request for {identifier} should be denied"

    def test_concurrent_access(self):
        allowed_requests = []

        def make_request():
            if self.allowed("concurrent_user"):
                allowed_requests.append(1)

        threads = [threading.Thread(target=make_request) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(allowed_requests) == 5, "Exactly the limit should get through under contention"

    def test_reset(self):
        for _ in range(5):
            assert self.allowed("reset_user")
        assert not self.allowed("reset_user")

        self.rate_limiter.reset(LIMIT, "reset_user")

        assert self.allowed("reset_user"), "Requests should be allowed again after reset"

    def test_get_remaining(self):
        assert self.rate_limiter.get_remaining(LIMIT, "fresh")["remaining"] == 5
        for _ in range(2):
            self.allowed("fresh")
        assert self.rate_limiter.get_remaining(LIMIT, "fresh")["remaining"] == 3
        assert self.rate_limiter.get_remaining("nonexistent", "fresh")["remaining"] == 0

    def test_custom_rate_limit(self):
        custom = make_limiter(max_requests=3, window_seconds=2, block_duration=2)
        for _ in range(3):
            assert self.allowed("custom_user", custom)
        assert not self.allowed("custom_user", custom)

        time.sleep(2.1)

        assert self.allowed("custom_user", custom)

    def test_zero_max_requests_blocks_everything(self):
        zero = make_limiter(max_requests=0)
        assert not self.allowed("edge_case_user", zero)

    def test_request_tracking(self):
        accepted = sum(self.allowed("tracking_user") for _ in range(10))
        assert accepted == 5, "Should track exactly 5 requests"

    def test_middleware_headers(self):
        middleware = RateLimitMiddleware(self.rate_limiter)
        allowed, headers = middleware.process_request({"client_ip": "10.0.0.1"})
        assert allowed
        assert headers["X-RateLimit-Remaining"] == "4"

        for _ in range(5):
            middleware.process_request({"client_ip": "10.0.0.1"})
        allowed, headers = middleware.process_request({"client_ip": "10.0.0.1"})
        assert not allowed
        assert "Retry-After" in headers
