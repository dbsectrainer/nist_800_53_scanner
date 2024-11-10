import time
import threading
import pytest
from modules.rate_limiter import RateLimiter

class TestRateLimiter:
    def setup_method(self):
        """Create a fresh rate limiter for each test"""
        self.rate_limiter = RateLimiter(max_requests=5, time_window=1)

    def test_basic_rate_limiting(self):
        """Test basic rate limiting functionality"""
        identifier = 'test_user'
        
        # Allow first 5 requests
        for _ in range(5):
            assert self.rate_limiter.is_allowed(identifier), "First 5 requests should be allowed"
        
        # 6th request should be denied
        assert not self.rate_limiter.is_allowed(identifier), "6th request should be denied"

    def test_time_window_reset(self):
        """Test rate limit reset after time window"""
        identifier = 'time_window_user'
        
        # Fill up rate limit
        for _ in range(5):
            assert self.rate_limiter.is_allowed(identifier), "Requests should be allowed"
        
        # Wait for time window to expire
        time.sleep(1.1)
        
        # Should be allowed again after time window
        assert self.rate_limiter.is_allowed(identifier), "Requests should be allowed after time window"

    def test_multiple_identifiers(self):
        """Test rate limiting with different identifiers"""
        identifiers = ['user1', 'user2', 'user3']
        
        # Each identifier should have independent rate limiting
        for identifier in identifiers:
            for _ in range(5):
                assert self.rate_limiter.is_allowed(identifier), f"First 5 requests for {identifier} should be allowed"
            
            assert not self.rate_limiter.is_allowed(identifier), f"6th request for {identifier} should be denied"

    def test_concurrent_access(self):
        """Test rate limiter under concurrent access"""
        identifier = 'concurrent_user'
        allowed_requests = [0]
        
        def make_request():
            if self.rate_limiter.is_allowed(identifier):
                allowed_requests[0] += 1
        
        # Create multiple threads to simulate concurrent requests
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=make_request)
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Should not exceed max requests
        assert allowed_requests[0] <= 5, "Concurrent requests should not exceed rate limit"

    def test_reset_rate_limit(self):
        """Test manual rate limit reset"""
        identifier = 'reset_user'
        
        # Fill up rate limit
        for _ in range(5):
            assert self.rate_limiter.is_allowed(identifier), "First 5 requests should be allowed"
        
        # Deny 6th request
        assert not self.rate_limiter.is_allowed(identifier), "6th request should be denied"
        
        # Reset rate limit
        self.rate_limiter.reset_rate_limit(identifier)
        
        # Should be allowed again after reset
        assert self.rate_limiter.is_allowed(identifier), "Requests should be allowed after reset"

    def test_custom_rate_limit(self):
        """Test rate limiter with custom configuration"""
        # Create rate limiter with different parameters
        custom_limiter = RateLimiter(max_requests=3, time_window=2)
        identifier = 'custom_user'
        
        # Allow first 3 requests
        for _ in range(3):
            assert custom_limiter.is_allowed(identifier), "First 3 requests should be allowed"
        
        # 4th request should be denied
        assert not custom_limiter.is_allowed(identifier), "4th request should be denied"
        
        # Wait for time window to expire
        time.sleep(2.1)
        
        # Should be allowed again after time window
        assert custom_limiter.is_allowed(identifier), "Requests should be allowed after time window"

    def test_edge_cases(self):
        """Test edge cases and boundary conditions"""
        # Zero max requests
        zero_limiter = RateLimiter(max_requests=0, time_window=1)
        identifier = 'edge_case_user'
        
        # No requests should be allowed
        assert not zero_limiter.is_allowed(identifier), "No requests should be allowed with max_requests=0"
        
        # Extremely short time window
        short_window_limiter = RateLimiter(max_requests=1, time_window=0.1)
        
        # First request allowed
        assert short_window_limiter.is_allowed(identifier), "First request should be allowed"
        
        # Wait just beyond time window
        time.sleep(0.11)
        
        # Should be allowed again
        assert short_window_limiter.is_allowed(identifier), "Request should be allowed after short time window"

    def test_request_tracking(self):
        """Verify request tracking mechanism"""
        identifier = 'tracking_user'
        
        # Track requests
        requests = []
        for _ in range(10):
            if self.rate_limiter.is_allowed(identifier):
                requests.append(time.time())
        
        # Verify number of tracked requests
        assert len(requests) == 5, "Should track exactly 5 requests"
        
        # Verify timestamps are within expected range
        time_differences = [requests[i+1] - requests[i] for i in range(len(requests)-1)]
        assert all(diff < 1 for diff in time_differences), "Requests should be within time window"
