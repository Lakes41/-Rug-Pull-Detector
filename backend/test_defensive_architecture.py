"""
Test defensive architecture components - rate limiter and circuit breaker
"""

import pytest
import asyncio
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from unittest.mock import Mock
import time

from rate_limiter import TokenBucket, RateLimiter, RateLimitMiddleware
from circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerOpenError, circuit_breaker


class TestTokenBucket:
    """Test token bucket implementation"""
    
    @pytest.mark.asyncio
    async def test_token_bucket_consume(self):
        """Test basic token consumption"""
        bucket = TokenBucket(rate=10.0, capacity=100)
        
        # Should allow initial consumption
        assert await bucket.consume(1) == True
        assert await bucket.consume(10) == True
        
        # Should have enough tokens
        assert await bucket.get_available_tokens() >= 89
    
    @pytest.mark.asyncio
    async def test_token_bucket_refill(self):
        """Test token refill over time"""
        bucket = TokenBucket(rate=10.0, capacity=10)
        
        # Consume all tokens
        await bucket.consume(10)
        assert await bucket.get_available_tokens() == 0
        
        # Wait for refill (1 second for 10 tokens at rate 10.0)
        await asyncio.sleep(1.1)
        
        # Should have refilled tokens
        available = await bucket.get_available_tokens()
        assert available >= 10  # Should be close to full capacity
    
    @pytest.mark.asyncio
    async def test_token_bucket_insufficient_tokens(self):
        """Test rejection when insufficient tokens"""
        bucket = TokenBucket(rate=1.0, capacity=5)
        
        # Consume all tokens
        await bucket.consume(5)
        assert await bucket.consume(1) == False
    
    @pytest.mark.asyncio
    async def test_token_bucket_burst_capacity(self):
        """Test burst capacity handling"""
        bucket = TokenBucket(rate=1.0, capacity=10)
        
        # Should allow burst up to capacity
        assert await bucket.consume(10) == True
        assert await bucket.consume(1) == False


class TestRateLimiter:
    """Test rate limiter implementation"""
    
    @pytest.mark.asyncio
    async def test_rate_limiter_allow_request(self):
        """Test request allowance under rate limit"""
        limiter = RateLimiter(rate=10.0, capacity=100)
        
        # Create mock request
        request = Mock(spec=Request)
        request.client = Mock()
        request.client.host = "127.0.0.1"
        request.headers = {}
        
        # Should allow requests
        allowed, retry_after = await limiter.is_allowed(request)
        assert allowed == True
        assert retry_after == 0
    
    @pytest.mark.asyncio
    async def test_rate_limiter_exceed_limit(self):
        """Test request rejection when limit exceeded"""
        limiter = RateLimiter(rate=1.0, capacity=5)
        
        # Create mock request
        request = Mock(spec=Request)
        request.client = Mock()
        request.client.host = "127.0.0.1"
        request.headers = {}
        
        # Exhaust capacity
        for _ in range(5):
            allowed, _ = await limiter.is_allowed(request)
            assert allowed == True
        
        # Next request should be denied
        allowed, retry_after = await limiter.is_allowed(request)
        assert allowed == False
        assert retry_after > 0
    
    @pytest.mark.asyncio
    async def test_rate_limiter_different_clients(self):
        """Test that different clients have separate buckets"""
        limiter = RateLimiter(rate=1.0, capacity=2)
        
        # Create mock requests for different clients
        request1 = Mock(spec=Request)
        request1.client = Mock()
        request1.client.host = "127.0.0.1"
        request1.headers = {}
        
        request2 = Mock(spec=Request)
        request2.client = Mock()
        request2.client.host = "192.168.1.1"
        request2.headers = {}
        
        # Each client should have separate capacity
        for _ in range(2):
            assert (await limiter.is_allowed(request1))[0] == True
            assert (await limiter.is_allowed(request2))[0] == True
        
        # Both should now be denied
        assert (await limiter.is_allowed(request1))[0] == False
        assert (await limiter.is_allowed(request2))[0] == False


class TestCircuitBreaker:
    """Test circuit breaker implementation"""
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_closed_state(self):
        """Test circuit breaker in closed state (normal operation)"""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            success_threshold=2,
            timeout=60.0
        )
        breaker = CircuitBreaker("test_breaker", config)
        
        # Should allow requests in closed state
        async def success_func():
            return "success"
        
        result = await breaker.call(success_func)
        assert result == "success"
        assert breaker.get_state().value == "closed"
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_opens_on_failures(self):
        """Test circuit breaker opens after threshold failures"""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            success_threshold=2,
            timeout=60.0
        )
        breaker = CircuitBreaker("test_breaker", config)
        
        async def failing_func():
            raise Exception("Service failure")
        
        # Failures should accumulate
        for _ in range(3):
            try:
                await breaker.call(failing_func)
            except Exception:
                pass
        
        # Circuit should be open now
        assert breaker.get_state().value == "open"
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_blocks_requests_when_open(self):
        """Test circuit breaker blocks requests when open"""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            success_threshold=2,
            timeout=60.0
        )
        breaker = CircuitBreaker("test_breaker", config)
        
        async def failing_func():
            raise Exception("Service failure")
        
        # Open the circuit
        for _ in range(2):
            try:
                await breaker.call(failing_func)
            except Exception:
                pass
        
        # Should block requests when open
        async def success_func():
            return "success"
        
        with pytest.raises(CircuitBreakerOpenError):
            await breaker.call(success_func)
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_half_open_recovery(self):
        """Test circuit breaker transitions to half-open and recovers"""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            success_threshold=2,
            timeout=1.0  # Short timeout for testing
        )
        breaker = CircuitBreaker("test_breaker", config)
        
        async def failing_func():
            raise Exception("Service failure")
        
        # Open the circuit
        for _ in range(2):
            try:
                await breaker.call(failing_func)
            except Exception:
                pass
        
        assert breaker.get_state().value == "open"
        
        # Wait for timeout
        await asyncio.sleep(1.1)
        
        # Should transition to half-open on next request
        async def success_func():
            return "success"
        
        result = await breaker.call(success_func)
        assert result == "success"
        
        # Should still be in half-open
        state = breaker.get_state()
        assert state.value == "half_open"
        
        # Another success should close the circuit
        result = await breaker.call(success_func)
        assert result == "success"
        
        # Should be closed now
        assert breaker.get_state().value == "closed"
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_decorator(self):
        """Test circuit breaker decorator"""
        call_count = {"success": 0, "failure": 0}
        
        @circuit_breaker(
            name="decorator_test",
            failure_threshold=2,
            success_threshold=2,
            timeout=60.0
        )
        async def test_func(should_fail=False):
            if should_fail:
                call_count["failure"] += 1
                raise Exception("Failure")
            call_count["success"] += 1
            return "success"
        
        # Should work normally
        result = await test_func(should_fail=False)
        assert result == "success"
        assert call_count["success"] == 1
        
        # Should handle failures
        for _ in range(2):
            try:
                await test_func(should_fail=True)
            except Exception:
                pass
        
        # Circuit should be open
        with pytest.raises(CircuitBreakerOpenError):
            await test_func(should_fail=False)


class TestIntegration:
    """Integration tests for rate limiter and circuit breaker"""
    
    @pytest.mark.asyncio
    async def test_rate_limiting_with_circuit_breaker(self):
        """Test rate limiter and circuit breaker working together"""
        limiter = RateLimiter(rate=10.0, capacity=10)
        breaker = CircuitBreaker("integration_test", CircuitBreakerConfig(
            failure_threshold=2,
            success_threshold=1,
            timeout=60.0
        ))
        
        request = Mock(spec=Request)
        request.client = Mock()
        request.client.host = "127.0.0.1"
        request.headers = {}
        
        async def protected_operation():
            # Check rate limit first
            allowed, retry_after = await limiter.is_allowed(request)
            if not allowed:
                raise Exception(f"Rate limited: retry after {retry_after}")
            
            # Then execute through circuit breaker
            return await breaker.call(lambda: "operation_success")
        
        # Should work normally
        result = await protected_operation()
        assert result == "operation_success"
        
        # Should handle rate limiting
        for _ in range(10):
            await protected_operation()
        
        # Next request should be rate limited
        with pytest.raises(Exception, match="Rate limited"):
            await protected_operation()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
