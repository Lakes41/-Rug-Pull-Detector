"""
Token Bucket Rate Limiter Middleware
Implements token-bucket algorithm for rate limiting HTTP requests to prevent API exhaustion.
"""

import time
import asyncio
from typing import Dict, Optional
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from collections import defaultdict
from functools import wraps


class TokenBucket:
    """
    Token bucket implementation for rate limiting.
    
    Args:
        rate: Number of tokens to add per second (refill rate)
        capacity: Maximum number of tokens the bucket can hold
    """
    
    def __init__(self, rate: float, capacity: int):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.time()
        self._lock = asyncio.Lock()
    
    async def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens from the bucket.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            True if tokens were consumed, False if insufficient tokens
        """
        async with self._lock:
            now = time.time()
            time_passed = now - self.last_update
            
            # Refill tokens based on time passed
            self.tokens = min(
                self.capacity,
                self.tokens + time_passed * self.rate
            )
            self.last_update = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    async def get_available_tokens(self) -> int:
        """Get current number of available tokens"""
        async with self._lock:
            now = time.time()
            time_passed = now - self.last_update
            self.tokens = min(
                self.capacity,
                self.tokens + time_passed * self.rate
            )
            self.last_update = now
            return int(self.tokens)


class RateLimiter:
    """
    Rate limiter using token bucket algorithm with per-client tracking.
    
    Args:
        rate: Requests per second per client
        capacity: Maximum burst capacity per client
        identifier_func: Function to extract client identifier from request
                         (defaults to IP address)
    """
    
    def __init__(
        self,
        rate: float = 10.0,
        capacity: int = 100,
        identifier_func: Optional[callable] = None
    ):
        self.rate = rate
        self.capacity = capacity
        self.identifier_func = identifier_func or self._default_identifier
        self.buckets: Dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(rate, capacity)
        )
        self._lock = asyncio.Lock()
    
    def _default_identifier(self, request: Request) -> str:
        """Extract client IP address as identifier"""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    async def is_allowed(self, request: Request, tokens: int = 1) -> tuple[bool, int]:
        """
        Check if request is allowed under rate limit.
        
        Args:
            request: FastAPI request object
            tokens: Number of tokens to consume
            
        Returns:
            Tuple of (is_allowed, retry_after_seconds)
        """
        identifier = self.identifier_func(request)
        
        async with self._lock:
            bucket = self.buckets[identifier]
            allowed = await bucket.consume(tokens)
            
            if not allowed:
                # Calculate retry after based on current token deficit
                available = await bucket.get_available_tokens()
                deficit = tokens - available
                retry_after = deficit / self.rate
                return False, int(retry_after) + 1
            
            return True, 0
    
    async def get_rate_limit_headers(self, request: Request) -> Dict[str, str]:
        """
        Get rate limit headers for response.
        
        Args:
            request: FastAPI request object
            
        Returns:
            Dictionary of rate limit headers
        """
        identifier = self.identifier_func(request)
        bucket = self.buckets[identifier]
        available = await bucket.get_available_tokens()
        
        return {
            "X-RateLimit-Limit": str(self.capacity),
            "X-RateLimit-Remaining": str(available),
            "X-RateLimit-Reset": str(int(time.time() + (self.capacity - available) / self.rate))
        }


class RateLimitMiddleware:
    """
    FastAPI middleware for rate limiting.
    
    Args:
        rate_limiter: RateLimiter instance
        exclude_paths: List of paths to exclude from rate limiting
    """
    
    def __init__(
        self,
        rate_limiter: RateLimiter,
        exclude_paths: Optional[list] = None
    ):
        self.rate_limiter = rate_limiter
        self.exclude_paths = exclude_paths or ["/health", "/metrics"]
    
    async def __call__(self, request: Request, call_next):
        """Process request through rate limiter"""
        
        # Skip excluded paths
        if request.url.path in self.exclude_paths:
            return await call_next(request)
        
        # Check rate limit
        allowed, retry_after = await self.rate_limiter.is_allowed(request)
        
        if not allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "message": "Too many requests. Please try again later.",
                    "retry_after": retry_after
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(self.rate_limiter.capacity),
                    "X-RateLimit-Remaining": "0"
                }
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        headers = await self.rate_limiter.get_rate_limit_headers(request)
        for key, value in headers.items():
            response.headers[key] = value
        
        return response


def rate_limit(
    rate: float = 10.0,
    capacity: int = 100,
    identifier_func: Optional[callable] = None
):
    """
    Decorator for rate limiting specific endpoints.
    
    Args:
        rate: Requests per second
        capacity: Maximum burst capacity
        identifier_func: Custom identifier function
    """
    limiter = RateLimiter(rate, capacity, identifier_func)
    
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from args (first arg for FastAPI endpoints)
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            
            if not request:
                return await func(*args, **kwargs)
            
            allowed, retry_after = await limiter.is_allowed(request)
            
            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "Rate limit exceeded",
                        "message": "Too many requests. Please try again later.",
                        "retry_after": retry_after
                    },
                    headers={"Retry-After": str(retry_after)}
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


# Global rate limiter instance
default_rate_limiter = RateLimiter(rate=10.0, capacity=100)
