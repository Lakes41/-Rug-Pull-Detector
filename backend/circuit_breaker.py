"""
Circuit Breaker Implementation
Implements circuit breaker pattern for graceful degradation when RPC node providers fail.
"""

import time
import asyncio
from typing import Optional, Callable, Any, Dict
from enum import Enum
from functools import wraps
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Circuit is open, blocking requests
    HALF_OPEN = "half_open"  # Testing if service has recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""
    failure_threshold: int = 5        # Failures before opening
    success_threshold: int = 2        # Successes to close circuit
    timeout: float = 60.0             # Seconds before attempting recovery
    expected_exception: Exception = Exception  # Exception type to catch
    recovery_timeout: float = 30.0    # How long to stay in half-open state


@dataclass
class CircuitBreakerStats:
    """Statistics for circuit breaker"""
    total_requests: int = 0
    total_failures: int = 0
    total_successes: int = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_failure_time: Optional[float] = None
    last_success_time: Optional[float] = None
    state_transitions: Dict[str, int] = field(default_factory=lambda: {
        "closed_to_open": 0,
        "open_to_half_open": 0,
        "half_open_to_closed": 0,
        "half_open_to_open": 0
    })


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open"""
    def __init__(self, message: str = "Circuit breaker is open", retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after


class CircuitBreaker:
    """
    Circuit breaker implementation for protecting external service calls.
    
    Args:
        name: Name of the circuit breaker (for logging/metrics)
        config: CircuitBreakerConfig instance
    """
    
    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.stats = CircuitBreakerStats()
        self.last_state_change = time.time()
        self._lock = asyncio.Lock()
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute a function through the circuit breaker.
        
        Args:
            func: Function to execute
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function
            
        Returns:
            Result from the function
            
        Raises:
            CircuitBreakerOpenError: If circuit is open
            Exception: If function fails and circuit is not open
        """
        async with self._lock:
            # Check if we should allow the request
            if not self._should_allow_request():
                retry_after = self.config.timeout - (time.time() - self.last_state_change)
                raise CircuitBreakerOpenError(
                    f"Circuit breaker '{self.name}' is open",
                    retry_after=max(0, retry_after)
                )
        
        # Execute the function
        self.stats.total_requests += 1
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            
            # Record success
            await self._on_success()
            return result
            
        except self.config.expected_exception as e:
            # Record failure
            await self._on_failure()
            raise
    
    def _should_allow_request(self) -> bool:
        """Check if request should be allowed based on current state"""
        now = time.time()
        time_since_change = now - self.last_state_change
        
        if self.state == CircuitState.CLOSED:
            return True
        
        elif self.state == CircuitState.OPEN:
            # Check if we should transition to half-open
            if time_since_change >= self.config.timeout:
                return True
            return False
        
        elif self.state == CircuitState.HALF_OPEN:
            return True
        
        return False
    
    async def _on_success(self):
        """Handle successful request"""
        async with self._lock:
            self.stats.total_successes += 1
            self.stats.last_success_time = time.time()
            
            if self.state == CircuitState.HALF_OPEN:
                self.stats.consecutive_successes += 1
                
                # Check if we should close the circuit
                if self.stats.consecutive_successes >= self.config.success_threshold:
                    self._transition_to(CircuitState.CLOSED)
                    self.stats.consecutive_successes = 0
                    self.stats.consecutive_failures = 0
                    logger.info(f"Circuit breaker '{self.name}' closed after successful recovery")
            
            elif self.state == CircuitState.CLOSED:
                self.stats.consecutive_failures = 0
    
    async def _on_failure(self):
        """Handle failed request"""
        async with self._lock:
            self.stats.total_failures += 1
            self.stats.consecutive_failures += 1
            self.stats.last_failure_time = time.time()
            
            if self.state == CircuitState.HALF_OPEN:
                # Failed in half-open, go back to open
                self._transition_to(CircuitState.OPEN)
                self.stats.consecutive_successes = 0
                logger.warning(f"Circuit breaker '{self.name}' re-opened after failed recovery attempt")
            
            elif self.state == CircuitState.CLOSED:
                # Check if we should open the circuit
                if self.stats.consecutive_failures >= self.config.failure_threshold:
                    self._transition_to(CircuitState.OPEN)
                    logger.warning(f"Circuit breaker '{self.name}' opened after {self.stats.consecutive_failures} failures")
    
    def _transition_to(self, new_state: CircuitState):
        """Transition to a new state"""
        old_state = self.state
        self.state = new_state
        self.last_state_change = time.time()
        
        # Track state transitions
        transition_key = f"{old_state.value}_to_{new_state.value}"
        if transition_key in self.stats.state_transitions:
            self.stats.state_transitions[transition_key] += 1
    
    def get_state(self) -> CircuitState:
        """Get current circuit state"""
        # Auto-transition from open to half-open if timeout has passed
        if self.state == CircuitState.OPEN:
            if time.time() - self.last_state_change >= self.config.timeout:
                self._transition_to(CircuitState.HALF_OPEN)
                logger.info(f"Circuit breaker '{self.name}' transitioned to half-open")
        return self.state
    
    def get_stats(self) -> Dict:
        """Get circuit breaker statistics"""
        return {
            "name": self.name,
            "state": self.state.value,
            "total_requests": self.stats.total_requests,
            "total_failures": self.stats.total_failures,
            "total_successes": self.stats.total_successes,
            "consecutive_failures": self.stats.consecutive_failures,
            "consecutive_successes": self.stats.consecutive_successes,
            "last_failure_time": self.stats.last_failure_time,
            "last_success_time": self.stats.last_success_time,
            "state_transitions": self.stats.state_transitions,
            "last_state_change": self.last_state_change
        }
    
    def reset(self):
        """Reset the circuit breaker to closed state"""
        self.state = CircuitState.CLOSED
        self.stats = CircuitBreakerStats()
        self.last_state_change = time.time()
        logger.info(f"Circuit breaker '{self.name}' reset to closed state")


def circuit_breaker(
    name: str,
    failure_threshold: int = 5,
    success_threshold: int = 2,
    timeout: float = 60.0,
    expected_exception: Exception = Exception
):
    """
    Decorator for applying circuit breaker to a function.
    
    Args:
        name: Name of the circuit breaker
        failure_threshold: Failures before opening
        success_threshold: Successes to close circuit
        timeout: Seconds before attempting recovery
        expected_exception: Exception type to catch
    """
    config = CircuitBreakerConfig(
        failure_threshold=failure_threshold,
        success_threshold=success_threshold,
        timeout=timeout,
        expected_exception=expected_exception
    )
    breaker = CircuitBreaker(name, config)
    
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await breaker.call(func, *args, **kwargs)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # For sync functions, we need to run in event loop
            return asyncio.run(breaker.call(func, *args, **kwargs))
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


class CircuitBreakerRegistry:
    """Registry for managing multiple circuit breakers"""
    
    def __init__(self):
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._lock = asyncio.Lock()
    
    async def get_breaker(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None
    ) -> CircuitBreaker:
        """Get or create a circuit breaker"""
        async with self._lock:
            if name not in self._breakers:
                self._breakers[name] = CircuitBreaker(name, config)
            return self._breakers[name]
    
    async def get_all_stats(self) -> Dict[str, Dict]:
        """Get statistics for all circuit breakers"""
        async with self._lock:
            return {name: breaker.get_stats() for name, breaker in self._breakers.items()}
    
    async def reset_all(self):
        """Reset all circuit breakers"""
        async with self._lock:
            for breaker in self._breakers.values():
                breaker.reset()
    
    async def reset_breaker(self, name: str):
        """Reset a specific circuit breaker"""
        async with self._lock:
            if name in self._breakers:
                self._breakers[name].reset()


# Global circuit breaker registry
circuit_breaker_registry = CircuitBreakerRegistry()


# Pre-configured circuit breakers for common RPC providers
async def get_rpc_circuit_breaker(rpc_url: str) -> CircuitBreaker:
    """Get or create a circuit breaker for a specific RPC URL"""
    # Extract a name from the URL for identification
    name = rpc_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    
    config = CircuitBreakerConfig(
        failure_threshold=3,        # Open after 3 failures
        success_threshold=2,        # Close after 2 successes
        timeout=60.0,               # Try recovery after 60 seconds
        expected_exception=Exception
    )
    
    return await circuit_breaker_registry.get_breaker(name, config)
