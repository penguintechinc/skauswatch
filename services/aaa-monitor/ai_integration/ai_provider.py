"""
SkausWatch AAA Monitor Service - AI Provider Abstraction Layer

Abstract base class and unified interface for all AI providers with
fallback mechanisms, load balancing, and health monitoring.
"""

import asyncio
import hashlib
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Union, AsyncGenerator
from collections import defaultdict, deque
import aioredis
import structlog

from ..models import AIProvider

logger = structlog.get_logger(__name__)


class AIProviderStatus(str, Enum):
    """AI provider status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    OFFLINE = "offline"


class AIAnalysisType(str, Enum):
    """AI analysis types"""
    SECURITY_EVENT = "security_event"
    ANOMALY_DETECTION = "anomaly_detection"  
    THREAT_CLASSIFICATION = "threat_classification"
    LOG_CORRELATION = "log_correlation"
    PATTERN_ANALYSIS = "pattern_analysis"
    INCIDENT_SUMMARY = "incident_summary"
    CUSTOM = "custom"


@dataclass
class AIAnalysisRequest:
    """AI analysis request"""
    request_id: str
    analysis_type: AIAnalysisType
    data: Dict[str, Any]
    prompt_template: Optional[str] = None
    custom_prompt: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    priority: int = 1  # 1=low, 5=high
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    timeout: Optional[int] = None


@dataclass 
class AIAnalysisResponse:
    """AI analysis response"""
    request_id: str
    provider: AIProvider
    model: str
    analysis_type: AIAnalysisType
    response_text: str
    confidence_score: Optional[float] = None
    tokens_used: Optional[int] = None
    processing_time: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    cached: bool = False


@dataclass
class ProviderHealthMetrics:
    """Provider health metrics"""
    status: AIProviderStatus = AIProviderStatus.HEALTHY
    last_request_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    last_error_time: Optional[datetime] = None
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    average_response_time: float = 0.0
    error_rate: float = 0.0
    rate_limit_hits: int = 0
    consecutive_failures: int = 0
    response_times: deque = field(default_factory=lambda: deque(maxlen=100))


class BaseAIProvider(ABC):
    """Abstract base class for AI providers"""
    
    def __init__(self, config: Dict[str, Any], provider_name: AIProvider):
        """Initialize AI provider
        
        Args:
            config: Provider configuration
            provider_name: Provider identifier
        """
        self.config = config
        self.provider_name = provider_name
        self.enabled = config.get('enabled', False)
        
        # Health metrics
        self.health_metrics = ProviderHealthMetrics()
        
        # Rate limiting
        self.rate_limiter = deque()
        self.rate_limit_window = timedelta(minutes=1)
        self.max_requests_per_minute = config.get('max_requests_per_minute', 60)
        
        # Circuit breaker
        self.circuit_breaker_threshold = config.get('circuit_breaker_threshold', 5)
        self.circuit_breaker_timeout = timedelta(minutes=config.get('circuit_breaker_timeout_minutes', 5))
        self.circuit_open_time = None

    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the provider client
        
        Returns:
            True if initialization successful, False otherwise
        """
        pass

    @abstractmethod
    async def analyze(self, request: AIAnalysisRequest) -> AIAnalysisResponse:
        """Perform AI analysis
        
        Args:
            request: Analysis request
            
        Returns:
            Analysis response
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check provider health
        
        Returns:
            True if provider is healthy, False otherwise
        """
        pass

    @abstractmethod
    async def get_available_models(self) -> List[str]:
        """Get list of available models
        
        Returns:
            List of available model names
        """
        pass

    async def is_rate_limited(self) -> bool:
        """Check if provider is rate limited
        
        Returns:
            True if rate limited, False otherwise
        """
        now = datetime.utcnow()
        
        # Clean old requests from rate limiter
        while self.rate_limiter and (now - self.rate_limiter[0]) > self.rate_limit_window:
            self.rate_limiter.popleft()
        
        return len(self.rate_limiter) >= self.max_requests_per_minute

    async def is_circuit_breaker_open(self) -> bool:
        """Check if circuit breaker is open
        
        Returns:
            True if circuit breaker is open, False otherwise
        """
        if self.circuit_open_time is None:
            return False
        
        # Reset circuit breaker after timeout
        if datetime.utcnow() - self.circuit_open_time > self.circuit_breaker_timeout:
            self.circuit_open_time = None
            self.health_metrics.consecutive_failures = 0
            logger.info("Circuit breaker reset", provider=self.provider_name)
            return False
        
        return True

    async def update_health_metrics(self, success: bool, response_time: float, error: Optional[str] = None):
        """Update provider health metrics
        
        Args:
            success: Whether request was successful
            response_time: Response time in seconds
            error: Error message if failed
        """
        now = datetime.utcnow()
        self.health_metrics.last_request_time = now
        self.health_metrics.total_requests += 1
        self.health_metrics.response_times.append(response_time)
        
        if success:
            self.health_metrics.successful_requests += 1
            self.health_metrics.last_success_time = now
            self.health_metrics.consecutive_failures = 0
            
            # Close circuit breaker on success
            if self.circuit_open_time is not None:
                self.circuit_open_time = None
                logger.info("Circuit breaker closed after successful request", provider=self.provider_name)
        else:
            self.health_metrics.failed_requests += 1
            self.health_metrics.last_error_time = now
            self.health_metrics.consecutive_failures += 1
            
            # Open circuit breaker if threshold reached
            if (self.health_metrics.consecutive_failures >= self.circuit_breaker_threshold 
                and self.circuit_open_time is None):
                self.circuit_open_time = now
                logger.warning("Circuit breaker opened due to consecutive failures", 
                             provider=self.provider_name, 
                             failures=self.health_metrics.consecutive_failures)
        
        # Update error rate and average response time
        if self.health_metrics.total_requests > 0:
            self.health_metrics.error_rate = (
                self.health_metrics.failed_requests / self.health_metrics.total_requests
            )
        
        if self.health_metrics.response_times:
            self.health_metrics.average_response_time = sum(self.health_metrics.response_times) / len(
                self.health_metrics.response_times
            )
        
        # Update status based on metrics
        self._update_status()

    def _update_status(self):
        """Update provider status based on health metrics"""
        if not self.enabled:
            self.health_metrics.status = AIProviderStatus.OFFLINE
        elif self.circuit_open_time is not None:
            self.health_metrics.status = AIProviderStatus.UNHEALTHY
        elif self.health_metrics.error_rate > 0.5:
            self.health_metrics.status = AIProviderStatus.UNHEALTHY
        elif self.health_metrics.error_rate > 0.2:
            self.health_metrics.status = AIProviderStatus.DEGRADED
        else:
            self.health_metrics.status = AIProviderStatus.HEALTHY

    async def track_request(self):
        """Track request for rate limiting"""
        self.rate_limiter.append(datetime.utcnow())


class AIProviderManager:
    """Manages multiple AI providers with load balancing and fallback"""
    
    def __init__(self, config: Dict[str, Any], redis_client: Optional[aioredis.Redis] = None):
        """Initialize AI provider manager
        
        Args:
            config: AI configuration
            redis_client: Optional Redis client for caching
        """
        self.config = config
        self.redis_client = redis_client
        self.providers: Dict[AIProvider, BaseAIProvider] = {}
        self.default_provider = AIProvider(config.get('default_provider', 'openai'))
        self.fallback_providers = [AIProvider(p) for p in config.get('fallback_providers', [])]
        
        # Load balancing
        self.load_balancer_index = defaultdict(int)
        
        # Caching
        self.cache_ttl = config.get('cache_ttl', 3600)
        self.enable_cache = config.get('enable_cache', True)
        
        # Concurrency control
        self.max_concurrent_requests = config.get('max_concurrent_requests', 10)
        self.semaphore = asyncio.Semaphore(self.max_concurrent_requests)
        
        # Health monitoring
        self.health_check_interval = config.get('health_check_interval', 60)
        self.health_monitor_task = None
        
    async def initialize(self):
        """Initialize all configured providers"""
        try:
            # Import and initialize providers based on config
            enabled_providers = []
            
            if self.config.get('openai', {}).get('enabled', False):
                from .openai_client import OpenAIProvider
                provider = OpenAIProvider(self.config['openai'])
                if await provider.initialize():
                    self.providers[AIProvider.OPENAI] = provider
                    enabled_providers.append(AIProvider.OPENAI)
            
            if self.config.get('anthropic', {}).get('enabled', False):
                from .anthropic_client import AnthropicProvider
                provider = AnthropicProvider(self.config['anthropic'])
                if await provider.initialize():
                    self.providers[AIProvider.ANTHROPIC] = provider
                    enabled_providers.append(AIProvider.ANTHROPIC)
            
            if self.config.get('ollama', {}).get('enabled', False):
                from .ollama_client import OllamaProvider
                provider = OllamaProvider(self.config['ollama'])
                if await provider.initialize():
                    self.providers[AIProvider.OLLAMA] = provider
                    enabled_providers.append(AIProvider.OLLAMA)
            
            if not enabled_providers:
                logger.warning("No AI providers enabled or available")
                return False
            
            # Start health monitoring
            self.health_monitor_task = asyncio.create_task(self._health_monitor())
            
            logger.info("AI provider manager initialized", providers=enabled_providers)
            return True
            
        except Exception as e:
            logger.error("Failed to initialize AI provider manager", error=str(e))
            return False

    async def analyze(self, request: AIAnalysisRequest) -> Optional[AIAnalysisResponse]:
        """Analyze request using available providers with fallback
        
        Args:
            request: Analysis request
            
        Returns:
            Analysis response or None if all providers failed
        """
        async with self.semaphore:
            # Check cache first
            if self.enable_cache and self.redis_client:
                cached_response = await self._get_cached_response(request)
                if cached_response:
                    return cached_response
            
            # Try providers in order: default, then fallbacks
            providers_to_try = [self.default_provider] + self.fallback_providers
            
            for provider_name in providers_to_try:
                if provider_name not in self.providers:
                    continue
                
                provider = self.providers[provider_name]
                
                # Skip if provider is unhealthy
                if provider.health_metrics.status == AIProviderStatus.UNHEALTHY:
                    continue
                
                # Skip if circuit breaker is open
                if await provider.is_circuit_breaker_open():
                    continue
                
                # Skip if rate limited
                if await provider.is_rate_limited():
                    continue
                
                try:
                    start_time = time.time()
                    await provider.track_request()
                    
                    response = await provider.analyze(request)
                    processing_time = time.time() - start_time
                    
                    await provider.update_health_metrics(True, processing_time)
                    
                    # Cache successful response
                    if self.enable_cache and self.redis_client:
                        await self._cache_response(request, response)
                    
                    logger.info("AI analysis completed", 
                              provider=provider_name,
                              request_id=request.request_id,
                              processing_time=processing_time)
                    
                    return response
                    
                except Exception as e:
                    processing_time = time.time() - start_time
                    await provider.update_health_metrics(False, processing_time, str(e))
                    
                    logger.warning("AI analysis failed, trying next provider", 
                                 provider=provider_name,
                                 request_id=request.request_id,
                                 error=str(e))
                    continue
            
            logger.error("All AI providers failed for request", request_id=request.request_id)
            return None

    async def get_provider_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all providers
        
        Returns:
            Provider status information
        """
        status = {}
        
        for provider_name, provider in self.providers.items():
            metrics = provider.health_metrics
            status[provider_name.value] = {
                'status': metrics.status.value,
                'enabled': provider.enabled,
                'total_requests': metrics.total_requests,
                'successful_requests': metrics.successful_requests,
                'failed_requests': metrics.failed_requests,
                'error_rate': metrics.error_rate,
                'average_response_time': metrics.average_response_time,
                'consecutive_failures': metrics.consecutive_failures,
                'last_request_time': metrics.last_request_time.isoformat() if metrics.last_request_time else None,
                'last_success_time': metrics.last_success_time.isoformat() if metrics.last_success_time else None,
                'last_error_time': metrics.last_error_time.isoformat() if metrics.last_error_time else None,
                'circuit_breaker_open': await provider.is_circuit_breaker_open(),
                'rate_limited': await provider.is_rate_limited()
            }
        
        return status

    async def _get_cached_response(self, request: AIAnalysisRequest) -> Optional[AIAnalysisResponse]:
        """Get cached response if available
        
        Args:
            request: Analysis request
            
        Returns:
            Cached response or None
        """
        try:
            # Create cache key from request content
            cache_data = {
                'analysis_type': request.analysis_type,
                'data': request.data,
                'prompt_template': request.prompt_template,
                'custom_prompt': request.custom_prompt
            }
            cache_key = f"ai_response:{hashlib.sha256(json.dumps(cache_data, sort_keys=True).encode()).hexdigest()}"
            
            cached_data = await self.redis_client.get(cache_key)
            if cached_data:
                response_data = json.loads(cached_data)
                response = AIAnalysisResponse(**response_data)
                response.cached = True
                
                logger.debug("Cache hit for AI analysis", request_id=request.request_id)
                return response
                
        except Exception as e:
            logger.warning("Failed to get cached response", error=str(e))
        
        return None

    async def _cache_response(self, request: AIAnalysisRequest, response: AIAnalysisResponse):
        """Cache analysis response
        
        Args:
            request: Analysis request
            response: Analysis response
        """
        try:
            # Create cache key from request content
            cache_data = {
                'analysis_type': request.analysis_type,
                'data': request.data,
                'prompt_template': request.prompt_template,
                'custom_prompt': request.custom_prompt
            }
            cache_key = f"ai_response:{hashlib.sha256(json.dumps(cache_data, sort_keys=True).encode()).hexdigest()}"
            
            # Convert response to dict for caching
            response_data = {
                'request_id': response.request_id,
                'provider': response.provider.value,
                'model': response.model,
                'analysis_type': response.analysis_type.value,
                'response_text': response.response_text,
                'confidence_score': response.confidence_score,
                'tokens_used': response.tokens_used,
                'processing_time': response.processing_time,
                'timestamp': response.timestamp.isoformat(),
                'metadata': response.metadata
            }
            
            await self.redis_client.setex(
                cache_key,
                self.cache_ttl,
                json.dumps(response_data)
            )
            
            logger.debug("Cached AI analysis response", request_id=request.request_id)
            
        except Exception as e:
            logger.warning("Failed to cache response", error=str(e))

    async def _health_monitor(self):
        """Background task to monitor provider health"""
        while True:
            try:
                await asyncio.sleep(self.health_check_interval)
                
                for provider_name, provider in self.providers.items():
                    try:
                        health_ok = await provider.health_check()
                        if not health_ok:
                            logger.warning("Provider health check failed", provider=provider_name)
                    except Exception as e:
                        logger.error("Provider health check error", provider=provider_name, error=str(e))
                        
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Health monitor error", error=str(e))

    async def shutdown(self):
        """Shutdown provider manager"""
        if self.health_monitor_task:
            self.health_monitor_task.cancel()
            try:
                await self.health_monitor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("AI provider manager shutdown complete")