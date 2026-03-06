"""AI provider factory and implementations for worker-darwin.

Adapted from darwin/services/flask-backend/app/providers/.
Supports Anthropic Claude, OpenAI, and Ollama backends.
"""

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import AsyncGenerator, Optional

from config.settings import settings

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AIResponse:
    """Response from an AI provider."""

    content: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    latency_ms: int
    finish_reason: str


@dataclass(slots=True)
class ProviderConfig:
    """Configuration for an AI provider."""

    api_key: str
    base_url: Optional[str]
    model: str
    max_tokens: int
    temperature: float
    timeout: int


class AIProvider(ABC):
    """Abstract base class for AI providers."""

    name: str = ""

    def __init__(self, config: ProviderConfig) -> None:
        self.config = config
        self._validate_config()

    @abstractmethod
    def _validate_config(self) -> None:
        """Validate provider configuration."""

    @abstractmethod
    async def complete(self, prompt: str, system_prompt: Optional[str] = None) -> AIResponse:
        """Generate a completion for the given prompt."""

    async def stream(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> AsyncGenerator[str, None]:
        """Stream completion chunks (optional, default raises NotImplementedError)."""
        raise NotImplementedError("Streaming not supported by this provider")
        yield  # Make it an async generator

    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Estimate cost in USD for the given token usage."""
        return 0.0


class ClaudeProvider(AIProvider):
    """Anthropic Claude AI provider."""

    name = "anthropic"

    MODEL_PRICING: dict = {
        "claude-opus-4-5": {"input": 15.00, "output": 75.00},
        "claude-sonnet-4-5": {"input": 3.00, "output": 15.00},
        "claude-haiku-4-5": {"input": 0.80, "output": 4.00},
        "claude-opus-4-20250514": {"input": 15.00, "output": 75.00},
        "claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
        "claude-3-5-sonnet-20241022": {"input": 3.00, "output": 15.00},
        "claude-3-5-haiku-20241022": {"input": 0.80, "output": 4.00},
    }

    def __init__(self, config: ProviderConfig) -> None:
        super().__init__(config)
        from anthropic import AsyncAnthropic
        self.client = AsyncAnthropic(api_key=config.api_key)

    def _validate_config(self) -> None:
        if not self.config.api_key:
            raise ValueError("Anthropic API key is required")

    async def complete(self, prompt: str, system_prompt: Optional[str] = None) -> AIResponse:
        from anthropic import APIError, RateLimitError

        start = time.time()
        try:
            kwargs: dict = {
                "model": self.config.model,
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature,
                "messages": [{"role": "user", "content": prompt}],
            }
            if system_prompt:
                kwargs["system"] = system_prompt

            response = await self.client.messages.create(**kwargs)
            latency_ms = int((time.time() - start) * 1000)

            return AIResponse(
                content=response.content[0].text,
                model=response.model,
                prompt_tokens=response.usage.input_tokens,
                completion_tokens=response.usage.output_tokens,
                total_tokens=response.usage.input_tokens + response.usage.output_tokens,
                latency_ms=latency_ms,
                finish_reason=response.stop_reason or "complete",
            )
        except (APIError, RateLimitError):
            raise
        except Exception as exc:
            logger.error("Unexpected error calling Claude: %s", exc)
            raise

    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        pricing = self.MODEL_PRICING.get(self.config.model)
        if not pricing:
            return 0.0
        return (prompt_tokens / 1_000_000) * pricing["input"] + (
            completion_tokens / 1_000_000
        ) * pricing["output"]


class OpenAIProvider(AIProvider):
    """OpenAI API provider."""

    name = "openai"

    def __init__(self, config: ProviderConfig) -> None:
        super().__init__(config)
        from openai import AsyncOpenAI
        self.client = AsyncOpenAI(api_key=config.api_key)

    def _validate_config(self) -> None:
        if not self.config.api_key:
            raise ValueError("OpenAI API key is required")

    async def complete(self, prompt: str, system_prompt: Optional[str] = None) -> AIResponse:
        start = time.time()
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = await self.client.chat.completions.create(
            model=self.config.model or "gpt-4o",
            messages=messages,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
        )
        latency_ms = int((time.time() - start) * 1000)
        choice = response.choices[0]

        return AIResponse(
            content=choice.message.content or "",
            model=response.model,
            prompt_tokens=response.usage.prompt_tokens,
            completion_tokens=response.usage.completion_tokens,
            total_tokens=response.usage.total_tokens,
            latency_ms=latency_ms,
            finish_reason=choice.finish_reason or "complete",
        )


class OllamaProvider(AIProvider):
    """Ollama local model provider."""

    name = "ollama"

    def _validate_config(self) -> None:
        if not self.config.base_url:
            raise ValueError("Ollama base URL is required")

    async def complete(self, prompt: str, system_prompt: Optional[str] = None) -> AIResponse:
        import aiohttp

        start = time.time()
        payload: dict = {
            "model": self.config.model or "llama3",
            "prompt": prompt,
            "stream": False,
        }
        if system_prompt:
            payload["system"] = system_prompt

        async with aiohttp.ClientSession() as session:
            url = f"{self.config.base_url}/api/generate"
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=self.config.timeout)) as resp:
                resp.raise_for_status()
                data = await resp.json()

        latency_ms = int((time.time() - start) * 1000)
        return AIResponse(
            content=data.get("response", ""),
            model=data.get("model", self.config.model),
            prompt_tokens=data.get("prompt_eval_count", 0),
            completion_tokens=data.get("eval_count", 0),
            total_tokens=data.get("prompt_eval_count", 0) + data.get("eval_count", 0),
            latency_ms=latency_ms,
            finish_reason="complete",
        )


def create_provider(provider_name: Optional[str] = None) -> AIProvider:
    """Factory function to create an AI provider from settings.

    Args:
        provider_name: Provider name (anthropic, openai, ollama).
                       Defaults to settings.ai.provider.

    Returns:
        AIProvider: Configured provider instance

    Raises:
        ValueError: If provider is unknown or not configured
    """
    name = (provider_name or settings.ai.provider).lower()

    if name in ("anthropic", "claude"):
        if not settings.ai.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY is not configured")
        config = ProviderConfig(
            api_key=settings.ai.anthropic_api_key,
            base_url=None,
            model=settings.ai.model,
            max_tokens=4096,
            temperature=0.3,
            timeout=settings.ai.timeout,
        )
        return ClaudeProvider(config)

    elif name == "openai":
        if not settings.ai.openai_api_key:
            raise ValueError("OPENAI_API_KEY is not configured")
        config = ProviderConfig(
            api_key=settings.ai.openai_api_key,
            base_url=None,
            model=settings.ai.model or "gpt-4o",
            max_tokens=4096,
            temperature=0.3,
            timeout=settings.ai.timeout,
        )
        return OpenAIProvider(config)

    elif name == "ollama":
        config = ProviderConfig(
            api_key="",
            base_url=settings.ai.ollama_url,
            model=settings.ai.model or "llama3",
            max_tokens=4096,
            temperature=0.3,
            timeout=settings.ai.timeout,
        )
        return OllamaProvider(config)

    else:
        raise ValueError(f"Unknown AI provider: {name}. Supported: anthropic, openai, ollama")
