"""OpenAI/ChatGPT AI provider."""
import logging
import time
from typing import AsyncGenerator

from openai import AsyncOpenAI, APIError, RateLimitError

from .base import AIProvider, AIResponse, ProviderConfig

logger = logging.getLogger(__name__)


class OpenAIProvider(AIProvider):
    """OpenAI/ChatGPT AI provider."""

    name = "openai"
    supports_streaming = True
    supports_function_calling = True

    # Pricing per million tokens (as of 2025)
    MODEL_PRICING = {
        "gpt-4o": {"input": 2.50, "output": 10.00},
        "gpt-4o-mini": {"input": 0.15, "output": 0.60},
        "gpt-4-turbo": {"input": 10.00, "output": 30.00},
        "gpt-4": {"input": 30.00, "output": 60.00},
        "gpt-3.5-turbo": {"input": 0.50, "output": 1.50},
    }

    def __init__(self, config: ProviderConfig):
        """Initialize OpenAI provider.

        Args:
            config: Provider configuration
        """
        super().__init__(config)
        kwargs = {"api_key": config.api_key}
        if config.base_url:
            kwargs["base_url"] = config.base_url

        self.client = AsyncOpenAI(**kwargs)
        if not config.model:
            self.config.model = "gpt-4o"

    def _validate_config(self) -> None:
        """Validate OpenAI configuration.

        Raises:
            ValueError: If configuration is invalid
        """
        if not self.config.api_key:
            raise ValueError("OpenAI API key is required")

    async def complete(
        self, prompt: str, system_prompt: str | None = None
    ) -> AIResponse:
        """Generate completion using OpenAI.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt

        Returns:
            AI response with content and metadata

        Raises:
            APIError: If API call fails
            RateLimitError: If rate limit exceeded
        """
        start_time = time.time()

        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = await self.client.chat.completions.create(
                model=self.config.model,
                messages=messages,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                timeout=self.config.timeout,
            )

            latency_ms = int((time.time() - start_time) * 1000)

            return AIResponse(
                content=response.choices[0].message.content or "",
                model=response.model,
                prompt_tokens=response.usage.prompt_tokens,
                completion_tokens=response.usage.completion_tokens,
                total_tokens=response.usage.total_tokens,
                latency_ms=latency_ms,
                finish_reason=response.choices[0].finish_reason or "complete",
            )

        except RateLimitError as e:
            logger.error(f"OpenAI rate limit exceeded: {e}")
            raise
        except APIError as e:
            logger.error(f"OpenAI API error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error calling OpenAI: {e}")
            raise

    async def stream(
        self, prompt: str, system_prompt: str | None = None
    ) -> AsyncGenerator[str, None]:
        """Stream completion using OpenAI.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt

        Yields:
            Content chunks

        Raises:
            APIError: If API call fails
            RateLimitError: If rate limit exceeded
        """
        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            stream = await self.client.chat.completions.create(
                model=self.config.model,
                messages=messages,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                timeout=self.config.timeout,
                stream=True,
            )

            async for chunk in stream:
                if chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content

        except RateLimitError as e:
            logger.error(f"OpenAI rate limit exceeded during streaming: {e}")
            raise
        except APIError as e:
            logger.error(f"OpenAI API error during streaming: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error streaming from OpenAI: {e}")
            raise

    async def health_check(self) -> bool:
        """Check if OpenAI API is accessible.

        Returns:
            True if API is healthy, False otherwise
        """
        try:
            # Simple test with minimal tokens
            response = await self.client.chat.completions.create(
                model=self.config.model,
                messages=[{"role": "user", "content": "Hello"}],
                max_tokens=5,
            )
            return response is not None
        except Exception as e:
            logger.error(f"OpenAI health check failed: {e}")
            return False

    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Estimate cost for OpenAI API usage.

        Args:
            prompt_tokens: Number of prompt tokens
            completion_tokens: Number of completion tokens

        Returns:
            Estimated cost in USD
        """
        pricing = self.MODEL_PRICING.get(self.config.model)
        if not pricing:
            logger.warning(
                f"No pricing data for model {self.config.model}, returning 0"
            )
            return 0.0

        input_cost = (prompt_tokens / 1_000_000) * pricing["input"]
        output_cost = (completion_tokens / 1_000_000) * pricing["output"]

        return input_cost + output_cost
