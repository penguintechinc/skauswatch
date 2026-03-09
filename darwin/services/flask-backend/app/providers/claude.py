"""Anthropic Claude AI provider."""
import logging
import time
from typing import AsyncGenerator

from anthropic import AsyncAnthropic, APIError, RateLimitError

from .base import AIProvider, AIResponse, ProviderConfig

logger = logging.getLogger(__name__)


class ClaudeProvider(AIProvider):
    """Anthropic Claude AI provider."""

    name = "claude"
    supports_streaming = True
    supports_function_calling = True

    # Pricing per million tokens (as of 2025)
    MODEL_PRICING = {
        "claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
        "claude-opus-4-20250514": {"input": 15.00, "output": 75.00},
        "claude-3-5-sonnet-20241022": {"input": 3.00, "output": 15.00},
        "claude-3-5-haiku-20241022": {"input": 0.80, "output": 4.00},
        "claude-3-opus-20240229": {"input": 15.00, "output": 75.00},
        "claude-3-sonnet-20240229": {"input": 3.00, "output": 15.00},
        "claude-3-haiku-20240307": {"input": 0.25, "output": 1.25},
    }

    def __init__(self, config: ProviderConfig):
        """Initialize Claude provider.

        Args:
            config: Provider configuration
        """
        super().__init__(config)
        self.client = AsyncAnthropic(api_key=config.api_key)
        if not config.model:
            self.config.model = "claude-sonnet-4-20250514"

    def _validate_config(self) -> None:
        """Validate Claude configuration.

        Raises:
            ValueError: If configuration is invalid
        """
        if not self.config.api_key:
            raise ValueError("Claude API key is required")

        if self.config.model and not self.config.model.startswith("claude-"):
            raise ValueError(f"Invalid Claude model: {self.config.model}")

    async def complete(
        self, prompt: str, system_prompt: str | None = None
    ) -> AIResponse:
        """Generate completion using Claude.

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
            kwargs = {
                "model": self.config.model,
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature,
                "messages": [{"role": "user", "content": prompt}],
            }

            if system_prompt:
                kwargs["system"] = system_prompt

            response = await self.client.messages.create(**kwargs)

            latency_ms = int((time.time() - start_time) * 1000)

            return AIResponse(
                content=response.content[0].text,
                model=response.model,
                prompt_tokens=response.usage.input_tokens,
                completion_tokens=response.usage.output_tokens,
                total_tokens=response.usage.input_tokens
                + response.usage.output_tokens,
                latency_ms=latency_ms,
                finish_reason=response.stop_reason or "complete",
            )

        except RateLimitError as e:
            logger.error(f"Claude rate limit exceeded: {e}")
            raise
        except APIError as e:
            logger.error(f"Claude API error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error calling Claude: {e}")
            raise

    async def stream(
        self, prompt: str, system_prompt: str | None = None
    ) -> AsyncGenerator[str, None]:
        """Stream completion using Claude.

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
            kwargs = {
                "model": self.config.model,
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature,
                "messages": [{"role": "user", "content": prompt}],
            }

            if system_prompt:
                kwargs["system"] = system_prompt

            async with self.client.messages.stream(**kwargs) as stream:
                async for text in stream.text_stream:
                    yield text

        except RateLimitError as e:
            logger.error(f"Claude rate limit exceeded during streaming: {e}")
            raise
        except APIError as e:
            logger.error(f"Claude API error during streaming: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error streaming from Claude: {e}")
            raise

    async def health_check(self) -> bool:
        """Check if Claude API is accessible.

        Returns:
            True if API is healthy, False otherwise
        """
        try:
            # Simple test with minimal tokens
            response = await self.client.messages.create(
                model=self.config.model,
                max_tokens=10,
                messages=[{"role": "user", "content": "Hello"}],
            )
            return response is not None
        except Exception as e:
            logger.error(f"Claude health check failed: {e}")
            return False

    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Estimate cost for Claude API usage.

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
