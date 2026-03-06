"""GitHub Copilot AI provider."""
import logging
import time
from typing import AsyncGenerator

import httpx

from .base import AIProvider, AIResponse, ProviderConfig

logger = logging.getLogger(__name__)


class CopilotProvider(AIProvider):
    """GitHub Copilot AI provider.

    Note: This uses the GitHub Copilot Preview API which may require
    GitHub App authentication. Implementation is basic and may need
    adjustments based on actual API requirements.
    """

    name = "copilot"
    supports_streaming = True
    supports_function_calling = False

    def __init__(self, config: ProviderConfig):
        """Initialize Copilot provider.

        Args:
            config: Provider configuration
        """
        super().__init__(config)
        self.base_url = config.base_url or "https://api.github.com/copilot"
        if not config.model:
            self.config.model = "gpt-4"

    def _validate_config(self) -> None:
        """Validate Copilot configuration.

        Raises:
            ValueError: If configuration is invalid
        """
        if not self.config.api_key:
            raise ValueError(
                "GitHub token is required for Copilot (use GITHUB_TOKEN)"
            )

    async def complete(
        self, prompt: str, system_prompt: str | None = None
    ) -> AIResponse:
        """Generate completion using Copilot.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt

        Returns:
            AI response with content and metadata

        Raises:
            httpx.HTTPError: If API call fails
        """
        start_time = time.time()

        try:
            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            payload = {
                "messages": messages,
                "model": self.config.model,
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature,
            }

            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/completions",
                    headers=headers,
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()

            latency_ms = int((time.time() - start_time) * 1000)

            # Parse response (structure may vary based on actual API)
            content = data.get("choices", [{}])[0].get("message", {}).get(
                "content", ""
            )
            usage = data.get("usage", {})

            return AIResponse(
                content=content,
                model=data.get("model", self.config.model),
                prompt_tokens=usage.get("prompt_tokens", 0),
                completion_tokens=usage.get("completion_tokens", 0),
                total_tokens=usage.get("total_tokens", 0),
                latency_ms=latency_ms,
                finish_reason=data.get("choices", [{}])[0].get(
                    "finish_reason", "complete"
                ),
            )

        except httpx.HTTPStatusError as e:
            logger.error(f"Copilot API HTTP error: {e.response.status_code} - {e}")
            raise
        except httpx.RequestError as e:
            logger.error(f"Copilot API request error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error calling Copilot: {e}")
            raise

    async def stream(
        self, prompt: str, system_prompt: str | None = None
    ) -> AsyncGenerator[str, None]:
        """Stream completion using Copilot.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt

        Yields:
            Content chunks

        Raises:
            httpx.HTTPError: If API call fails
        """
        try:
            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Accept": "text/event-stream",
                "Content-Type": "application/json",
            }

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            payload = {
                "messages": messages,
                "model": self.config.model,
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature,
                "stream": True,
            }

            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                async with client.stream(
                    "POST",
                    f"{self.base_url}/completions",
                    headers=headers,
                    json=payload,
                ) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            data_str = line[6:]
                            if data_str == "[DONE]":
                                break
                            try:
                                import json

                                data = json.loads(data_str)
                                content = (
                                    data.get("choices", [{}])[0]
                                    .get("delta", {})
                                    .get("content", "")
                                )
                                if content:
                                    yield content
                            except json.JSONDecodeError:
                                continue

        except httpx.HTTPStatusError as e:
            logger.error(
                f"Copilot streaming HTTP error: {e.response.status_code} - {e}"
            )
            raise
        except httpx.RequestError as e:
            logger.error(f"Copilot streaming request error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error streaming from Copilot: {e}")
            raise

    async def health_check(self) -> bool:
        """Check if Copilot API is accessible.

        Returns:
            True if API is healthy, False otherwise
        """
        try:
            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Accept": "application/json",
            }

            async with httpx.AsyncClient(timeout=10) as client:
                # Try to access API endpoint
                response = await client.get(
                    f"{self.base_url}/models",
                    headers=headers,
                )
                return response.status_code == 200

        except Exception as e:
            logger.error(f"Copilot health check failed: {e}")
            return False

    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Estimate cost for Copilot usage.

        Note: Copilot pricing is typically subscription-based,
        not per-token. Return 0 for now.

        Args:
            prompt_tokens: Number of prompt tokens
            completion_tokens: Number of completion tokens

        Returns:
            Estimated cost in USD (0 for subscription-based)
        """
        return 0.0
