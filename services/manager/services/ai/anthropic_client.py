"""Anthropic Claude AI provider client."""

from typing import Any, Dict, List, Optional

import httpx
import structlog

from services.ai.provider import AIProvider

logger = structlog.get_logger()


class AnthropicClient(AIProvider):
    """
    Anthropic Claude client for AI analysis.

    Supports Claude 3 models:
    - claude-3-opus-20240229 (most capable)
    - claude-3-sonnet-20240229 (balanced)
    - claude-3-haiku-20240307 (fastest)
    """

    BASE_URL = "https://api.anthropic.com/v1"
    API_VERSION = "2023-06-01"

    def __init__(
        self,
        api_key: str,
        model: str = "claude-3-sonnet-20240229",
        max_tokens: int = 4096,
        timeout: int = 120,
    ):
        """
        Initialize Anthropic client.

        Args:
            api_key: Anthropic API key
            model: Claude model to use
            max_tokens: Maximum tokens in response
            timeout: Request timeout in seconds
        """
        self._api_key = api_key
        self._model = model
        self._max_tokens = max_tokens
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            headers={
                "x-api-key": api_key,
                "anthropic-version": self.API_VERSION,
                "content-type": "application/json",
            },
            timeout=timeout,
        )

    @property
    def name(self) -> str:
        return "anthropic"

    @property
    def model(self) -> str:
        return self._model

    async def analyze(
        self,
        prompt: str,
        system: str = None,
        model: str = None,
        max_tokens: int = None,
        temperature: float = 0.7,
        **kwargs,
    ) -> str:
        """
        Send analysis request to Claude.

        Args:
            prompt: The prompt to analyze
            system: Optional system prompt
            model: Override default model
            max_tokens: Override max tokens
            temperature: Response randomness (0-1)

        Returns:
            AI response text
        """
        payload = {
            "model": model or self._model,
            "max_tokens": max_tokens or self._max_tokens,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }

        if system:
            payload["system"] = system

        try:
            response = await self._client.post("/messages", json=payload)
            response.raise_for_status()
            data = response.json()

            # Extract text from content blocks
            content = data.get("content", [])
            text_parts = []
            for block in content:
                if block.get("type") == "text":
                    text_parts.append(block.get("text", ""))

            return "\n".join(text_parts)

        except httpx.HTTPStatusError as e:
            logger.error(
                "Anthropic API error", status=e.response.status_code, error=str(e)
            )
            raise
        except Exception as e:
            logger.error("Anthropic request failed", error=str(e))
            raise

    async def chat(
        self,
        messages: List[Dict[str, str]],
        system: str = None,
        model: str = None,
        max_tokens: int = None,
        temperature: float = 0.7,
        **kwargs,
    ) -> str:
        """
        Multi-turn chat with Claude.

        Args:
            messages: List of {'role': 'user/assistant', 'content': '...'}
            system: Optional system prompt
            model: Override default model
            max_tokens: Override max tokens
            temperature: Response randomness (0-1)

        Returns:
            AI response text
        """
        # Convert messages to Anthropic format
        anthropic_messages = []
        for msg in messages:
            role = msg["role"]
            if role == "system":
                continue  # System is separate in Anthropic API
            anthropic_messages.append(
                {
                    "role": role,
                    "content": msg["content"],
                }
            )

        payload = {
            "model": model or self._model,
            "max_tokens": max_tokens or self._max_tokens,
            "messages": anthropic_messages,
            "temperature": temperature,
        }

        if system:
            payload["system"] = system

        try:
            response = await self._client.post("/messages", json=payload)
            response.raise_for_status()
            data = response.json()

            content = data.get("content", [])
            text_parts = []
            for block in content:
                if block.get("type") == "text":
                    text_parts.append(block.get("text", ""))

            return "\n".join(text_parts)

        except Exception as e:
            logger.error("Anthropic chat failed", error=str(e))
            raise

    async def health_check(self) -> bool:
        """Check if Anthropic API is available."""
        try:
            # Make a minimal request to check API availability
            response = await self._client.post(
                "/messages",
                json={
                    "model": self._model,
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "Hi"}],
                },
            )
            return response.status_code == 200
        except Exception:
            return False

    async def count_tokens(self, text: str) -> int:
        """
        Estimate token count for text.

        Note: This is an approximation. Use the API's token counting
        for accurate counts.
        """
        # Rough approximation: ~4 characters per token for English
        return len(text) // 4

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
