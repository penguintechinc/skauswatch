"""OpenAI AI provider client."""
from typing import Optional, Dict, Any, List

import httpx
import structlog

from .provider import AIProvider

logger = structlog.get_logger()


class OpenAIClient(AIProvider):
    """
    OpenAI client for GPT models.

    Supports:
    - gpt-4-turbo (most capable)
    - gpt-4
    - gpt-3.5-turbo (fastest, cheapest)
    """

    BASE_URL = "https://api.openai.com/v1"

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4-turbo",
        max_tokens: int = 4096,
        timeout: int = 120,
        organization: str = None,
    ):
        """
        Initialize OpenAI client.

        Args:
            api_key: OpenAI API key
            model: GPT model to use
            max_tokens: Maximum tokens in response
            timeout: Request timeout in seconds
            organization: Optional organization ID
        """
        self._api_key = api_key
        self._model = model
        self._max_tokens = max_tokens

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        if organization:
            headers["OpenAI-Organization"] = organization

        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            headers=headers,
            timeout=timeout,
        )

    @property
    def name(self) -> str:
        return "openai"

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
        **kwargs
    ) -> str:
        """
        Send analysis request to OpenAI.

        Args:
            prompt: The prompt to analyze
            system: Optional system prompt
            model: Override default model
            max_tokens: Override max tokens
            temperature: Response randomness (0-2)

        Returns:
            AI response text
        """
        messages = []

        if system:
            messages.append({
                "role": "system",
                "content": system,
            })

        messages.append({
            "role": "user",
            "content": prompt,
        })

        payload = {
            "model": model or self._model,
            "messages": messages,
            "max_tokens": max_tokens or self._max_tokens,
            "temperature": temperature,
        }

        try:
            response = await self._client.post(
                "/chat/completions", json=payload
            )
            response.raise_for_status()
            data = response.json()

            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "")
            return ""

        except httpx.HTTPStatusError as e:
            logger.error(
                "OpenAI API error",
                status=e.response.status_code,
                error=str(e)
            )
            raise
        except Exception as e:
            logger.error("OpenAI request failed", error=str(e))
            raise

    async def chat(
        self,
        messages: List[Dict[str, str]],
        system: str = None,
        model: str = None,
        max_tokens: int = None,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        """
        Multi-turn chat with OpenAI.

        Args:
            messages: List of {'role': 'user/assistant/system', 'content': '...'}
            system: Optional system prompt (prepended if provided)
            model: Override default model
            max_tokens: Override max tokens
            temperature: Response randomness (0-2)

        Returns:
            AI response text
        """
        openai_messages = []

        if system:
            openai_messages.append({
                "role": "system",
                "content": system,
            })

        for msg in messages:
            openai_messages.append({
                "role": msg["role"],
                "content": msg["content"],
            })

        payload = {
            "model": model or self._model,
            "messages": openai_messages,
            "max_tokens": max_tokens or self._max_tokens,
            "temperature": temperature,
        }

        try:
            response = await self._client.post(
                "/chat/completions", json=payload
            )
            response.raise_for_status()
            data = response.json()

            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "")
            return ""

        except Exception as e:
            logger.error("OpenAI chat failed", error=str(e))
            raise

    async def health_check(self) -> bool:
        """Check if OpenAI API is available."""
        try:
            response = await self._client.get("/models")
            return response.status_code == 200
        except Exception:
            return False

    async def list_models(self) -> List[Dict[str, Any]]:
        """List available models."""
        try:
            response = await self._client.get("/models")
            response.raise_for_status()
            data = response.json()
            return data.get("data", [])
        except Exception as e:
            logger.error("Failed to list models", error=str(e))
            return []

    async def generate_embeddings(
        self,
        text: str,
        model: str = "text-embedding-ada-002"
    ) -> List[float]:
        """Generate embeddings for text."""
        try:
            response = await self._client.post(
                "/embeddings",
                json={
                    "input": text,
                    "model": model,
                },
            )
            response.raise_for_status()
            data = response.json()

            embeddings = data.get("data", [])
            if embeddings:
                return embeddings[0].get("embedding", [])
            return []

        except Exception as e:
            logger.error("Failed to generate embeddings", error=str(e))
            return []

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
