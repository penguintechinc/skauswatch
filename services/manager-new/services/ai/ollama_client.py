"""Ollama AI provider client.

Supports both local and remote Ollama instances.
"""

from typing import Any, Dict, List, Optional

import httpx
import structlog
from services.ai.provider import AIProvider

logger = structlog.get_logger()


class OllamaClient(AIProvider):
    """
    Ollama client for local or remote LLM inference.

    Supports remote Ollama servers via OLLAMA_URL environment variable.
    Example: OLLAMA_URL=https://ollama.example.com:11434

    Features:
    - Local and remote server support
    - Multiple model support (llama3, mistral, codellama, etc.)
    - Streaming and non-streaming responses
    - Custom system prompts
    - Temperature and other parameter control
    """

    def __init__(
        self,
        url: str = "http://localhost:11434",
        model: str = "llama3",
        timeout: int = 120,
    ):
        """
        Initialize Ollama client.

        Args:
            url: Ollama server URL (can be remote)
            model: Default model to use
            timeout: Request timeout in seconds
        """
        self._url = url.rstrip("/")
        self._model = model
        self._timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=self._url,
            timeout=timeout,
        )

    @property
    def name(self) -> str:
        return "ollama"

    @property
    def model(self) -> str:
        return self._model

    async def analyze(
        self,
        prompt: str,
        system: str = None,
        model: str = None,
        temperature: float = 0.7,
        **kwargs,
    ) -> str:
        """
        Send analysis request to Ollama.

        Args:
            prompt: The prompt to analyze
            system: Optional system prompt
            model: Override default model
            temperature: Response randomness (0-1)
            **kwargs: Additional Ollama parameters

        Returns:
            AI response text
        """
        payload = {
            "model": model or self._model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }

        if system:
            payload["system"] = system

        # Add any extra options
        if kwargs:
            payload["options"].update(kwargs)

        try:
            response = await self._client.post("/api/generate", json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("response", "")

        except httpx.HTTPStatusError as e:
            logger.error(
                "Ollama API error", status=e.response.status_code, error=str(e)
            )
            raise
        except httpx.TimeoutException:
            logger.error("Ollama request timed out")
            raise
        except Exception as e:
            logger.error("Ollama request failed", error=str(e))
            raise

    async def chat(
        self,
        messages: List[Dict[str, str]],
        system: str = None,
        model: str = None,
        temperature: float = 0.7,
        **kwargs,
    ) -> str:
        """
        Multi-turn chat with Ollama.

        Args:
            messages: List of {'role': 'user/assistant', 'content': '...'}
            system: Optional system prompt
            model: Override default model
            temperature: Response randomness (0-1)

        Returns:
            AI response text
        """
        # Convert messages format for Ollama
        ollama_messages = []

        if system:
            ollama_messages.append(
                {
                    "role": "system",
                    "content": system,
                }
            )

        for msg in messages:
            ollama_messages.append(
                {
                    "role": msg["role"],
                    "content": msg["content"],
                }
            )

        payload = {
            "model": model or self._model,
            "messages": ollama_messages,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }

        if kwargs:
            payload["options"].update(kwargs)

        try:
            response = await self._client.post("/api/chat", json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("message", {}).get("content", "")

        except Exception as e:
            logger.error("Ollama chat failed", error=str(e))
            raise

    async def health_check(self) -> bool:
        """Check if Ollama server is available."""
        try:
            response = await self._client.get("/api/tags")
            return response.status_code == 200
        except Exception:
            return False

    async def list_models(self) -> List[Dict[str, Any]]:
        """List available models on the Ollama server."""
        try:
            response = await self._client.get("/api/tags")
            response.raise_for_status()
            data = response.json()
            return data.get("models", [])
        except Exception as e:
            logger.error("Failed to list models", error=str(e))
            return []

    async def pull_model(self, model_name: str) -> bool:
        """Pull a model from Ollama registry."""
        try:
            response = await self._client.post(
                "/api/pull",
                json={"name": model_name},
                timeout=600,  # Extended timeout for pulling
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error("Failed to pull model", model=model_name, error=str(e))
            return False

    async def get_model_info(self, model_name: str = None) -> Dict[str, Any]:
        """Get information about a model."""
        model = model_name or self._model

        try:
            response = await self._client.post(
                "/api/show",
                json={"name": model},
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error("Failed to get model info", model=model, error=str(e))
            return {}

    async def generate_embeddings(self, text: str, model: str = None) -> List[float]:
        """Generate embeddings for text."""
        try:
            response = await self._client.post(
                "/api/embeddings",
                json={
                    "model": model or self._model,
                    "prompt": text,
                },
            )
            response.raise_for_status()
            data = response.json()
            return data.get("embedding", [])
        except Exception as e:
            logger.error("Failed to generate embeddings", error=str(e))
            return []

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
