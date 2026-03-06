"""Ollama local AI provider."""
import logging
import time
from typing import AsyncGenerator

import httpx

from .base import AIProvider, AIResponse, ProviderConfig

logger = logging.getLogger(__name__)


class OllamaProvider(AIProvider):
    """Ollama local AI provider."""

    name = "ollama"
    supports_streaming = True
    supports_function_calling = False

    # Recommended models by review category (Western/US-based only)
    RECOMMENDED_MODELS = {
        "security": "granite-code:34b",  # IBM Granite - security-focused
        "best_practices": "llama3.3:70b",  # Meta Llama 3.3 - design reviews
        "framework": "codestral:22b",  # Mistral - framework patterns
        "iac": "granite-code:20b",  # IBM Granite - IaC and compliance
        "fallback": "starcoder2:15b",  # BigCode - general fallback
    }

    DEFAULT_MODEL = "granite-code:20b"  # Balanced security and performance

    def __init__(self, config: ProviderConfig):
        """Initialize Ollama provider.

        Args:
            config: Provider configuration
        """
        # Ollama doesn't need an API key
        if not config.api_key:
            config.api_key = "not-required"

        super().__init__(config)
        self.base_url = config.base_url or "http://localhost:11434"
        if not config.model:
            self.config.model = self.DEFAULT_MODEL

    def _validate_config(self) -> None:
        """Validate Ollama configuration.

        Raises:
            ValueError: If configuration is invalid
        """
        if not self.base_url:
            raise ValueError("Ollama base_url is required")

    async def complete(
        self, prompt: str, system_prompt: str | None = None
    ) -> AIResponse:
        """Generate completion using Ollama.

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
            payload = {
                "model": self.config.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": self.config.temperature,
                    "num_predict": self.config.max_tokens,
                },
            }

            if system_prompt:
                payload["system"] = system_prompt

            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()

            latency_ms = int((time.time() - start_time) * 1000)

            return AIResponse(
                content=data.get("response", ""),
                model=data.get("model", self.config.model),
                prompt_tokens=data.get("prompt_eval_count", 0),
                completion_tokens=data.get("eval_count", 0),
                total_tokens=data.get("prompt_eval_count", 0)
                + data.get("eval_count", 0),
                latency_ms=latency_ms,
                finish_reason=data.get("done_reason", "complete"),
            )

        except httpx.HTTPStatusError as e:
            logger.error(f"Ollama API HTTP error: {e.response.status_code} - {e}")
            raise
        except httpx.RequestError as e:
            logger.error(f"Ollama API request error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error calling Ollama: {e}")
            raise

    async def stream(
        self, prompt: str, system_prompt: str | None = None
    ) -> AsyncGenerator[str, None]:
        """Stream completion using Ollama.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt

        Yields:
            Content chunks

        Raises:
            httpx.HTTPError: If API call fails
        """
        try:
            payload = {
                "model": self.config.model,
                "prompt": prompt,
                "stream": True,
                "options": {
                    "temperature": self.config.temperature,
                    "num_predict": self.config.max_tokens,
                },
            }

            if system_prompt:
                payload["system"] = system_prompt

            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                async with client.stream(
                    "POST",
                    f"{self.base_url}/api/generate",
                    json=payload,
                ) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if line:
                            try:
                                import json

                                data = json.loads(line)
                                if data.get("response"):
                                    yield data["response"]
                                if data.get("done"):
                                    break
                            except json.JSONDecodeError:
                                continue

        except httpx.HTTPStatusError as e:
            logger.error(
                f"Ollama streaming HTTP error: {e.response.status_code} - {e}"
            )
            raise
        except httpx.RequestError as e:
            logger.error(f"Ollama streaming request error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error streaming from Ollama: {e}")
            raise

    async def health_check(self) -> bool:
        """Check if Ollama is accessible.

        Returns:
            True if Ollama is healthy, False otherwise
        """
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                return response.status_code == 200
        except Exception as e:
            logger.error(f"Ollama health check failed: {e}")
            return False

    async def list_models(self) -> list[str]:
        """List available Ollama models.

        Returns:
            List of model names

        Raises:
            httpx.HTTPError: If API call fails
        """
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                response.raise_for_status()
                data = response.json()

                models = []
                for model in data.get("models", []):
                    models.append(model.get("name", ""))

                return models

        except Exception as e:
            logger.error(f"Failed to list Ollama models: {e}")
            raise

    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Estimate cost for Ollama usage.

        Ollama runs locally and has no API costs.

        Args:
            prompt_tokens: Number of prompt tokens
            completion_tokens: Number of completion tokens

        Returns:
            0.0 (no cost for local models)
        """
        return 0.0

    @classmethod
    def get_model_for_category(
        cls, category: str, large_context: bool = False
    ) -> str:
        """Get recommended Ollama model for review category.

        Args:
            category: Review category (security, best_practices, framework, iac)
            large_context: Whether codebase is very large (>100K tokens)

        Returns:
            Ollama model name

        Examples:
            >>> OllamaProvider.get_model_for_category("security")
            'granite-code:34b'
            >>> OllamaProvider.get_model_for_category("framework", large_context=True)
            'codestral:22b'
        """
        # For large codebases, use Codestral with 256K context window
        if large_context:
            return "codestral:22b"

        # Return category-specific model or fallback
        return cls.RECOMMENDED_MODELS.get(category, cls.DEFAULT_MODEL)
