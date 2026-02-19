"""AI Provider base class and factory."""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List

import structlog

logger = structlog.get_logger()


class AIProvider(ABC):
    """Abstract base class for AI providers."""

    @abstractmethod
    async def analyze(self, prompt: str, system: str = None, **kwargs) -> str:
        """
        Send analysis request to AI provider.

        Args:
            prompt: The prompt/question to analyze
            system: Optional system prompt
            **kwargs: Additional provider-specific parameters

        Returns:
            AI response text
        """
        pass

    @abstractmethod
    async def chat(
        self, messages: List[Dict[str, str]], system: str = None, **kwargs
    ) -> str:
        """
        Multi-turn chat with AI provider.

        Args:
            messages: List of message dicts with 'role' and 'content'
            system: Optional system prompt
            **kwargs: Additional parameters

        Returns:
            AI response text
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if AI provider is available.

        Returns:
            True if available, False otherwise
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Return provider name."""
        pass

    @property
    @abstractmethod
    def model(self) -> str:
        """Return model name/ID."""
        pass


class AIProviderFactory:
    """Factory for creating AI providers."""

    @staticmethod
    def create(provider_type: str, config: Dict[str, Any]) -> Optional[AIProvider]:
        """
        Create an AI provider instance.

        Args:
            provider_type: Type of provider ('ollama', 'anthropic', 'openai')
            config: Provider configuration

        Returns:
            AIProvider instance or None if creation fails
        """
        from .ollama_client import OllamaClient
        from .anthropic_client import AnthropicClient
        from .openai_client import OpenAIClient

        provider_type = provider_type.lower()

        try:
            if provider_type == "ollama":
                return OllamaClient(
                    url=config.get("url", "http://localhost:11434"),
                    model=config.get("model", "llama3"),
                    timeout=config.get("timeout", 120),
                )

            elif provider_type == "anthropic":
                api_key = config.get("api_key")
                if not api_key:
                    logger.error("Anthropic API key not provided")
                    return None

                return AnthropicClient(
                    api_key=api_key,
                    model=config.get("model", "claude-3-sonnet-20240229"),
                    max_tokens=config.get("max_tokens", 4096),
                )

            elif provider_type == "openai":
                api_key = config.get("api_key")
                if not api_key:
                    logger.error("OpenAI API key not provided")
                    return None

                return OpenAIClient(
                    api_key=api_key,
                    model=config.get("model", "gpt-4-turbo"),
                    max_tokens=config.get("max_tokens", 4096),
                )

            else:
                logger.error(f"Unknown AI provider type: {provider_type}")
                return None

        except Exception as e:
            logger.error(
                "Failed to create AI provider", provider=provider_type, error=str(e)
            )
            return None
