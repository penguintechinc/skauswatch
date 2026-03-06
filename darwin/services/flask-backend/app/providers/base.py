"""Abstract base class for AI providers."""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import AsyncGenerator


@dataclass(slots=True)
class AIResponse:
    """Response from AI provider."""

    content: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    latency_ms: int
    finish_reason: str


@dataclass(slots=True)
class ProviderConfig:
    """Configuration for AI provider."""

    api_key: str
    base_url: str | None = None
    model: str = ""
    max_tokens: int = 4096
    temperature: float = 0.3
    timeout: int = 120


class AIProvider(ABC):
    """Abstract base class for AI providers."""

    name: str = ""
    supports_streaming: bool = False
    supports_function_calling: bool = False

    def __init__(self, config: ProviderConfig):
        """Initialize provider with configuration.

        Args:
            config: Provider configuration
        """
        self.config = config
        self._validate_config()

    @abstractmethod
    def _validate_config(self) -> None:
        """Validate provider configuration.

        Raises:
            ValueError: If configuration is invalid
        """
        pass

    @abstractmethod
    async def complete(
        self, prompt: str, system_prompt: str | None = None
    ) -> AIResponse:
        """Generate completion for prompt.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt

        Returns:
            AI response with content and metadata

        Raises:
            Exception: If API call fails
        """
        pass

    @abstractmethod
    async def stream(
        self, prompt: str, system_prompt: str | None = None
    ) -> AsyncGenerator[str, None]:
        """Stream completion for prompt.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt

        Yields:
            Content chunks

        Raises:
            Exception: If API call fails
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if provider is healthy.

        Returns:
            True if provider is healthy, False otherwise
        """
        pass

    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Estimate cost for token usage.

        Args:
            prompt_tokens: Number of prompt tokens
            completion_tokens: Number of completion tokens

        Returns:
            Estimated cost in USD
        """
        return 0.0
