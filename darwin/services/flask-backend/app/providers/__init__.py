"""AI provider factory and registry."""
import logging
import os
from typing import Type

from .base import AIProvider, AIResponse, ProviderConfig
from .claude import ClaudeProvider
from .copilot import CopilotProvider
from .ollama import OllamaProvider
from .openai_provider import OpenAIProvider

logger = logging.getLogger(__name__)

# Provider registry
PROVIDERS: dict[str, Type[AIProvider]] = {
    "claude": ClaudeProvider,
    "anthropic": ClaudeProvider,
    "openai": OpenAIProvider,
    "chatgpt": OpenAIProvider,
    "copilot": CopilotProvider,
    "github": CopilotProvider,
    "ollama": OllamaProvider,
}


def get_provider(name: str, config: ProviderConfig | None = None) -> AIProvider:
    """Get AI provider instance by name.

    Args:
        name: Provider name (claude, openai, copilot, ollama)
        config: Optional provider configuration. If not provided,
                will be auto-configured from environment variables.

    Returns:
        Configured AI provider instance

    Raises:
        ValueError: If provider not found or configuration invalid

    Environment Variables:
        - AI_PROVIDER: Default provider name
        - ANTHROPIC_API_KEY: Claude API key
        - OPENAI_API_KEY: OpenAI API key
        - GITHUB_TOKEN: GitHub Copilot token
        - OLLAMA_BASE_URL: Ollama base URL
        - AI_MODEL: Model name override
        - AI_MAX_TOKENS: Max tokens override
        - AI_TEMPERATURE: Temperature override
    """
    provider_name = name.lower()

    if provider_name not in PROVIDERS:
        available = ", ".join(PROVIDERS.keys())
        raise ValueError(
            f"Unknown provider: {provider_name}. Available: {available}"
        )

    # Auto-configure from environment if no config provided
    if config is None:
        config = _auto_configure(provider_name)

    provider_class = PROVIDERS[provider_name]
    return provider_class(config)


def _auto_configure(provider_name: str) -> ProviderConfig:
    """Auto-configure provider from environment variables.

    Args:
        provider_name: Provider name

    Returns:
        Provider configuration

    Raises:
        ValueError: If required environment variables missing
    """
    # Map provider to environment variable
    api_key_map = {
        "claude": "ANTHROPIC_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "chatgpt": "OPENAI_API_KEY",
        "copilot": "GITHUB_TOKEN",
        "github": "GITHUB_TOKEN",
        "ollama": None,  # No API key needed
    }

    env_var = api_key_map.get(provider_name)
    api_key = ""

    if env_var:
        api_key = os.getenv(env_var, "")
        if not api_key:
            raise ValueError(
                f"Missing environment variable {env_var} for {provider_name}"
            )

    # Base URL configuration
    base_url = None
    if provider_name in ["ollama"]:
        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    elif provider_name in ["openai", "chatgpt"]:
        base_url = os.getenv("OPENAI_BASE_URL")  # Optional override

    # Model configuration
    model = os.getenv("AI_MODEL", "")

    # Token and temperature configuration
    max_tokens = int(os.getenv("AI_MAX_TOKENS", "4096"))
    temperature = float(os.getenv("AI_TEMPERATURE", "0.3"))
    timeout = int(os.getenv("AI_TIMEOUT", "120"))

    return ProviderConfig(
        api_key=api_key,
        base_url=base_url,
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        timeout=timeout,
    )


def list_providers() -> list[str]:
    """List all available provider names.

    Returns:
        List of provider names
    """
    return sorted(set(PROVIDERS.keys()))


def get_default_provider() -> AIProvider:
    """Get default AI provider from environment.

    Returns:
        Default AI provider instance

    Raises:
        ValueError: If AI_PROVIDER not set or invalid

    Environment Variables:
        AI_PROVIDER: Default provider name (required)
    """
    provider_name = os.getenv("AI_PROVIDER", "").lower()

    if not provider_name:
        raise ValueError(
            "AI_PROVIDER environment variable not set. "
            f"Available providers: {', '.join(list_providers())}"
        )

    return get_provider(provider_name)


__all__ = [
    "AIProvider",
    "AIResponse",
    "ProviderConfig",
    "ClaudeProvider",
    "OpenAIProvider",
    "CopilotProvider",
    "OllamaProvider",
    "get_provider",
    "list_providers",
    "get_default_provider",
    "PROVIDERS",
]
