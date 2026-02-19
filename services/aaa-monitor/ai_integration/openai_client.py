"""
SkausWatch AAA Monitor Service - OpenAI Client

OpenAI integration for log analysis with GPT models.
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import openai
import structlog
from openai import AsyncOpenAI

from ..models import AIProvider
from .ai_provider import (
    AIAnalysisRequest,
    AIAnalysisResponse,
    AIProviderStatus,
    BaseAIProvider,
)

logger = structlog.get_logger(__name__)


class OpenAIProvider(BaseAIProvider):
    """OpenAI provider implementation"""

    def __init__(self, config: Dict[str, Any]):
        """Initialize OpenAI provider

        Args:
            config: OpenAI configuration
        """
        super().__init__(config, AIProvider.OPENAI)

        self.api_key = config.get("api_key", "")
        self.model = config.get("model", "gpt-3.5-turbo")
        self.max_tokens = config.get("max_tokens", 1000)
        self.temperature = config.get("temperature", 0.1)
        self.timeout = config.get("timeout", 30)
        self.base_url = config.get("base_url")  # For custom endpoints

        # Client instance
        self.client = None

        # Model capabilities
        self.supported_models = [
            "gpt-3.5-turbo",
            "gpt-3.5-turbo-16k",
            "gpt-4",
            "gpt-4-32k",
            "gpt-4-turbo",
            "gpt-4-turbo-preview",
            "gpt-4o",
            "gpt-4o-mini",
        ]

        # Token limits by model
        self.model_token_limits = {
            "gpt-3.5-turbo": 4096,
            "gpt-3.5-turbo-16k": 16384,
            "gpt-4": 8192,
            "gpt-4-32k": 32768,
            "gpt-4-turbo": 128000,
            "gpt-4-turbo-preview": 128000,
            "gpt-4o": 128000,
            "gpt-4o-mini": 128000,
        }

    async def initialize(self) -> bool:
        """Initialize OpenAI client

        Returns:
            True if initialization successful, False otherwise
        """
        try:
            if not self.api_key:
                logger.error("OpenAI API key not provided")
                self.enabled = False
                return False

            # Initialize client
            client_kwargs = {"api_key": self.api_key, "timeout": self.timeout}

            if self.base_url:
                client_kwargs["base_url"] = self.base_url

            self.client = AsyncOpenAI(**client_kwargs)

            # Test connection with a simple request
            try:
                response = await self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": "Hello"}],
                    max_tokens=10,
                    timeout=10,
                )

                logger.info(
                    "OpenAI provider initialized successfully",
                    model=self.model,
                    api_key_prefix=self.api_key[:8] + "...",
                )
                return True

            except openai.AuthenticationError:
                logger.error("OpenAI authentication failed - invalid API key")
                self.enabled = False
                return False

            except openai.RateLimitError:
                logger.warning(
                    "OpenAI rate limit hit during initialization, but provider available"
                )
                return True

            except Exception as e:
                logger.error("OpenAI initialization test failed", error=str(e))
                # Don't disable on test failure - might be temporary
                return True

        except Exception as e:
            logger.error("Failed to initialize OpenAI provider", error=str(e))
            self.enabled = False
            return False

    async def analyze(self, request: AIAnalysisRequest) -> AIAnalysisResponse:
        """Perform AI analysis using OpenAI

        Args:
            request: Analysis request

        Returns:
            Analysis response

        Raises:
            Exception: If analysis fails
        """
        if not self.client:
            raise Exception("OpenAI client not initialized")

        start_time = time.time()

        try:
            # Prepare the prompt
            if request.custom_prompt:
                prompt = request.custom_prompt
            elif request.prompt_template:
                # Template will be formatted elsewhere with request.data
                prompt = request.prompt_template
            else:
                # Basic prompt for log analysis
                prompt = self._build_default_prompt(request)

            # Prepare messages
            messages = [
                {
                    "role": "system",
                    "content": self._get_system_prompt(request.analysis_type),
                },
                {"role": "user", "content": prompt},
            ]

            # Determine model parameters
            model = self.model
            max_tokens = request.max_tokens or self.max_tokens
            temperature = (
                request.temperature
                if request.temperature is not None
                else self.temperature
            )
            timeout = request.timeout or self.timeout

            # Adjust max_tokens based on model limits
            if model in self.model_token_limits:
                model_limit = self.model_token_limits[model]
                # Estimate prompt tokens (rough approximation: 1 token ~= 4 characters)
                prompt_tokens = sum(len(msg["content"]) for msg in messages) // 4
                available_tokens = model_limit - prompt_tokens - 100  # Buffer
                max_tokens = min(max_tokens, available_tokens)

            if max_tokens <= 0:
                raise Exception(f"Prompt too long for model {model}")

            # Make API request
            response = await self.client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                timeout=timeout,
            )

            processing_time = time.time() - start_time

            # Extract response
            response_text = response.choices[0].message.content
            tokens_used = response.usage.total_tokens if response.usage else None

            # Calculate confidence based on response quality
            confidence_score = self._calculate_confidence(
                response_text, request.analysis_type
            )

            return AIAnalysisResponse(
                request_id=request.request_id,
                provider=AIProvider.OPENAI,
                model=model,
                analysis_type=request.analysis_type,
                response_text=response_text,
                confidence_score=confidence_score,
                tokens_used=tokens_used,
                processing_time=processing_time,
                metadata={
                    "finish_reason": response.choices[0].finish_reason,
                    "prompt_tokens": (
                        response.usage.prompt_tokens if response.usage else None
                    ),
                    "completion_tokens": (
                        response.usage.completion_tokens if response.usage else None
                    ),
                },
            )

        except openai.RateLimitError as e:
            self.health_metrics.rate_limit_hits += 1
            raise Exception(f"OpenAI rate limit exceeded: {str(e)}")

        except openai.AuthenticationError as e:
            self.enabled = False  # Disable provider on auth error
            raise Exception(f"OpenAI authentication error: {str(e)}")

        except openai.APITimeoutError as e:
            raise Exception(f"OpenAI request timeout: {str(e)}")

        except openai.APIError as e:
            raise Exception(f"OpenAI API error: {str(e)}")

        except Exception as e:
            raise Exception(f"OpenAI analysis failed: {str(e)}")

    async def health_check(self) -> bool:
        """Check OpenAI provider health

        Returns:
            True if provider is healthy, False otherwise
        """
        if not self.enabled or not self.client:
            return False

        try:
            # Simple health check with minimal token usage
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "OK"}],
                max_tokens=1,
                timeout=10,
            )

            return response.choices[0].message.content is not None

        except openai.AuthenticationError:
            self.enabled = False
            return False
        except openai.RateLimitError:
            # Rate limited but provider is technically healthy
            return True
        except Exception as e:
            logger.debug("OpenAI health check failed", error=str(e))
            return False

    async def get_available_models(self) -> List[str]:
        """Get list of available OpenAI models

        Returns:
            List of available model names
        """
        if not self.client:
            return []

        try:
            models = await self.client.models.list()
            available_models = []

            for model in models.data:
                if model.id in self.supported_models:
                    available_models.append(model.id)

            return available_models

        except Exception as e:
            logger.warning("Failed to get OpenAI models", error=str(e))
            return self.supported_models

    def _get_system_prompt(self, analysis_type) -> str:
        """Get system prompt based on analysis type

        Args:
            analysis_type: Type of analysis

        Returns:
            System prompt
        """
        prompts = {
            "security_event": (
                "You are a cybersecurity expert analyzing security logs. "
                "Focus on identifying threats, attack patterns, and security violations. "
                "Provide structured analysis with threat level, indicators, and recommendations."
            ),
            "anomaly_detection": (
                "You are a log analysis expert specializing in anomaly detection. "
                "Identify unusual patterns, outliers, and deviations from normal behavior. "
                "Explain why something is anomalous and assess its significance."
            ),
            "threat_classification": (
                "You are a threat intelligence analyst. Classify and categorize threats "
                "based on MITRE ATT&CK framework, TTPs, and threat actor behavior. "
                "Provide confidence scores and related IOCs."
            ),
            "log_correlation": (
                "You are a log correlation specialist. Analyze relationships between "
                "events, identify patterns across multiple log sources, and reconstruct "
                "attack sequences or incident timelines."
            ),
            "pattern_analysis": (
                "You are a pattern analysis expert. Identify recurring patterns, "
                "trends, and behaviors in log data. Focus on statistical significance "
                "and predictive insights."
            ),
            "incident_summary": (
                "You are an incident response analyst. Summarize security incidents "
                "with clear timelines, impact assessment, root cause, and remediation "
                "recommendations."
            ),
        }

        return prompts.get(
            (
                analysis_type.value
                if hasattr(analysis_type, "value")
                else str(analysis_type)
            ),
            "You are a log analysis expert. Analyze the provided data and give insights.",
        )

    def _build_default_prompt(self, request: AIAnalysisRequest) -> str:
        """Build default prompt for analysis request

        Args:
            request: Analysis request

        Returns:
            Formatted prompt
        """
        data_str = json.dumps(request.data, indent=2)

        prompt = f"""
Please analyze the following log data:

Analysis Type: {request.analysis_type.value if hasattr(request.analysis_type, 'value') else str(request.analysis_type)}

Log Data:
{data_str}

Context:
{json.dumps(request.context, indent=2) if request.context else 'No additional context provided'}

Please provide:
1. Summary of findings
2. Threat assessment (if applicable)
3. Confidence level (0-100%)
4. Recommendations for action
5. Related indicators or patterns

Format your response as structured text that can be easily parsed.
"""

        return prompt.strip()

    def _calculate_confidence(self, response_text: str, analysis_type) -> float:
        """Calculate confidence score based on response quality

        Args:
            response_text: AI response text
            analysis_type: Type of analysis

        Returns:
            Confidence score (0.0 to 1.0)
        """
        if not response_text:
            return 0.0

        confidence = 0.5  # Base confidence

        # Boost confidence for structured responses
        if any(
            keyword in response_text.lower()
            for keyword in ["summary:", "findings:", "recommendation", "analysis:"]
        ):
            confidence += 0.2

        # Boost for specific indicators
        if analysis_type.value == "security_event" and any(
            keyword in response_text.lower()
            for keyword in ["threat", "attack", "malicious", "suspicious", "alert"]
        ):
            confidence += 0.15

        # Boost for confidence indicators in response
        if any(
            phrase in response_text.lower()
            for phrase in ["high confidence", "confident", "certain", "definitive"]
        ):
            confidence += 0.1

        # Penalize for uncertainty indicators
        if any(
            phrase in response_text.lower()
            for phrase in [
                "unclear",
                "uncertain",
                "cannot determine",
                "insufficient data",
            ]
        ):
            confidence -= 0.2

        # Ensure confidence is in valid range
        return max(0.0, min(1.0, confidence))
