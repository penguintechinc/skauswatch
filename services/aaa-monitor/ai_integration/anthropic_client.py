"""
SkausWatch AAA Monitor Service - Anthropic Client

Anthropic Claude integration for log analysis.
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
import structlog

import anthropic
from anthropic import AsyncAnthropic

from .ai_provider import (
    BaseAIProvider,
    AIAnalysisRequest,
    AIAnalysisResponse,
    AIProviderStatus,
)
from ..models import AIProvider

logger = structlog.get_logger(__name__)


class AnthropicProvider(BaseAIProvider):
    """Anthropic Claude provider implementation"""

    def __init__(self, config: Dict[str, Any]):
        """Initialize Anthropic provider

        Args:
            config: Anthropic configuration
        """
        super().__init__(config, AIProvider.ANTHROPIC)

        self.api_key = config.get("api_key", "")
        self.model = config.get("model", "claude-3-sonnet-20240229")
        self.max_tokens = config.get("max_tokens", 1000)
        self.timeout = config.get("timeout", 30)
        self.base_url = config.get("base_url")  # For custom endpoints

        # Client instance
        self.client = None

        # Model capabilities
        self.supported_models = [
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229",
            "claude-3-haiku-20240307",
            "claude-3-5-sonnet-20241022",
            "claude-3-5-haiku-20241022",
        ]

        # Token limits by model (context window)
        self.model_token_limits = {
            "claude-3-opus-20240229": 200000,
            "claude-3-sonnet-20240229": 200000,
            "claude-3-haiku-20240307": 200000,
            "claude-3-5-sonnet-20241022": 200000,
            "claude-3-5-haiku-20241022": 200000,
        }

        # Output token limits by model
        self.model_output_limits = {
            "claude-3-opus-20240229": 4096,
            "claude-3-sonnet-20240229": 4096,
            "claude-3-haiku-20240307": 4096,
            "claude-3-5-sonnet-20241022": 8192,
            "claude-3-5-haiku-20241022": 8192,
        }

    async def initialize(self) -> bool:
        """Initialize Anthropic client

        Returns:
            True if initialization successful, False otherwise
        """
        try:
            if not self.api_key:
                logger.error("Anthropic API key not provided")
                self.enabled = False
                return False

            # Initialize client
            client_kwargs = {"api_key": self.api_key, "timeout": self.timeout}

            if self.base_url:
                client_kwargs["base_url"] = self.base_url

            self.client = AsyncAnthropic(**client_kwargs)

            # Test connection with a simple request
            try:
                response = await self.client.messages.create(
                    model=self.model,
                    max_tokens=10,
                    messages=[{"role": "user", "content": "Hello"}],
                    timeout=10,
                )

                logger.info(
                    "Anthropic provider initialized successfully",
                    model=self.model,
                    api_key_prefix=self.api_key[:8] + "...",
                )
                return True

            except anthropic.AuthenticationError:
                logger.error("Anthropic authentication failed - invalid API key")
                self.enabled = False
                return False

            except anthropic.RateLimitError:
                logger.warning(
                    "Anthropic rate limit hit during initialization, but provider available"
                )
                return True

            except Exception as e:
                logger.error("Anthropic initialization test failed", error=str(e))
                # Don't disable on test failure - might be temporary
                return True

        except Exception as e:
            logger.error("Failed to initialize Anthropic provider", error=str(e))
            self.enabled = False
            return False

    async def analyze(self, request: AIAnalysisRequest) -> AIAnalysisResponse:
        """Perform AI analysis using Anthropic Claude

        Args:
            request: Analysis request

        Returns:
            Analysis response

        Raises:
            Exception: If analysis fails
        """
        if not self.client:
            raise Exception("Anthropic client not initialized")

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

            # Prepare messages with system prompt
            system_prompt = self._get_system_prompt(request.analysis_type)
            messages = [{"role": "user", "content": prompt}]

            # Determine model parameters
            model = self.model
            max_tokens = request.max_tokens or self.max_tokens
            timeout = request.timeout or self.timeout

            # Adjust max_tokens based on model limits
            if model in self.model_output_limits:
                output_limit = self.model_output_limits[model]
                max_tokens = min(max_tokens, output_limit)

            # Make API request
            response = await self.client.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=system_prompt,
                messages=messages,
                timeout=timeout,
            )

            processing_time = time.time() - start_time

            # Extract response
            response_text = ""
            for content in response.content:
                if content.type == "text":
                    response_text += content.text

            tokens_used = (
                response.usage.input_tokens + response.usage.output_tokens
                if response.usage
                else None
            )

            # Calculate confidence based on response quality
            confidence_score = self._calculate_confidence(
                response_text, request.analysis_type
            )

            return AIAnalysisResponse(
                request_id=request.request_id,
                provider=AIProvider.ANTHROPIC,
                model=model,
                analysis_type=request.analysis_type,
                response_text=response_text,
                confidence_score=confidence_score,
                tokens_used=tokens_used,
                processing_time=processing_time,
                metadata={
                    "stop_reason": response.stop_reason,
                    "stop_sequence": response.stop_sequence,
                    "input_tokens": (
                        response.usage.input_tokens if response.usage else None
                    ),
                    "output_tokens": (
                        response.usage.output_tokens if response.usage else None
                    ),
                },
            )

        except anthropic.RateLimitError as e:
            self.health_metrics.rate_limit_hits += 1
            raise Exception(f"Anthropic rate limit exceeded: {str(e)}")

        except anthropic.AuthenticationError as e:
            self.enabled = False  # Disable provider on auth error
            raise Exception(f"Anthropic authentication error: {str(e)}")

        except anthropic.APITimeoutError as e:
            raise Exception(f"Anthropic request timeout: {str(e)}")

        except anthropic.APIError as e:
            raise Exception(f"Anthropic API error: {str(e)}")

        except Exception as e:
            raise Exception(f"Anthropic analysis failed: {str(e)}")

    async def health_check(self) -> bool:
        """Check Anthropic provider health

        Returns:
            True if provider is healthy, False otherwise
        """
        if not self.enabled or not self.client:
            return False

        try:
            # Simple health check with minimal token usage
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=1,
                messages=[{"role": "user", "content": "OK"}],
                timeout=10,
            )

            return len(response.content) > 0 and response.content[0].type == "text"

        except anthropic.AuthenticationError:
            self.enabled = False
            return False
        except anthropic.RateLimitError:
            # Rate limited but provider is technically healthy
            return True
        except Exception as e:
            logger.debug("Anthropic health check failed", error=str(e))
            return False

    async def get_available_models(self) -> List[str]:
        """Get list of available Anthropic models

        Returns:
            List of available model names
        """
        # Anthropic doesn't provide a models endpoint, return supported models
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
                "You are an expert cybersecurity analyst with deep knowledge of threat detection, "
                "attack patterns, and security incident response. Analyze security logs with precision, "
                "identify potential threats, classify attack types using MITRE ATT&CK framework, "
                "and provide actionable recommendations. Focus on accuracy and minimize false positives."
            ),
            "anomaly_detection": (
                "You are a specialized log analysis expert focused on anomaly detection and behavioral "
                "analysis. Your expertise lies in identifying deviations from normal patterns, unusual "
                "system behaviors, and statistical outliers in log data. Provide detailed explanations "
                "of why events are anomalous and assess their potential impact."
            ),
            "threat_classification": (
                "You are a threat intelligence analyst with expertise in threat categorization, "
                "malware analysis, and threat actor profiling. Classify threats according to industry "
                "standards (MITRE ATT&CK, Kill Chain), assess threat sophistication, and provide "
                "indicators of compromise (IOCs) with confidence ratings."
            ),
            "log_correlation": (
                "You are an expert in log correlation and incident reconstruction. Your specialty is "
                "analyzing relationships between disparate log events, identifying attack chains, "
                "and reconstructing complete incident timelines. Focus on causal relationships and "
                "temporal sequences to build comprehensive attack narratives."
            ),
            "pattern_analysis": (
                "You are a data analysis expert specializing in pattern recognition and trend analysis "
                "in security logs. Identify recurring behaviors, statistical patterns, frequency "
                "anomalies, and predictive indicators. Provide insights that can inform security "
                "policies and threat hunting strategies."
            ),
            "incident_summary": (
                "You are an experienced incident response analyst tasked with creating clear, "
                "comprehensive incident summaries. Synthesize complex security events into "
                "executive-level briefings that include impact assessment, timeline of events, "
                "root cause analysis, and prioritized remediation steps."
            ),
        }

        return prompts.get(
            (
                analysis_type.value
                if hasattr(analysis_type, "value")
                else str(analysis_type)
            ),
            "You are an expert log analysis specialist. Analyze the provided data thoroughly and provide detailed insights with clear reasoning.",
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
I need you to analyze the following log data for {request.analysis_type.value if hasattr(request.analysis_type, 'value') else str(request.analysis_type)}:

<log_data>
{data_str}
</log_data>

<context>
{json.dumps(request.context, indent=2) if request.context else 'No additional context provided'}
</context>

Please provide a comprehensive analysis that includes:

1. **Executive Summary**: Brief overview of findings
2. **Detailed Analysis**: In-depth examination of the log data
3. **Threat Assessment**: Risk level and potential impact (if applicable)
4. **Confidence Rating**: Your confidence in the analysis (0-100%)
5. **Key Indicators**: Important patterns, anomalies, or IOCs identified
6. **Recommendations**: Specific actions to take based on findings
7. **Additional Context**: Any relevant background information or related threats

Please structure your response clearly with headers and provide specific evidence from the log data to support your conclusions.
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

        confidence = 0.6  # Base confidence for Claude (generally more reliable)

        # Boost confidence for structured responses
        if any(
            keyword in response_text.lower()
            for keyword in [
                "summary",
                "analysis",
                "assessment",
                "recommendation",
                "confidence",
            ]
        ):
            confidence += 0.15

        # Boost for specific evidence citations
        if any(
            phrase in response_text.lower()
            for phrase in [
                "based on the log data",
                "evidence shows",
                "indicates that",
                "demonstrates",
            ]
        ):
            confidence += 0.1

        # Boost for security-specific terminology
        if analysis_type.value == "security_event" and any(
            keyword in response_text.lower()
            for keyword in [
                "mitre",
                "att&ck",
                "ioc",
                "ttp",
                "threat actor",
                "malicious activity",
            ]
        ):
            confidence += 0.1

        # Boost for confidence indicators in response
        if any(
            phrase in response_text.lower()
            for phrase in [
                "high confidence",
                "confident",
                "definitive",
                "clearly indicates",
            ]
        ):
            confidence += 0.05
        elif any(
            phrase in response_text.lower()
            for phrase in ["medium confidence", "likely", "probably", "suggests"]
        ):
            # Neutral adjustment
            pass

        # Penalize for uncertainty indicators
        if any(
            phrase in response_text.lower()
            for phrase in [
                "low confidence",
                "unclear",
                "uncertain",
                "cannot determine",
                "insufficient",
            ]
        ):
            confidence -= 0.15

        # Boost for detailed technical analysis
        if len(response_text) > 500 and any(
            phrase in response_text.lower()
            for phrase in [
                "technical analysis",
                "forensic",
                "investigation",
                "methodology",
            ]
        ):
            confidence += 0.05

        # Ensure confidence is in valid range
        return max(0.0, min(1.0, confidence))
