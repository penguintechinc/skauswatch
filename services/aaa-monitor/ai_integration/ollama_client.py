"""
SkausWatch AAA Monitor Service - Ollama Client

Ollama integration for local AI models in log analysis.
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
import structlog

import aiohttp

from .ai_provider import BaseAIProvider, AIAnalysisRequest, AIAnalysisResponse, AIProviderStatus
from ..models import AIProvider

logger = structlog.get_logger(__name__)


class OllamaProvider(BaseAIProvider):
    """Ollama local AI provider implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Ollama provider
        
        Args:
            config: Ollama configuration
        """
        super().__init__(config, AIProvider.OLLAMA)
        
        self.base_url = config.get('base_url', 'http://localhost:11434')
        self.model = config.get('model', 'llama2')
        self.timeout = config.get('timeout', 60)
        self.stream = config.get('stream', False)
        self.temperature = config.get('temperature', 0.1)
        self.num_ctx = config.get('num_ctx', 4096)  # Context window
        
        # HTTP session for connections
        self.session = None
        
        # Available models cache
        self.available_models = []
        self.models_cache_time = None
        self.models_cache_ttl = 300  # 5 minutes
        
        # Model capabilities (will be populated during initialization)
        self.model_info = {}

    async def initialize(self) -> bool:
        """Initialize Ollama client
        
        Returns:
            True if initialization successful, False otherwise
        """
        try:
            # Create HTTP session
            connector = aiohttp.TCPConnector(
                limit=10,
                limit_per_host=5,
                keepalive_timeout=30
            )
            
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            )
            
            # Test connection and get model info
            try:
                models = await self._get_models()
                if not models:
                    logger.warning("No models available in Ollama")
                    return False
                
                # Check if configured model exists
                model_names = [model['name'] for model in models]
                if self.model not in model_names:
                    logger.warning("Configured model not available", 
                                 model=self.model, 
                                 available=model_names)
                    # Use the first available model
                    if model_names:
                        self.model = model_names[0]
                        logger.info("Using first available model", model=self.model)
                    else:
                        return False
                
                # Get model info
                try:
                    model_info = await self._get_model_info(self.model)
                    self.model_info[self.model] = model_info
                except Exception as e:
                    logger.warning("Failed to get model info", model=self.model, error=str(e))
                
                # Test with simple generation
                test_request = {
                    'model': self.model,
                    'prompt': 'Hello',
                    'stream': False,
                    'options': {
                        'num_predict': 1,
                        'temperature': 0.1
                    }
                }
                
                async with self.session.post(
                    f"{self.base_url}/api/generate",
                    json=test_request,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        await response.json()
                        logger.info("Ollama provider initialized successfully", 
                                  model=self.model, 
                                  base_url=self.base_url)
                        return True
                    else:
                        logger.error("Ollama test request failed", status=response.status)
                        return False
                        
            except aiohttp.ClientError as e:
                logger.error("Failed to connect to Ollama", url=self.base_url, error=str(e))
                return False
                
        except Exception as e:
            logger.error("Failed to initialize Ollama provider", error=str(e))
            return False

    async def analyze(self, request: AIAnalysisRequest) -> AIAnalysisResponse:
        """Perform AI analysis using Ollama
        
        Args:
            request: Analysis request
            
        Returns:
            Analysis response
            
        Raises:
            Exception: If analysis fails
        """
        if not self.session:
            raise Exception("Ollama client not initialized")
        
        start_time = time.time()
        
        try:
            # Prepare the prompt
            if request.custom_prompt:
                full_prompt = request.custom_prompt
            elif request.prompt_template:
                # Template will be formatted elsewhere with request.data
                full_prompt = request.prompt_template
            else:
                # Build prompt with system instructions and user request
                system_prompt = self._get_system_prompt(request.analysis_type)
                user_prompt = self._build_default_prompt(request)
                full_prompt = f"{system_prompt}\n\n{user_prompt}"
            
            # Determine model parameters
            model = self.model
            temperature = request.temperature if request.temperature is not None else self.temperature
            timeout = request.timeout or self.timeout
            
            # Calculate max_tokens based on context window
            max_tokens = request.max_tokens or 1000
            if self.num_ctx:
                # Estimate prompt tokens (rough approximation: 1 token ~= 4 characters)
                prompt_tokens = len(full_prompt) // 4
                available_tokens = self.num_ctx - prompt_tokens - 100  # Buffer
                max_tokens = min(max_tokens, max(100, available_tokens))
            
            # Prepare request
            ollama_request = {
                'model': model,
                'prompt': full_prompt,
                'stream': False,
                'options': {
                    'temperature': temperature,
                    'num_predict': max_tokens,
                    'num_ctx': self.num_ctx,
                    'top_p': 0.9,
                    'repeat_penalty': 1.1
                }
            }
            
            # Make API request
            async with self.session.post(
                f"{self.base_url}/api/generate",
                json=ollama_request,
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"Ollama API error {response.status}: {error_text}")
                
                result = await response.json()
            
            processing_time = time.time() - start_time
            
            # Extract response
            response_text = result.get('response', '')
            if not response_text:
                raise Exception("Empty response from Ollama")
            
            # Extract token information if available
            tokens_used = None
            if 'prompt_eval_count' in result and 'eval_count' in result:
                tokens_used = result['prompt_eval_count'] + result['eval_count']
            
            # Calculate confidence based on response quality
            confidence_score = self._calculate_confidence(response_text, request.analysis_type)
            
            return AIAnalysisResponse(
                request_id=request.request_id,
                provider=AIProvider.OLLAMA,
                model=model,
                analysis_type=request.analysis_type,
                response_text=response_text,
                confidence_score=confidence_score,
                tokens_used=tokens_used,
                processing_time=processing_time,
                metadata={
                    'done': result.get('done', False),
                    'context': result.get('context'),
                    'prompt_eval_count': result.get('prompt_eval_count'),
                    'prompt_eval_duration': result.get('prompt_eval_duration'),
                    'eval_count': result.get('eval_count'),
                    'eval_duration': result.get('eval_duration'),
                    'total_duration': result.get('total_duration')
                }
            )
            
        except aiohttp.ClientError as e:
            raise Exception(f"Ollama connection error: {str(e)}")
        except asyncio.TimeoutError:
            raise Exception("Ollama request timeout")
        except Exception as e:
            raise Exception(f"Ollama analysis failed: {str(e)}")

    async def health_check(self) -> bool:
        """Check Ollama provider health
        
        Returns:
            True if provider is healthy, False otherwise
        """
        if not self.session:
            return False
        
        try:
            # Check if Ollama is running
            async with self.session.get(
                f"{self.base_url}/api/tags",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status == 200:
                    # Also check if our model is available
                    models_data = await response.json()
                    models = models_data.get('models', [])
                    model_names = [model['name'] for model in models]
                    return self.model in model_names
                else:
                    return False
                    
        except Exception as e:
            logger.debug("Ollama health check failed", error=str(e))
            return False

    async def get_available_models(self) -> List[str]:
        """Get list of available Ollama models
        
        Returns:
            List of available model names
        """
        try:
            models = await self._get_models()
            return [model['name'] for model in models]
        except Exception as e:
            logger.warning("Failed to get Ollama models", error=str(e))
            return []

    async def _get_models(self) -> List[Dict[str, Any]]:
        """Get available models from Ollama
        
        Returns:
            List of model information
        """
        if not self.session:
            return []
        
        # Check cache
        current_time = time.time()
        if (self.models_cache_time and 
            (current_time - self.models_cache_time) < self.models_cache_ttl and 
            self.available_models):
            return self.available_models
        
        try:
            async with self.session.get(f"{self.base_url}/api/tags") as response:
                if response.status == 200:
                    data = await response.json()
                    models = data.get('models', [])
                    self.available_models = models
                    self.models_cache_time = current_time
                    return models
                else:
                    logger.warning("Failed to get models", status=response.status)
                    return []
                    
        except Exception as e:
            logger.warning("Error getting models from Ollama", error=str(e))
            return []

    async def _get_model_info(self, model_name: str) -> Dict[str, Any]:
        """Get detailed information about a specific model
        
        Args:
            model_name: Name of the model
            
        Returns:
            Model information
        """
        if not self.session:
            return {}
        
        try:
            async with self.session.post(
                f"{self.base_url}/api/show",
                json={'name': model_name}
            ) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logger.warning("Failed to get model info", 
                                 model=model_name, 
                                 status=response.status)
                    return {}
                    
        except Exception as e:
            logger.warning("Error getting model info", model=model_name, error=str(e))
            return {}

    def _get_system_prompt(self, analysis_type) -> str:
        """Get system prompt based on analysis type
        
        Args:
            analysis_type: Type of analysis
            
        Returns:
            System prompt
        """
        prompts = {
            'security_event': (
                "You are a cybersecurity expert specializing in log analysis and threat detection. "
                "Your task is to analyze security logs and identify potential threats, attack patterns, "
                "and security violations. Provide clear, actionable analysis with specific evidence "
                "from the log data. Focus on accuracy and practical recommendations."
            ),
            'anomaly_detection': (
                "You are a log analysis specialist focused on anomaly detection. Your expertise is "
                "in identifying unusual patterns, deviations from normal behavior, and outliers in "
                "system logs. Explain why events are anomalous and assess their significance for "
                "security and operational purposes."
            ),
            'threat_classification': (
                "You are a threat intelligence analyst with expertise in classifying and categorizing "
                "security threats. Use frameworks like MITRE ATT&CK to classify threats, assess their "
                "sophistication, and provide relevant indicators of compromise (IOCs)."
            ),
            'log_correlation': (
                "You are an expert in log correlation and incident reconstruction. Analyze relationships "
                "between different log events, identify patterns across multiple sources, and reconstruct "
                "attack sequences or incident timelines with clear causal relationships."
            ),
            'pattern_analysis': (
                "You are a pattern analysis expert specializing in identifying recurring behaviors, "
                "trends, and patterns in log data. Focus on statistical significance, frequency analysis, "
                "and predictive insights that can inform security strategies."
            ),
            'incident_summary': (
                "You are an incident response analyst tasked with creating comprehensive incident summaries. "
                "Synthesize security events into clear reports with timelines, impact assessments, "
                "root cause analysis, and remediation recommendations."
            )
        }
        
        return prompts.get(
            analysis_type.value if hasattr(analysis_type, 'value') else str(analysis_type),
            "You are a log analysis expert. Analyze the provided data and give detailed, accurate insights."
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
Please analyze the following log data for {request.analysis_type.value if hasattr(request.analysis_type, 'value') else str(request.analysis_type)}:

Log Data:
{data_str}

Context Information:
{json.dumps(request.context, indent=2) if request.context else 'No additional context provided'}

Please provide a detailed analysis including:

1. Summary: Brief overview of key findings
2. Analysis: Detailed examination of the log data
3. Risk Assessment: Potential security implications (if applicable)
4. Confidence Level: Your confidence in the analysis (0-100%)
5. Key Indicators: Important patterns or anomalies identified
6. Recommendations: Specific actions based on the analysis
7. Supporting Evidence: Specific log entries that support your conclusions

Please be thorough but concise in your response.
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
        
        # Start with lower base confidence for local models
        confidence = 0.4
        
        # Boost confidence for structured responses
        if any(keyword in response_text.lower() for keyword in 
               ['summary:', 'analysis:', 'assessment:', 'recommendation']):
            confidence += 0.2
        
        # Boost for specific evidence references
        if any(phrase in response_text.lower() for phrase in 
               ['log shows', 'evidence indicates', 'data reveals', 'logs contain']):
            confidence += 0.15
        
        # Boost for detailed analysis
        if len(response_text) > 300:
            confidence += 0.1
        
        # Boost for security-specific analysis
        if analysis_type.value == 'security_event' and any(
            keyword in response_text.lower() for keyword in 
            ['attack', 'threat', 'malicious', 'suspicious', 'vulnerability']
        ):
            confidence += 0.1
        
        # Boost for confidence indicators
        if any(phrase in response_text.lower() for phrase in 
               ['high confidence', 'confident', 'certain']):
            confidence += 0.05
        elif any(phrase in response_text.lower() for phrase in 
                 ['moderate confidence', 'likely', 'probable']):
            # Neutral
            pass
        
        # Penalize for uncertainty
        if any(phrase in response_text.lower() for phrase in 
               ['uncertain', 'unclear', 'cannot determine', 'insufficient']):
            confidence -= 0.2
        
        # Penalize for very short responses
        if len(response_text) < 100:
            confidence -= 0.1
        
        # Ensure confidence is in valid range
        return max(0.0, min(1.0, confidence))

    async def shutdown(self):
        """Shutdown Ollama provider"""
        if self.session:
            await self.session.close()
            self.session = None