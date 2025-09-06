"""
SkausWatch AAA Monitor Service - AI Integration

Comprehensive AI-powered analysis integration supporting multiple providers including
OpenAI GPT, Anthropic Claude, and local Ollama models with advanced features:
- Multi-provider abstraction with failover and load balancing
- Intelligent prompt engineering with pre-built templates
- Response processing and caching for cost optimization
- Real-time and batch analysis capabilities
- Confidence scoring and consensus building
"""

from .ai_provider import (
    BaseAIProvider, AIProviderManager, AIAnalysisRequest, 
    AIAnalysisResponse, AIAnalysisType, AIProviderStatus
)
from .openai_client import OpenAIProvider
from .anthropic_client import AnthropicProvider
from .ollama_client import OllamaProvider
from .prompt_templates import PromptTemplateManager, PromptCategory, PromptComplexity
from .analysis_engine import AIAnalysisEngine, AnalysisResult
from .response_processor import ResponseProcessor, ProcessedResponse

__all__ = [
    # Core AI provider system
    'BaseAIProvider',
    'AIProviderManager', 
    'AIAnalysisRequest',
    'AIAnalysisResponse',
    'AIAnalysisType',
    'AIProviderStatus',
    
    # Individual providers
    'OpenAIProvider',
    'AnthropicProvider',
    'OllamaProvider',
    
    # Prompt engineering
    'PromptTemplateManager',
    'PromptCategory',
    'PromptComplexity',
    
    # Analysis engine
    'AIAnalysisEngine',
    'AnalysisResult',
    
    # Response processing
    'ResponseProcessor',
    'ProcessedResponse'
]

# Version information
__version__ = "1.0.0"
__author__ = "SkausWatch Team"