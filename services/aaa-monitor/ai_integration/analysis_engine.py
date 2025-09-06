"""
SkausWatch AAA Monitor Service - AI Analysis Engine

Real-time log event analysis, batch processing, confidence scoring,
and result aggregation with consensus building.
"""

import asyncio
import hashlib
import json
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, AsyncGenerator, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import structlog

from .ai_provider import (
    AIProviderManager, AIAnalysisRequest, AIAnalysisResponse, 
    AIAnalysisType, BaseAIProvider
)
from .prompt_templates import PromptTemplateManager, PromptComplexity
from .response_processor import ResponseProcessor
from ..models import BaseEvent, Severity, ThreatLevel, AIProvider

logger = structlog.get_logger(__name__)


class AnalysisMode(str, Enum):
    """Analysis processing modes"""
    REAL_TIME = "real_time"
    BATCH = "batch"
    PRIORITY = "priority"
    SCHEDULED = "scheduled"


class ConsensusStrategy(str, Enum):
    """Consensus building strategies"""
    MAJORITY = "majority"
    WEIGHTED = "weighted"
    HIGHEST_CONFIDENCE = "highest_confidence"
    PROVIDER_PRIORITY = "provider_priority"


@dataclass
class AnalysisJob:
    """Analysis job definition"""
    job_id: str
    mode: AnalysisMode
    analysis_type: AIAnalysisType
    events: List[BaseEvent]
    context: Dict[str, Any] = field(default_factory=dict)
    priority: int = 1  # 1=low, 5=high
    template_name: Optional[str] = None
    custom_prompt: Optional[str] = None
    providers: Optional[List[AIProvider]] = None  # Specific providers to use
    consensus_required: bool = False
    timeout: Optional[int] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: str = "pending"  # pending, running, completed, failed


@dataclass
class AnalysisResult:
    """Analysis result with consensus"""
    job_id: str
    analysis_type: AIAnalysisType
    events_analyzed: int
    responses: List[AIAnalysisResponse]
    consensus_response: Optional[AIAnalysisResponse] = None
    confidence_score: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    recommendations: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    processing_time: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class BatchAnalysisConfig:
    """Batch analysis configuration"""
    batch_size: int = 100
    processing_interval: int = 30  # seconds
    max_batch_age: int = 300  # seconds
    auto_flush_threshold: float = 0.8  # flush at 80% capacity


class AIAnalysisEngine:
    """AI-powered analysis engine for log events"""
    
    def __init__(self, 
                 config: Dict[str, Any],
                 provider_manager: AIProviderManager,
                 redis_client=None):
        """Initialize AI analysis engine
        
        Args:
            config: Analysis engine configuration
            provider_manager: AI provider manager
            redis_client: Optional Redis client for caching
        """
        self.config = config
        self.provider_manager = provider_manager
        self.redis_client = redis_client
        
        # Initialize components
        self.prompt_manager = PromptTemplateManager()
        self.response_processor = ResponseProcessor(redis_client)
        
        # Analysis queues
        self.real_time_queue = asyncio.PriorityQueue()
        self.batch_queue = deque()
        self.priority_queue = asyncio.PriorityQueue()
        
        # Job tracking
        self.active_jobs: Dict[str, AnalysisJob] = {}
        self.completed_jobs: Dict[str, AnalysisResult] = {}
        self.job_history = deque(maxlen=1000)
        
        # Batch processing
        self.batch_config = BatchAnalysisConfig(**config.get('batch_processing', {}))
        self.batch_buffer: Dict[AIAnalysisType, List[BaseEvent]] = defaultdict(list)
        self.batch_timestamps: Dict[AIAnalysisType, datetime] = {}
        
        # Processing workers
        self.workers: List[asyncio.Task] = []
        self.batch_processor_task: Optional[asyncio.Task] = None
        self.running = False
        
        # Statistics
        self.stats = {
            'total_analyses': 0,
            'real_time_analyses': 0,
            'batch_analyses': 0,
            'successful_analyses': 0,
            'failed_analyses': 0,
            'average_processing_time': 0.0,
            'by_analysis_type': defaultdict(int),
            'by_provider': defaultdict(int)
        }
        
        # Configuration
        self.ai_threshold = config.get('ai_analysis_threshold', 10)
        self.consensus_strategy = ConsensusStrategy(config.get('consensus_strategy', 'weighted'))
        self.default_timeout = config.get('default_timeout', 60)
        self.max_concurrent_analyses = config.get('max_concurrent_analyses', 5)
        self.enable_consensus = config.get('enable_consensus', True)
        
        # Semaphore for concurrency control
        self.analysis_semaphore = asyncio.Semaphore(self.max_concurrent_analyses)

    async def initialize(self):
        """Initialize the analysis engine"""
        try:
            # Initialize response processor
            await self.response_processor.initialize()
            
            # Start worker tasks
            await self._start_workers()
            
            logger.info("AI analysis engine initialized successfully")
            
        except Exception as e:
            logger.error("Failed to initialize AI analysis engine", error=str(e))
            raise

    async def analyze_real_time(self,
                               events: List[BaseEvent],
                               analysis_type: AIAnalysisType,
                               priority: int = 1,
                               context: Optional[Dict[str, Any]] = None,
                               template_name: Optional[str] = None) -> str:
        """Submit events for real-time AI analysis
        
        Args:
            events: Events to analyze
            analysis_type: Type of analysis to perform
            priority: Analysis priority (1-5, 5=highest)
            context: Additional context for analysis
            template_name: Specific template to use
            
        Returns:
            Job ID for tracking analysis
        """
        job_id = str(uuid.uuid4())
        
        job = AnalysisJob(
            job_id=job_id,
            mode=AnalysisMode.REAL_TIME,
            analysis_type=analysis_type,
            events=events,
            context=context or {},
            priority=priority,
            template_name=template_name
        )
        
        self.active_jobs[job_id] = job
        
        # Add to appropriate queue based on priority
        if priority >= 4:
            await self.priority_queue.put((10 - priority, job))
        else:
            await self.real_time_queue.put((10 - priority, job))
        
        logger.info("Real-time analysis job queued", 
                   job_id=job_id, 
                   events=len(events),
                   analysis_type=analysis_type.value)
        
        return job_id

    async def analyze_batch(self,
                           events: List[BaseEvent],
                           analysis_type: AIAnalysisType,
                           force_processing: bool = False) -> Optional[str]:
        """Add events to batch processing queue
        
        Args:
            events: Events to add to batch
            analysis_type: Type of analysis
            force_processing: Force immediate batch processing
            
        Returns:
            Job ID if batch was processed, None if added to buffer
        """
        self.batch_buffer[analysis_type].extend(events)
        
        # Update timestamp for this analysis type
        if analysis_type not in self.batch_timestamps:
            self.batch_timestamps[analysis_type] = datetime.utcnow()
        
        # Check if we should process batch
        should_process = (
            force_processing or
            len(self.batch_buffer[analysis_type]) >= self.batch_config.batch_size or
            (datetime.utcnow() - self.batch_timestamps[analysis_type]).total_seconds() 
            >= self.batch_config.max_batch_age
        )
        
        if should_process:
            return await self._process_batch(analysis_type)
        
        return None

    async def get_analysis_result(self, job_id: str) -> Optional[AnalysisResult]:
        """Get analysis result by job ID
        
        Args:
            job_id: Job identifier
            
        Returns:
            Analysis result if completed, None otherwise
        """
        return self.completed_jobs.get(job_id)

    async def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job status information
        
        Args:
            job_id: Job identifier
            
        Returns:
            Job status information
        """
        if job_id in self.active_jobs:
            job = self.active_jobs[job_id]
            return {
                'job_id': job_id,
                'status': job.status,
                'mode': job.mode.value,
                'analysis_type': job.analysis_type.value,
                'events_count': len(job.events),
                'created_at': job.created_at.isoformat(),
                'started_at': job.started_at.isoformat() if job.started_at else None,
                'completed_at': job.completed_at.isoformat() if job.completed_at else None
            }
        
        if job_id in self.completed_jobs:
            result = self.completed_jobs[job_id]
            return {
                'job_id': job_id,
                'status': 'completed',
                'analysis_type': result.analysis_type.value,
                'events_analyzed': result.events_analyzed,
                'confidence_score': result.confidence_score,
                'threat_level': result.threat_level.value,
                'processing_time': result.processing_time,
                'timestamp': result.timestamp.isoformat()
            }
        
        return None

    async def _start_workers(self):
        """Start processing workers"""
        self.running = True
        
        # Real-time processing workers
        for i in range(2):
            worker = asyncio.create_task(self._real_time_worker(f"rt-{i}"))
            self.workers.append(worker)
        
        # Priority processing worker
        worker = asyncio.create_task(self._priority_worker())
        self.workers.append(worker)
        
        # Batch processing worker
        self.batch_processor_task = asyncio.create_task(self._batch_processor())
        
        logger.info("AI analysis workers started")

    async def _real_time_worker(self, worker_id: str):
        """Real-time analysis worker"""
        logger.info("Real-time worker started", worker_id=worker_id)
        
        while self.running:
            try:
                # Get job from queue with timeout
                try:
                    priority, job = await asyncio.wait_for(
                        self.real_time_queue.get(), 
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                # Process the job
                await self._process_analysis_job(job, worker_id)
                
            except Exception as e:
                logger.error("Real-time worker error", worker_id=worker_id, error=str(e))

    async def _priority_worker(self):
        """Priority analysis worker"""
        logger.info("Priority worker started")
        
        while self.running:
            try:
                # Get job from priority queue
                try:
                    priority, job = await asyncio.wait_for(
                        self.priority_queue.get(), 
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                # Process the job with higher priority
                await self._process_analysis_job(job, "priority")
                
            except Exception as e:
                logger.error("Priority worker error", error=str(e))

    async def _batch_processor(self):
        """Batch processing worker"""
        logger.info("Batch processor started")
        
        while self.running:
            try:
                await asyncio.sleep(self.batch_config.processing_interval)
                
                # Check each analysis type for batch processing
                for analysis_type in list(self.batch_buffer.keys()):
                    if not self.batch_buffer[analysis_type]:
                        continue
                    
                    # Check if batch should be processed
                    batch_age = (datetime.utcnow() - self.batch_timestamps[analysis_type]).total_seconds()
                    batch_size = len(self.batch_buffer[analysis_type])
                    
                    should_process = (
                        batch_size >= self.batch_config.batch_size or
                        batch_age >= self.batch_config.max_batch_age or
                        batch_size >= (self.batch_config.batch_size * self.batch_config.auto_flush_threshold)
                    )
                    
                    if should_process:
                        await self._process_batch(analysis_type)
                
            except Exception as e:
                logger.error("Batch processor error", error=str(e))

    async def _process_batch(self, analysis_type: AIAnalysisType) -> str:
        """Process a batch of events
        
        Args:
            analysis_type: Type of analysis
            
        Returns:
            Job ID of the batch processing job
        """
        if not self.batch_buffer[analysis_type]:
            return None
        
        # Extract events from buffer
        events = self.batch_buffer[analysis_type].copy()
        self.batch_buffer[analysis_type].clear()
        
        # Reset timestamp
        self.batch_timestamps[analysis_type] = datetime.utcnow()
        
        # Create batch job
        job_id = str(uuid.uuid4())
        job = AnalysisJob(
            job_id=job_id,
            mode=AnalysisMode.BATCH,
            analysis_type=analysis_type,
            events=events,
            context={'batch_size': len(events)},
            priority=2  # Medium priority for batch jobs
        )
        
        self.active_jobs[job_id] = job
        
        # Process immediately in background
        asyncio.create_task(self._process_analysis_job(job, "batch"))
        
        logger.info("Batch processing job created", 
                   job_id=job_id, 
                   events=len(events),
                   analysis_type=analysis_type.value)
        
        return job_id

    async def _process_analysis_job(self, job: AnalysisJob, worker_id: str):
        """Process an analysis job
        
        Args:
            job: Analysis job to process
            worker_id: Worker identifier
        """
        async with self.analysis_semaphore:
            job.status = "running"
            job.started_at = datetime.utcnow()
            start_time = time.time()
            
            try:
                logger.info("Processing analysis job", 
                           job_id=job.job_id, 
                           worker_id=worker_id,
                           events=len(job.events))
                
                # Prepare analysis request
                request = await self._prepare_analysis_request(job)
                
                # Get AI analysis
                if self.enable_consensus and len(self.provider_manager.providers) > 1:
                    responses = await self._get_consensus_analysis(request)
                else:
                    response = await self.provider_manager.analyze(request)
                    responses = [response] if response else []
                
                if not responses:
                    raise Exception("No AI providers returned valid responses")
                
                # Process responses
                result = await self._build_analysis_result(job, responses)
                result.processing_time = time.time() - start_time
                
                # Store result
                self.completed_jobs[job.job_id] = result
                self.job_history.append(job.job_id)
                
                # Update statistics
                self._update_stats(job, result, True)
                
                job.status = "completed"
                job.completed_at = datetime.utcnow()
                
                logger.info("Analysis job completed", 
                           job_id=job.job_id,
                           processing_time=result.processing_time,
                           confidence=result.confidence_score,
                           threat_level=result.threat_level.value)
                
            except Exception as e:
                logger.error("Analysis job failed", 
                           job_id=job.job_id, 
                           error=str(e))
                
                job.status = "failed"
                job.completed_at = datetime.utcnow()
                
                # Store empty result for failed job
                result = AnalysisResult(
                    job_id=job.job_id,
                    analysis_type=job.analysis_type,
                    events_analyzed=len(job.events),
                    responses=[],
                    processing_time=time.time() - start_time,
                    metadata={'error': str(e)}
                )
                self.completed_jobs[job.job_id] = result
                
                self._update_stats(job, result, False)
            
            finally:
                # Clean up active job
                if job.job_id in self.active_jobs:
                    del self.active_jobs[job.job_id]

    async def _prepare_analysis_request(self, job: AnalysisJob) -> AIAnalysisRequest:
        """Prepare AI analysis request from job
        
        Args:
            job: Analysis job
            
        Returns:
            AI analysis request
        """
        # Prepare event data
        events_data = []
        for event in job.events:
            event_dict = {
                'id': event.id,
                'timestamp': event.timestamp.isoformat(),
                'source': event.source.value,
                'event_type': event.event_type.value,
                'severity': event.severity.value,
                'message': event.message,
                'raw_data': event.raw_data,
                'processed_data': event.processed_data,
                'tags': event.tags
            }
            events_data.append(event_dict)
        
        # Prepare context
        context = job.context.copy()
        context.update({
            'job_id': job.job_id,
            'mode': job.mode.value,
            'event_count': len(job.events),
            'processing_timestamp': datetime.utcnow().isoformat()
        })
        
        # Determine prompt
        prompt = None
        if job.template_name:
            template_data = {
                'log_data': events_data,
                'context': context
            }
            prompt = self.prompt_manager.format_prompt(job.template_name, template_data)
        elif job.custom_prompt:
            prompt = job.custom_prompt
        
        return AIAnalysisRequest(
            request_id=job.job_id,
            analysis_type=job.analysis_type,
            data={'events': events_data},
            prompt_template=prompt,
            context=context,
            priority=job.priority,
            timeout=job.timeout or self.default_timeout
        )

    async def _get_consensus_analysis(self, request: AIAnalysisRequest) -> List[AIAnalysisResponse]:
        """Get consensus analysis from multiple providers
        
        Args:
            request: Analysis request
            
        Returns:
            List of AI responses from different providers
        """
        responses = []
        
        # Get responses from multiple providers
        providers_to_use = min(3, len(self.provider_manager.providers))  # Use up to 3 providers
        
        tasks = []
        for provider_name in list(self.provider_manager.providers.keys())[:providers_to_use]:
            task = asyncio.create_task(self._get_provider_response(provider_name, request))
            tasks.append(task)
        
        # Wait for all responses
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, AIAnalysisResponse):
                responses.append(result)
            elif not isinstance(result, Exception):
                logger.warning("Unexpected response type", type=type(result))
        
        return responses

    async def _get_provider_response(self, provider_name: AIProvider, request: AIAnalysisRequest) -> Optional[AIAnalysisResponse]:
        """Get response from specific provider
        
        Args:
            provider_name: AI provider name
            request: Analysis request
            
        Returns:
            AI response or None if failed
        """
        try:
            provider = self.provider_manager.providers[provider_name]
            
            # Skip if provider is unhealthy
            if provider.health_metrics.status.value == 'unhealthy':
                return None
            
            return await provider.analyze(request)
            
        except Exception as e:
            logger.warning("Provider response failed", 
                         provider=provider_name.value, 
                         error=str(e))
            return None

    async def _build_analysis_result(self, 
                                   job: AnalysisJob, 
                                   responses: List[AIAnalysisResponse]) -> AnalysisResult:
        """Build analysis result from AI responses
        
        Args:
            job: Analysis job
            responses: AI responses
            
        Returns:
            Consolidated analysis result
        """
        if not responses:
            return AnalysisResult(
                job_id=job.job_id,
                analysis_type=job.analysis_type,
                events_analyzed=len(job.events),
                responses=[]
            )
        
        # Process responses
        processed_responses = []
        for response in responses:
            processed = await self.response_processor.process_response(response)
            processed_responses.append(processed)
        
        # Build consensus
        consensus_response = await self._build_consensus(processed_responses)
        
        # Extract key information
        confidence_score = self._calculate_consensus_confidence(processed_responses)
        threat_level = self._determine_threat_level(processed_responses)
        recommendations = self._extract_recommendations(processed_responses)
        iocs = self._extract_iocs(processed_responses)
        
        return AnalysisResult(
            job_id=job.job_id,
            analysis_type=job.analysis_type,
            events_analyzed=len(job.events),
            responses=processed_responses,
            consensus_response=consensus_response,
            confidence_score=confidence_score,
            threat_level=threat_level,
            recommendations=recommendations,
            iocs=iocs,
            metadata={
                'providers_used': [r.provider.value for r in responses],
                'consensus_strategy': self.consensus_strategy.value
            }
        )

    async def _build_consensus(self, responses: List[AIAnalysisResponse]) -> Optional[AIAnalysisResponse]:
        """Build consensus response from multiple AI responses
        
        Args:
            responses: List of AI responses
            
        Returns:
            Consensus response
        """
        if not responses:
            return None
        
        if len(responses) == 1:
            return responses[0]
        
        # Apply consensus strategy
        if self.consensus_strategy == ConsensusStrategy.HIGHEST_CONFIDENCE:
            return max(responses, key=lambda r: r.confidence_score or 0)
        
        elif self.consensus_strategy == ConsensusStrategy.WEIGHTED:
            # Weight by confidence and provider reliability
            weighted_responses = []
            for response in responses:
                provider = self.provider_manager.providers.get(response.provider)
                reliability = 1.0 - (provider.health_metrics.error_rate if provider else 0.5)
                weight = (response.confidence_score or 0.5) * reliability
                weighted_responses.append((weight, response))
            
            return max(weighted_responses, key=lambda x: x[0])[1]
        
        else:  # MAJORITY or default
            return responses[len(responses) // 2]  # Return median response

    def _calculate_consensus_confidence(self, responses: List[AIAnalysisResponse]) -> float:
        """Calculate consensus confidence from multiple responses
        
        Args:
            responses: AI responses
            
        Returns:
            Consensus confidence score
        """
        if not responses:
            return 0.0
        
        confidences = [r.confidence_score or 0.5 for r in responses]
        
        # Calculate weighted average with consensus penalty/bonus
        base_confidence = sum(confidences) / len(confidences)
        
        # Bonus for agreement (low variance)
        if len(confidences) > 1:
            variance = sum((c - base_confidence) ** 2 for c in confidences) / len(confidences)
            agreement_bonus = max(0, (0.1 - variance) * 2)  # Up to 0.2 bonus for high agreement
            base_confidence += agreement_bonus
        
        return min(1.0, base_confidence)

    def _determine_threat_level(self, responses: List[AIAnalysisResponse]) -> ThreatLevel:
        """Determine threat level from responses
        
        Args:
            responses: AI responses
            
        Returns:
            Consensus threat level
        """
        if not responses:
            return ThreatLevel.UNKNOWN
        
        # Extract threat levels from response text
        threat_keywords = {
            ThreatLevel.CRITICAL: ['critical', 'severe', 'immediate', 'emergency'],
            ThreatLevel.HIGH: ['high', 'urgent', 'serious', 'dangerous'],
            ThreatLevel.MEDIUM: ['medium', 'moderate', 'elevated', 'concerning'],
            ThreatLevel.LOW: ['low', 'minor', 'minimal', 'slight']
        }
        
        threat_votes = defaultdict(int)
        
        for response in responses:
            text = response.response_text.lower()
            for level, keywords in threat_keywords.items():
                if any(keyword in text for keyword in keywords):
                    # Weight by confidence
                    weight = response.confidence_score or 0.5
                    threat_votes[level] += weight
        
        if not threat_votes:
            return ThreatLevel.UNKNOWN
        
        return max(threat_votes.keys(), key=lambda k: threat_votes[k])

    def _extract_recommendations(self, responses: List[AIAnalysisResponse]) -> List[str]:
        """Extract recommendations from responses
        
        Args:
            responses: AI responses
            
        Returns:
            List of unique recommendations
        """
        recommendations = set()
        
        for response in responses:
            text = response.response_text
            
            # Extract recommendations using patterns
            recommendation_patterns = [
                r'recommend(?:ation)?s?:?\s*(.+?)(?:\n\n|\Z)',
                r'(?:should|must|need to):\s*(.+?)(?:\n|\Z)',
                r'action(?:s)?:?\s*(.+?)(?:\n\n|\Z)'
            ]
            
            import re
            for pattern in recommendation_patterns:
                matches = re.finditer(pattern, text, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    rec_text = match.group(1).strip()
                    if len(rec_text) > 10:  # Filter out very short matches
                        recommendations.add(rec_text[:200])  # Limit length
        
        return list(recommendations)[:10]  # Limit to 10 recommendations

    def _extract_iocs(self, responses: List[AIAnalysisResponse]) -> List[str]:
        """Extract IOCs from responses
        
        Args:
            responses: AI responses
            
        Returns:
            List of unique IOCs
        """
        iocs = set()
        
        for response in responses:
            text = response.response_text
            
            # Extract IOCs using patterns
            import re
            patterns = {
                'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                'domain': r'\b[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b',
                'hash': r'\b[a-fA-F0-9]{32,64}\b',
                'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            }
            
            for ioc_type, pattern in patterns.items():
                matches = re.findall(pattern, text)
                for match in matches:
                    iocs.add(match)
        
        return list(iocs)[:20]  # Limit to 20 IOCs

    def _update_stats(self, job: AnalysisJob, result: AnalysisResult, success: bool):
        """Update analysis statistics
        
        Args:
            job: Analysis job
            result: Analysis result
            success: Whether analysis was successful
        """
        self.stats['total_analyses'] += 1
        
        if job.mode == AnalysisMode.REAL_TIME:
            self.stats['real_time_analyses'] += 1
        elif job.mode == AnalysisMode.BATCH:
            self.stats['batch_analyses'] += 1
        
        if success:
            self.stats['successful_analyses'] += 1
        else:
            self.stats['failed_analyses'] += 1
        
        self.stats['by_analysis_type'][job.analysis_type.value] += 1
        
        if result.responses:
            for response in result.responses:
                self.stats['by_provider'][response.provider.value] += 1
        
        # Update average processing time
        current_avg = self.stats['average_processing_time']
        total = self.stats['total_analyses']
        self.stats['average_processing_time'] = (
            (current_avg * (total - 1) + result.processing_time) / total
        )

    async def get_statistics(self) -> Dict[str, Any]:
        """Get analysis engine statistics
        
        Returns:
            Statistics dictionary
        """
        stats = self.stats.copy()
        stats.update({
            'active_jobs': len(self.active_jobs),
            'completed_jobs': len(self.completed_jobs),
            'real_time_queue_size': self.real_time_queue.qsize(),
            'priority_queue_size': self.priority_queue.qsize(),
            'batch_buffer_sizes': {
                analysis_type.value: len(events) 
                for analysis_type, events in self.batch_buffer.items()
            }
        })
        return stats

    async def shutdown(self):
        """Shutdown analysis engine"""
        self.running = False
        
        # Cancel workers
        for worker in self.workers:
            worker.cancel()
        
        if self.batch_processor_task:
            self.batch_processor_task.cancel()
        
        # Wait for workers to complete
        await asyncio.gather(*self.workers, self.batch_processor_task, return_exceptions=True)
        
        logger.info("AI analysis engine shutdown complete")