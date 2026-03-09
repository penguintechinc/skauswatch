"""
SkausWatch AAA Monitor Service - Response Processor

AI response parsing, validation, result caching, deduplication,
and error handling with retry logic.
"""

import asyncio
import hashlib
import json
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import structlog

from ..models import AIProvider, Severity, ThreatLevel
from .ai_provider import AIAnalysisResponse, AIAnalysisType

logger = structlog.get_logger(__name__)


class ResponseQuality(str, Enum):
    """Response quality assessment"""

    EXCELLENT = "excellent"
    GOOD = "good"
    ACCEPTABLE = "acceptable"
    POOR = "poor"
    INVALID = "invalid"


class CacheStrategy(str, Enum):
    """Caching strategies"""

    AGGRESSIVE = "aggressive"  # Cache everything
    SELECTIVE = "selective"  # Cache based on confidence
    MINIMAL = "minimal"  # Cache only high-confidence results
    DISABLED = "disabled"  # No caching


@dataclass
class ProcessedResponse:
    """Processed AI response with extracted information"""

    original_response: AIAnalysisResponse
    quality: ResponseQuality

    # Extracted structured data
    threat_level: Optional[ThreatLevel] = None
    confidence_score: float = 0.0
    severity: Optional[Severity] = None

    # Extracted entities
    iocs: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    affected_systems: List[str] = field(default_factory=list)
    attack_techniques: List[str] = field(default_factory=list)

    # Metadata
    key_findings: List[str] = field(default_factory=list)
    confidence_factors: List[str] = field(default_factory=list)
    processing_notes: List[str] = field(default_factory=list)

    # Quality metrics
    structure_score: float = 0.0
    completeness_score: float = 0.0
    relevance_score: float = 0.0

    processing_time: float = 0.0
    processed_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class CacheEntry:
    """Cache entry for AI responses"""

    cache_key: str
    response: ProcessedResponse
    cached_at: datetime
    access_count: int = 0
    last_accessed: datetime = field(default_factory=datetime.utcnow)
    ttl: int = 3600  # seconds

    @property
    def is_expired(self) -> bool:
        """Check if cache entry is expired"""
        return (datetime.utcnow() - self.cached_at).total_seconds() > self.ttl


@dataclass
class DeduplicationEntry:
    """Deduplication tracking entry"""

    content_hash: str
    first_seen: datetime
    last_seen: datetime
    count: int = 1
    response_ids: List[str] = field(default_factory=list)


class ResponseProcessor:
    """AI response processor with caching and deduplication"""

    def __init__(self, redis_client=None, config: Optional[Dict[str, Any]] = None):
        """Initialize response processor

        Args:
            redis_client: Optional Redis client for distributed caching
            config: Processor configuration
        """
        self.redis_client = redis_client
        self.config = config or {}

        # Cache configuration
        self.cache_strategy = CacheStrategy(
            self.config.get("cache_strategy", "selective")
        )
        self.cache_ttl = self.config.get("cache_ttl", 3600)
        self.max_cache_size = self.config.get("max_cache_size", 10000)
        self.cache_min_confidence = self.config.get("cache_min_confidence", 0.6)

        # Deduplication configuration
        self.enable_dedup = self.config.get("enable_deduplication", True)
        self.dedup_window = timedelta(
            minutes=self.config.get("dedup_window_minutes", 60)
        )
        self.dedup_threshold = self.config.get(
            "dedup_threshold", 0.9
        )  # Similarity threshold

        # Local caches
        self.response_cache: Dict[str, CacheEntry] = {}
        self.dedup_cache: Dict[str, DeduplicationEntry] = {}

        # Processing statistics
        self.stats = {
            "total_processed": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "deduplicated_responses": 0,
            "quality_scores": defaultdict(int),
            "processing_errors": 0,
            "average_processing_time": 0.0,
        }

        # Quality assessment patterns
        self._initialize_patterns()

        # Cleanup task
        self.cleanup_task = None
        self.cleanup_interval = self.config.get("cleanup_interval", 300)  # 5 minutes

    async def initialize(self):
        """Initialize the response processor"""
        try:
            # Start cleanup task
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())

            logger.info(
                "Response processor initialized",
                cache_strategy=self.cache_strategy.value,
                enable_dedup=self.enable_dedup,
            )

        except Exception as e:
            logger.error("Failed to initialize response processor", error=str(e))
            raise

    async def process_response(self, response: AIAnalysisResponse) -> ProcessedResponse:
        """Process an AI response

        Args:
            response: Raw AI response

        Returns:
            Processed response with extracted information
        """
        start_time = time.time()

        try:
            # Check cache first
            cache_key = self._generate_cache_key(response)
            cached_result = await self._get_cached_response(cache_key)
            if cached_result:
                self.stats["cache_hits"] += 1
                return cached_result

            self.stats["cache_misses"] += 1

            # Check for deduplication
            if self.enable_dedup:
                dedup_result = await self._check_deduplication(response)
                if dedup_result:
                    self.stats["deduplicated_responses"] += 1
                    return dedup_result

            # Process the response
            processed = await self._parse_response(response)
            processed.processing_time = time.time() - start_time

            # Cache if appropriate
            await self._cache_response(cache_key, processed)

            # Update deduplication tracking
            if self.enable_dedup:
                await self._update_deduplication(response, processed)

            # Update statistics
            self._update_stats(processed)

            logger.debug(
                "Response processed",
                request_id=response.request_id,
                quality=processed.quality.value,
                processing_time=processed.processing_time,
            )

            return processed

        except Exception as e:
            self.stats["processing_errors"] += 1
            logger.error(
                "Response processing failed",
                request_id=response.request_id,
                error=str(e),
            )

            # Return minimal processed response
            return ProcessedResponse(
                original_response=response,
                quality=ResponseQuality.INVALID,
                processing_time=time.time() - start_time,
                processing_notes=[f"Processing error: {str(e)}"],
            )

    async def _parse_response(self, response: AIAnalysisResponse) -> ProcessedResponse:
        """Parse AI response and extract structured information

        Args:
            response: AI response to parse

        Returns:
            Processed response with extracted data
        """
        text = response.response_text or ""

        # Initialize processed response
        processed = ProcessedResponse(
            original_response=response,
            quality=ResponseQuality.ACCEPTABLE,
            confidence_score=response.confidence_score or 0.5,
        )

        # Assess response quality
        processed.quality = self._assess_quality(text, response.analysis_type)
        processed.structure_score = self._calculate_structure_score(text)
        processed.completeness_score = self._calculate_completeness_score(
            text, response.analysis_type
        )
        processed.relevance_score = self._calculate_relevance_score(
            text, response.analysis_type
        )

        # Extract threat level
        processed.threat_level = self._extract_threat_level(text)

        # Extract severity
        processed.severity = self._extract_severity(text)

        # Extract IOCs
        processed.iocs = self._extract_iocs(text)

        # Extract recommendations
        processed.recommendations = self._extract_recommendations(text)

        # Extract affected systems
        processed.affected_systems = self._extract_affected_systems(text)

        # Extract attack techniques
        processed.attack_techniques = self._extract_attack_techniques(text)

        # Extract key findings
        processed.key_findings = self._extract_key_findings(text)

        # Extract confidence factors
        processed.confidence_factors = self._extract_confidence_factors(text)

        # Adjust confidence based on quality
        if processed.quality == ResponseQuality.EXCELLENT:
            processed.confidence_score = min(1.0, processed.confidence_score * 1.1)
        elif processed.quality == ResponseQuality.POOR:
            processed.confidence_score *= 0.8
        elif processed.quality == ResponseQuality.INVALID:
            processed.confidence_score *= 0.5

        return processed

    def _assess_quality(
        self, text: str, analysis_type: AIAnalysisType
    ) -> ResponseQuality:
        """Assess the quality of AI response

        Args:
            text: Response text
            analysis_type: Type of analysis

        Returns:
            Quality assessment
        """
        if not text or len(text.strip()) < 50:
            return ResponseQuality.INVALID

        score = 0.0

        # Check for structure indicators
        structure_indicators = [
            "summary:",
            "analysis:",
            "findings:",
            "recommendation",
            "assessment:",
            "conclusion:",
            "details:",
        ]
        structure_count = sum(
            1 for indicator in structure_indicators if indicator in text.lower()
        )
        score += min(0.3, structure_count * 0.1)

        # Check for specific analysis type indicators
        type_indicators = {
            AIAnalysisType.SECURITY_EVENT: [
                "threat",
                "attack",
                "malicious",
                "vulnerability",
                "security",
            ],
            AIAnalysisType.ANOMALY_DETECTION: [
                "anomaly",
                "unusual",
                "outlier",
                "deviation",
                "abnormal",
            ],
            AIAnalysisType.THREAT_CLASSIFICATION: [
                "classification",
                "category",
                "type",
                "mitre",
                "technique",
            ],
            AIAnalysisType.LOG_CORRELATION: [
                "correlation",
                "relationship",
                "timeline",
                "sequence",
                "pattern",
            ],
            AIAnalysisType.PATTERN_ANALYSIS: [
                "pattern",
                "trend",
                "frequency",
                "behavior",
                "distribution",
            ],
            AIAnalysisType.INCIDENT_SUMMARY: [
                "incident",
                "impact",
                "timeline",
                "response",
                "remediation",
            ],
        }

        relevant_indicators = type_indicators.get(analysis_type, [])
        relevance_count = sum(
            1 for indicator in relevant_indicators if indicator in text.lower()
        )
        score += min(0.25, relevance_count * 0.05)

        # Check for evidence and specificity
        if re.search(
            r"evidence|indicates|shows|demonstrates|reveals", text, re.IGNORECASE
        ):
            score += 0.15

        # Check for confidence indicators
        confidence_patterns = [
            r"confidence|certain|likely|probable|definitive",
            r"\d+%|\b\d+\.\d+\b",  # Percentages or decimal numbers
            r"high|medium|low",
        ]
        for pattern in confidence_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                score += 0.1
                break

        # Check for actionable recommendations
        if re.search(r"recommend|suggest|should|must|action", text, re.IGNORECASE):
            score += 0.2

        # Determine quality based on score
        if score >= 0.8:
            return ResponseQuality.EXCELLENT
        elif score >= 0.6:
            return ResponseQuality.GOOD
        elif score >= 0.4:
            return ResponseQuality.ACCEPTABLE
        else:
            return ResponseQuality.POOR

    def _calculate_structure_score(self, text: str) -> float:
        """Calculate structure score based on organization

        Args:
            text: Response text

        Returns:
            Structure score (0-1)
        """
        score = 0.0

        # Check for headers/sections
        headers = re.findall(r"^[A-Z][^:]*:", text, re.MULTILINE)
        score += min(0.4, len(headers) * 0.1)

        # Check for numbered lists
        numbered_lists = re.findall(r"^\s*\d+\.", text, re.MULTILINE)
        score += min(0.3, len(numbered_lists) * 0.05)

        # Check for bullet points
        bullets = re.findall(r"^\s*[-*•]", text, re.MULTILINE)
        score += min(0.3, len(bullets) * 0.03)

        return min(1.0, score)

    def _calculate_completeness_score(
        self, text: str, analysis_type: AIAnalysisType
    ) -> float:
        """Calculate completeness score based on expected elements

        Args:
            text: Response text
            analysis_type: Type of analysis

        Returns:
            Completeness score (0-1)
        """
        expected_elements = {
            AIAnalysisType.SECURITY_EVENT: [
                "threat",
                "risk",
                "impact",
                "recommendation",
                "evidence",
            ],
            AIAnalysisType.ANOMALY_DETECTION: [
                "anomaly",
                "normal",
                "deviation",
                "significance",
                "explanation",
            ],
            AIAnalysisType.THREAT_CLASSIFICATION: [
                "classification",
                "threat",
                "technique",
                "indicator",
                "confidence",
            ],
            AIAnalysisType.LOG_CORRELATION: [
                "correlation",
                "relationship",
                "timeline",
                "causation",
                "sequence",
            ],
            AIAnalysisType.PATTERN_ANALYSIS: [
                "pattern",
                "frequency",
                "trend",
                "behavior",
                "statistical",
            ],
            AIAnalysisType.INCIDENT_SUMMARY: [
                "incident",
                "timeline",
                "impact",
                "response",
                "remediation",
            ],
        }

        elements = expected_elements.get(analysis_type, [])
        if not elements:
            return 0.5

        found_elements = sum(1 for element in elements if element in text.lower())
        return found_elements / len(elements)

    def _calculate_relevance_score(
        self, text: str, analysis_type: AIAnalysisType
    ) -> float:
        """Calculate relevance score based on analysis type focus

        Args:
            text: Response text
            analysis_type: Type of analysis

        Returns:
            Relevance score (0-1)
        """
        # This is simplified - in practice, you might use more sophisticated NLP
        text_lower = text.lower()

        relevance_keywords = {
            AIAnalysisType.SECURITY_EVENT: [
                "security",
                "threat",
                "attack",
                "malicious",
                "vulnerability",
                "breach",
                "intrusion",
                "unauthorized",
                "suspicious",
            ],
            AIAnalysisType.ANOMALY_DETECTION: [
                "anomaly",
                "abnormal",
                "unusual",
                "outlier",
                "deviation",
                "irregular",
                "unexpected",
                "statistical",
                "baseline",
            ],
            AIAnalysisType.THREAT_CLASSIFICATION: [
                "threat",
                "malware",
                "apt",
                "campaign",
                "actor",
                "technique",
                "tactic",
                "procedure",
                "mitre",
                "attack",
            ],
        }

        keywords = relevance_keywords.get(analysis_type, [])
        if not keywords:
            return 0.5

        keyword_count = sum(1 for keyword in keywords if keyword in text_lower)
        return min(
            1.0, keyword_count / len(keywords) * 2
        )  # Scale up to allow for high relevance

    def _extract_threat_level(self, text: str) -> Optional[ThreatLevel]:
        """Extract threat level from response text

        Args:
            text: Response text

        Returns:
            Detected threat level
        """
        text_lower = text.lower()

        # Define patterns for each threat level
        patterns = {
            ThreatLevel.CRITICAL: [
                "critical",
                "severe",
                "immediate",
                "emergency",
                "urgent",
                "critical threat",
                "severe risk",
                "immediate action",
            ],
            ThreatLevel.HIGH: [
                "high",
                "serious",
                "significant",
                "major",
                "important",
                "high risk",
                "serious threat",
                "significant risk",
            ],
            ThreatLevel.MEDIUM: [
                "medium",
                "moderate",
                "elevated",
                "concerning",
                "notable",
                "moderate risk",
                "elevated threat",
            ],
            ThreatLevel.LOW: [
                "low",
                "minor",
                "minimal",
                "slight",
                "negligible",
                "low risk",
                "minor threat",
                "minimal impact",
            ],
        }

        # Score each threat level
        level_scores = {}
        for level, keywords in patterns.items():
            score = sum(1 for keyword in keywords if keyword in text_lower)
            if score > 0:
                level_scores[level] = score

        if level_scores:
            return max(level_scores.keys(), key=lambda k: level_scores[k])

        return None

    def _extract_severity(self, text: str) -> Optional[Severity]:
        """Extract severity level from response text

        Args:
            text: Response text

        Returns:
            Detected severity
        """
        text_lower = text.lower()

        severity_patterns = {
            Severity.CRITICAL: ["critical", "emergency"],
            Severity.HIGH: ["high", "serious", "major"],
            Severity.MEDIUM: ["medium", "moderate", "elevated"],
            Severity.LOW: ["low", "minor", "minimal"],
            Severity.INFO: ["info", "informational", "notice"],
        }

        for severity, patterns in severity_patterns.items():
            if any(pattern in text_lower for pattern in patterns):
                return severity

        return None

    def _extract_iocs(self, text: str) -> List[str]:
        """Extract Indicators of Compromise from response text

        Args:
            text: Response text

        Returns:
            List of IOCs found
        """
        iocs = []

        # Define IOC patterns
        patterns = {
            "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "domain": r"\b[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b",
            "url": r'https?://[^\s<>"{}|\\^`\[\]]+',
            "hash_md5": r"\b[a-fA-F0-9]{32}\b",
            "hash_sha1": r"\b[a-fA-F0-9]{40}\b",
            "hash_sha256": r"\b[a-fA-F0-9]{64}\b",
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "file_path": r'[A-Za-z]:\\[^\s<>"|?*]+|/[^\s<>"|?*]+',
            "registry": r'HKEY_[A-Z_]+\\[^\s<>"|?*]+',
        }

        for ioc_type, pattern in patterns.items():
            matches = re.findall(pattern, text)
            for match in matches:
                # Basic validation to avoid false positives
                if self._is_valid_ioc(match, ioc_type):
                    iocs.append(match)

        # Remove duplicates while preserving order
        return list(dict.fromkeys(iocs))[:20]  # Limit to 20 IOCs

    def _is_valid_ioc(self, value: str, ioc_type: str) -> bool:
        """Validate if extracted value is a legitimate IOC

        Args:
            value: Extracted value
            ioc_type: Type of IOC

        Returns:
            True if valid IOC
        """
        # Basic validation rules
        if ioc_type == "ip":
            parts = value.split(".")
            return all(0 <= int(part) <= 255 for part in parts if part.isdigit())
        elif ioc_type == "domain":
            return len(value) > 4 and "." in value and not value.startswith(".")
        elif ioc_type in ["hash_md5", "hash_sha1", "hash_sha256"]:
            return len(value) in [32, 40, 64] and all(
                c in "0123456789abcdefABCDEF" for c in value
            )
        elif ioc_type == "email":
            return "@" in value and "." in value.split("@")[1]

        return True

    def _extract_recommendations(self, text: str) -> List[str]:
        """Extract recommendations from response text

        Args:
            text: Response text

        Returns:
            List of recommendations
        """
        recommendations = []

        # Define patterns to find recommendations
        patterns = [
            r"recommend(?:ation)?s?:?\s*(.+?)(?:\n\n|\n[A-Z]|\Z)",
            r"(?:should|must|need to|advised to):\s*(.+?)(?:\n|\Z)",
            r"action(?:s)? (?:required|needed|recommended):?\s*(.+?)(?:\n\n|\Z)",
            r"next steps?:?\s*(.+?)(?:\n\n|\Z)",
            r"mitigation:?\s*(.+?)(?:\n\n|\Z)",
        ]

        for pattern in patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE | re.DOTALL)
            for match in matches:
                rec_text = match.group(1).strip()

                # Split multiple recommendations
                for rec in re.split(r"[•\-\*]\s*|\d+\.\s*", rec_text):
                    rec = rec.strip()
                    if len(rec) > 10 and len(rec) < 500:  # Reasonable length
                        recommendations.append(rec)

        return recommendations[:10]  # Limit to 10 recommendations

    def _extract_affected_systems(self, text: str) -> List[str]:
        """Extract affected systems from response text

        Args:
            text: Response text

        Returns:
            List of affected systems
        """
        systems = []

        # System name patterns
        patterns = [
            r"\b(?:server|host|system|machine|endpoint|workstation|device)-?\w*\b",
            r"\b\w*(?:server|host|system|db|web|mail|dns|dc)\b",
            r"\b[A-Z][A-Z0-9]{2,}-\w+\b",  # Common naming patterns
            r"\b(?:Windows|Linux|Unix|MacOS|CentOS|Ubuntu)\s+\w*\b",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            systems.extend(matches)

        # Clean up and deduplicate
        cleaned_systems = []
        for system in systems:
            system = system.strip()
            if len(system) > 2 and system not in cleaned_systems:
                cleaned_systems.append(system)

        return cleaned_systems[:15]  # Limit to 15 systems

    def _extract_attack_techniques(self, text: str) -> List[str]:
        """Extract attack techniques from response text

        Args:
            text: Response text

        Returns:
            List of attack techniques
        """
        techniques = []

        # Common attack technique patterns
        technique_patterns = [
            r"T\d{4}(?:\.\d{3})?",  # MITRE ATT&CK technique IDs
            r"\b(?:phishing|spear.?phishing|malware|ransomware|trojan|backdoor)\b",
            r"\b(?:lateral.movement|privilege.escalation|credential.dumping)\b",
            r"\b(?:command.and.control|data.exfiltration|persistence)\b",
            r"\b(?:brute.force|dictionary.attack|password.spray)\b",
            r"\b(?:sql.injection|xss|csrf|rce|lfi|rfi)\b",
        ]

        for pattern in technique_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            techniques.extend(matches)

        return list(set(techniques))[:10]  # Unique techniques, limited to 10

    def _extract_key_findings(self, text: str) -> List[str]:
        """Extract key findings from response text

        Args:
            text: Response text

        Returns:
            List of key findings
        """
        findings = []

        # Look for findings sections
        patterns = [
            r"(?:key\s+)?findings?:?\s*(.+?)(?:\n\n|\n[A-Z]|\Z)",
            r"summary:?\s*(.+?)(?:\n\n|\n[A-Z]|\Z)",
            r"(?:main\s+)?results?:?\s*(.+?)(?:\n\n|\n[A-Z]|\Z)",
        ]

        for pattern in patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE | re.DOTALL)
            for match in matches:
                finding_text = match.group(1).strip()

                # Split by bullet points or numbers
                for finding in re.split(r"[•\-\*]\s*|\d+\.\s*", finding_text):
                    finding = finding.strip()
                    if len(finding) > 15 and len(finding) < 300:
                        findings.append(finding)

        return findings[:8]  # Limit to 8 findings

    def _extract_confidence_factors(self, text: str) -> List[str]:
        """Extract confidence factors from response text

        Args:
            text: Response text

        Returns:
            List of confidence factors
        """
        factors = []

        # Look for confidence-related terms
        confidence_patterns = [
            r"confidence:?\s*(.+?)(?:\n|\Z)",
            r"certainty:?\s*(.+?)(?:\n|\Z)",
            r"evidence:?\s*(.+?)(?:\n\n|\Z)",
            r"(?:based on|indicates|suggests|shows):?\s*(.+?)(?:\n|\Z)",
        ]

        for pattern in confidence_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                factor = match.group(1).strip()
                if len(factor) > 10 and len(factor) < 200:
                    factors.append(factor)

        return factors[:5]  # Limit to 5 factors

    def _generate_cache_key(self, response: AIAnalysisResponse) -> str:
        """Generate cache key for response

        Args:
            response: AI response

        Returns:
            Cache key string
        """
        # Create key from request characteristics
        key_data = {
            "analysis_type": response.analysis_type.value,
            "provider": response.provider.value,
            "model": response.model,
            "response_hash": hashlib.sha256(
                response.response_text.encode()
            ).hexdigest()[:16],
        }

        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_string.encode()).hexdigest()[:32]

    async def _get_cached_response(self, cache_key: str) -> Optional[ProcessedResponse]:
        """Get cached response if available and valid

        Args:
            cache_key: Cache key

        Returns:
            Cached processed response or None
        """
        # Check local cache first
        if cache_key in self.response_cache:
            entry = self.response_cache[cache_key]
            if not entry.is_expired:
                entry.access_count += 1
                entry.last_accessed = datetime.utcnow()
                return entry.response
            else:
                del self.response_cache[cache_key]

        # Check Redis cache if available
        if self.redis_client:
            try:
                cached_data = await self.redis_client.get(f"ai_response:{cache_key}")
                if cached_data:
                    # Deserialize would go here - simplified for this example
                    pass
            except Exception as e:
                logger.warning("Redis cache read failed", error=str(e))

        return None

    async def _cache_response(self, cache_key: str, response: ProcessedResponse):
        """Cache processed response

        Args:
            cache_key: Cache key
            response: Processed response to cache
        """
        # Check if we should cache based on strategy
        should_cache = False

        if self.cache_strategy == CacheStrategy.AGGRESSIVE:
            should_cache = True
        elif self.cache_strategy == CacheStrategy.SELECTIVE:
            should_cache = (
                response.quality in [ResponseQuality.EXCELLENT, ResponseQuality.GOOD]
                or response.confidence_score >= self.cache_min_confidence
            )
        elif self.cache_strategy == CacheStrategy.MINIMAL:
            should_cache = (
                response.quality == ResponseQuality.EXCELLENT
                and response.confidence_score >= 0.8
            )

        if not should_cache:
            return

        # Cache locally
        if len(self.response_cache) >= self.max_cache_size:
            # Remove oldest entries
            oldest_entries = sorted(
                self.response_cache.items(), key=lambda x: x[1].last_accessed
            )
            for key, _ in oldest_entries[: self.max_cache_size // 4]:
                del self.response_cache[key]

        entry = CacheEntry(
            cache_key=cache_key,
            response=response,
            cached_at=datetime.utcnow(),
            ttl=self.cache_ttl,
        )
        self.response_cache[cache_key] = entry

        # Cache in Redis if available
        if self.redis_client:
            try:
                # Serialize response for Redis - simplified
                await self.redis_client.setex(
                    f"ai_response:{cache_key}",
                    self.cache_ttl,
                    json.dumps({"processed": True}),  # Simplified
                )
            except Exception as e:
                logger.warning("Redis cache write failed", error=str(e))

    async def _check_deduplication(
        self, response: AIAnalysisResponse
    ) -> Optional[ProcessedResponse]:
        """Check if response is a duplicate and return cached result

        Args:
            response: AI response to check

        Returns:
            Cached result if duplicate found, None otherwise
        """
        content_hash = hashlib.sha256(response.response_text.encode()).hexdigest()

        if content_hash in self.dedup_cache:
            entry = self.dedup_cache[content_hash]

            # Check if within dedup window
            if datetime.utcnow() - entry.first_seen <= self.dedup_window:
                entry.count += 1
                entry.last_seen = datetime.utcnow()
                entry.response_ids.append(response.request_id)

                # Return the cached result (simplified - would need actual cached response)
                return None  # In practice, return the cached ProcessedResponse

        return None

    async def _update_deduplication(
        self, response: AIAnalysisResponse, processed: ProcessedResponse
    ):
        """Update deduplication tracking

        Args:
            response: Original AI response
            processed: Processed response
        """
        content_hash = hashlib.sha256(response.response_text.encode()).hexdigest()

        entry = DeduplicationEntry(
            content_hash=content_hash,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            response_ids=[response.request_id],
        )

        self.dedup_cache[content_hash] = entry

    def _initialize_patterns(self):
        """Initialize patterns for text extraction"""
        # This would contain compiled regex patterns for better performance
        # Simplified for this implementation
        pass

    def _update_stats(self, processed: ProcessedResponse):
        """Update processing statistics

        Args:
            processed: Processed response
        """
        self.stats["total_processed"] += 1
        self.stats["quality_scores"][processed.quality.value] += 1

        # Update average processing time
        current_avg = self.stats["average_processing_time"]
        total = self.stats["total_processed"]
        self.stats["average_processing_time"] = (
            current_avg * (total - 1) + processed.processing_time
        ) / total

    async def _cleanup_loop(self):
        """Background cleanup task"""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)

                # Clean up expired cache entries
                current_time = datetime.utcnow()
                expired_keys = [
                    key
                    for key, entry in self.response_cache.items()
                    if entry.is_expired
                ]
                for key in expired_keys:
                    del self.response_cache[key]

                # Clean up old deduplication entries
                expired_dedup_keys = [
                    key
                    for key, entry in self.dedup_cache.items()
                    if current_time - entry.last_seen > self.dedup_window
                ]
                for key in expired_dedup_keys:
                    del self.dedup_cache[key]

                if expired_keys or expired_dedup_keys:
                    logger.debug(
                        "Cleaned up expired cache entries",
                        response_cache=len(expired_keys),
                        dedup_cache=len(expired_dedup_keys),
                    )

            except Exception as e:
                logger.error("Cleanup task error", error=str(e))

    async def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics

        Returns:
            Statistics dictionary
        """
        stats = self.stats.copy()
        stats.update(
            {
                "cache_size": len(self.response_cache),
                "dedup_cache_size": len(self.dedup_cache),
                "cache_hit_ratio": (
                    self.stats["cache_hits"]
                    / (self.stats["cache_hits"] + self.stats["cache_misses"])
                    if (self.stats["cache_hits"] + self.stats["cache_misses"]) > 0
                    else 0
                ),
            }
        )
        return stats

    async def shutdown(self):
        """Shutdown response processor"""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass

        logger.info("Response processor shutdown complete")
