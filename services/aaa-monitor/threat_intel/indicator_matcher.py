"""
SkausWatch AAA Monitor Service - Indicator Matcher

Real-time threat intelligence matching service that compares
events against IOC database for threat detection.
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
import ipaddress

import structlog

from ..models import BaseEvent, ThreatMatch, IOC, ThreatLevel

logger = structlog.get_logger(__name__)


class IndicatorMatcher:
    """Real-time threat intelligence indicator matcher"""
    
    def __init__(self, threat_database, config: Dict[str, Any]):
        """Initialize indicator matcher
        
        Args:
            threat_database: Threat database instance
            config: Matcher configuration
        """
        self.threat_database = threat_database
        self.config = config
        
        # Matching configuration
        self.minimum_confidence = config.get('minimum_confidence', 0.3)
        self.enable_fuzzy_matching = config.get('enable_fuzzy_matching', True)
        self.fuzzy_threshold = config.get('fuzzy_threshold', 0.8)
        self.match_cache_ttl = config.get('match_cache_ttl', 3600)  # 1 hour
        
        # Cache for performance
        self.match_cache = {}
        self.cache_timestamps = {}
        
        # Compiled regex patterns for better performance
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.domain_pattern = re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b')
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.url_pattern = re.compile(r'https?://[^\s<>"]+')
        self.hash_patterns = {
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'sha512': re.compile(r'\b[a-fA-F0-9]{128}\b')
        }
        
        # Statistics
        self.stats = {
            'total_matches': 0,
            'matches_by_type': {},
            'matches_by_confidence': {'high': 0, 'medium': 0, 'low': 0},
            'cache_hits': 0,
            'cache_misses': 0,
            'last_match': None
        }

    async def match_event(self, event: BaseEvent) -> List[ThreatMatch]:
        """Match event against threat intelligence indicators
        
        Args:
            event: Event to match against indicators
            
        Returns:
            List of threat matches
        """
        try:
            start_time = datetime.utcnow()
            matches = []
            
            # Extract observables from event
            observables = await self._extract_observables(event)
            
            if not observables:
                return matches
            
            # Check each observable against indicators
            for observable in observables:
                # Check cache first
                cache_key = f"{observable['type']}:{observable['value']}"
                cached_matches = self._get_cached_matches(cache_key)
                
                if cached_matches is not None:
                    matches.extend(cached_matches)
                    self.stats['cache_hits'] += 1
                    continue
                
                self.stats['cache_misses'] += 1
                
                # Perform indicator matching
                indicator_matches = await self._match_observable(observable, event)
                
                # Cache results
                self._cache_matches(cache_key, indicator_matches)
                
                matches.extend(indicator_matches)
            
            # Update statistics
            if matches:
                self.stats['total_matches'] += len(matches)
                self.stats['last_match'] = start_time.isoformat()
                
                for match in matches:
                    # Update type statistics
                    match_type = getattr(match, 'matched_field', 'unknown')
                    self.stats['matches_by_type'][match_type] = self.stats['matches_by_type'].get(match_type, 0) + 1
                    
                    # Update confidence statistics
                    if match.confidence >= 0.8:
                        self.stats['matches_by_confidence']['high'] += 1
                    elif match.confidence >= 0.5:
                        self.stats['matches_by_confidence']['medium'] += 1
                    else:
                        self.stats['matches_by_confidence']['low'] += 1
            
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            
            logger.debug("Threat intelligence matching completed",
                        event_id=event.id,
                        observables_extracted=len(observables),
                        matches_found=len(matches),
                        processing_time=processing_time)
            
            return matches
            
        except Exception as e:
            logger.error("Error matching event against indicators", 
                        event_id=event.id, error=str(e))
            return []

    async def _extract_observables(self, event: BaseEvent) -> List[Dict[str, Any]]:
        """Extract observables from event data"""
        try:
            observables = []
            text_content = []
            
            # Collect all text content to analyze
            text_content.append(event.message)
            
            # Add content from raw data
            if event.raw_data:
                text_content.extend(self._extract_text_from_dict(event.raw_data))
            
            # Add content from processed data
            if event.processed_data:
                text_content.extend(self._extract_text_from_dict(event.processed_data))
            
            # Extract from event-specific fields
            observables.extend(self._extract_from_event_fields(event))
            
            # Extract from combined text content
            combined_text = ' '.join(text_content)
            observables.extend(await self._extract_from_text(combined_text))
            
            # Remove duplicates
            unique_observables = []
            seen = set()
            
            for obs in observables:
                key = f"{obs['type']}:{obs['value'].lower()}"
                if key not in seen:
                    seen.add(key)
                    unique_observables.append(obs)
            
            return unique_observables
            
        except Exception as e:
            logger.error("Error extracting observables", error=str(e))
            return []

    def _extract_text_from_dict(self, data: Dict[str, Any]) -> List[str]:
        """Extract text values from nested dictionary"""
        text_values = []
        
        try:
            def extract_recursive(obj):
                if isinstance(obj, dict):
                    for value in obj.values():
                        extract_recursive(value)
                elif isinstance(obj, list):
                    for item in obj:
                        extract_recursive(item)
                elif isinstance(obj, str):
                    text_values.append(obj)
                elif obj is not None:
                    text_values.append(str(obj))
            
            extract_recursive(data)
            return text_values
            
        except Exception as e:
            logger.error("Error extracting text from dict", error=str(e))
            return []

    def _extract_from_event_fields(self, event: BaseEvent) -> List[Dict[str, Any]]:
        """Extract observables from specific event fields"""
        observables = []
        
        try:
            # IP addresses
            if hasattr(event, 'source_ip') and event.source_ip:
                observables.append({
                    'type': 'ip',
                    'value': event.source_ip,
                    'field': 'source_ip'
                })
            
            if hasattr(event, 'destination_ip') and event.destination_ip:
                observables.append({
                    'type': 'ip',
                    'value': event.destination_ip,
                    'field': 'destination_ip'
                })
            
            # Usernames
            if hasattr(event, 'username') and event.username:
                observables.append({
                    'type': 'username',
                    'value': event.username,
                    'field': 'username'
                })
            
            # File paths
            if hasattr(event, 'file_path') and event.file_path:
                observables.append({
                    'type': 'file',
                    'value': event.file_path,
                    'field': 'file_path'
                })
            
            # Processes/commands
            if hasattr(event, 'command') and event.command:
                observables.append({
                    'type': 'command',
                    'value': event.command,
                    'field': 'command'
                })
            
            if hasattr(event, 'executable') and event.executable:
                observables.append({
                    'type': 'file',
                    'value': event.executable,
                    'field': 'executable'
                })
            
            return observables
            
        except Exception as e:
            logger.error("Error extracting from event fields", error=str(e))
            return []

    async def _extract_from_text(self, text: str) -> List[Dict[str, Any]]:
        """Extract observables from text content using regex patterns"""
        observables = []
        
        try:
            # IP addresses
            ip_matches = self.ip_pattern.findall(text)
            for ip in ip_matches:
                if self._is_valid_ip(ip):
                    observables.append({
                        'type': 'ip',
                        'value': ip,
                        'field': 'text_content'
                    })
            
            # Domain names
            domain_matches = self.domain_pattern.findall(text)
            for domain in domain_matches:
                if self._is_valid_domain(domain):
                    observables.append({
                        'type': 'domain',
                        'value': domain,
                        'field': 'text_content'
                    })
            
            # Email addresses
            email_matches = self.email_pattern.findall(text)
            for email in email_matches:
                observables.append({
                    'type': 'email',
                    'value': email,
                    'field': 'text_content'
                })
            
            # URLs
            url_matches = self.url_pattern.findall(text)
            for url in url_matches:
                observables.append({
                    'type': 'url',
                    'value': url,
                    'field': 'text_content'
                })
            
            # File hashes
            for hash_type, pattern in self.hash_patterns.items():
                hash_matches = pattern.findall(text)
                for hash_value in hash_matches:
                    observables.append({
                        'type': f'hash-{hash_type}',
                        'value': hash_value.lower(),
                        'field': 'text_content'
                    })
            
            return observables
            
        except Exception as e:
            logger.error("Error extracting from text", error=str(e))
            return []

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            addr = ipaddress.ip_address(ip)
            # Exclude private and reserved addresses from matching
            return not (addr.is_private or addr.is_reserved or addr.is_loopback)
        except:
            return False

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain name"""
        try:
            # Basic domain validation
            if len(domain) < 4 or len(domain) > 253:
                return False
            
            # Must contain at least one dot
            if '.' not in domain:
                return False
            
            # Should not be a local/private domain
            if domain.endswith('.local') or domain.endswith('.localhost'):
                return False
            
            # Should not be numeric (likely extracted IP)
            if domain.replace('.', '').isdigit():
                return False
            
            return True
            
        except:
            return False

    async def _match_observable(self, observable: Dict[str, Any], event: BaseEvent) -> List[ThreatMatch]:
        """Match single observable against threat indicators"""
        try:
            matches = []
            
            # Get matching indicators from database
            indicators = await self.threat_database.search_indicators(
                observable['type'], 
                observable['value']
            )
            
            for indicator in indicators:
                # Skip indicators below minimum confidence
                if indicator.confidence < self.minimum_confidence:
                    continue
                
                # Calculate match confidence
                match_confidence = await self._calculate_match_confidence(
                    observable, indicator, event
                )
                
                if match_confidence >= self.minimum_confidence:
                    match = ThreatMatch(
                        event_id=event.id,
                        ioc_id=indicator.id,
                        matched_value=observable['value'],
                        field_name=observable.get('field', 'unknown'),
                        confidence=match_confidence,
                        threat_level=indicator.threat_level
                    )
                    matches.append(match)
            
            # Perform fuzzy matching if enabled
            if self.enable_fuzzy_matching and not matches:
                fuzzy_matches = await self._fuzzy_match_observable(observable, event)
                matches.extend(fuzzy_matches)
            
            return matches
            
        except Exception as e:
            logger.error("Error matching observable", 
                        observable=observable, error=str(e))
            return []

    async def _calculate_match_confidence(self, observable: Dict[str, Any], 
                                        indicator: IOC, event: BaseEvent) -> float:
        """Calculate confidence score for indicator match"""
        try:
            base_confidence = indicator.confidence
            
            # Adjust confidence based on match type
            match_type_modifiers = {
                'ip': 1.0,          # Exact IP matches are highly reliable
                'domain': 0.95,      # Domain matches are very reliable
                'hash-md5': 1.0,     # Hash matches are exact
                'hash-sha1': 1.0,
                'hash-sha256': 1.0,
                'hash-sha512': 1.0,
                'email': 0.9,        # Email matches are quite reliable
                'url': 0.85,         # URL matches can have variations
                'username': 0.7,     # Usernames can be common
                'file': 0.8,         # File paths are moderately reliable
                'command': 0.75      # Commands can be common
            }
            
            type_modifier = match_type_modifiers.get(observable['type'], 0.6)
            adjusted_confidence = base_confidence * type_modifier
            
            # Context-based adjustments
            if event.severity in ['critical', 'high']:
                adjusted_confidence *= 1.1  # Higher confidence for critical events
            
            # Source field adjustments
            field = observable.get('field', '')
            if field in ['source_ip', 'destination_ip', 'file_path']:
                adjusted_confidence *= 1.05  # Structured fields more reliable
            elif field == 'text_content':
                adjusted_confidence *= 0.95  # Text extraction less reliable
            
            # Ensure confidence stays within bounds
            return min(1.0, max(0.0, adjusted_confidence))
            
        except Exception as e:
            logger.error("Error calculating match confidence", error=str(e))
            return 0.0

    async def _fuzzy_match_observable(self, observable: Dict[str, Any], 
                                    event: BaseEvent) -> List[ThreatMatch]:
        """Perform fuzzy matching for partial indicator matches"""
        try:
            matches = []
            
            # Only perform fuzzy matching for certain types
            fuzzable_types = ['domain', 'url', 'file', 'command']
            
            if observable['type'] not in fuzzable_types:
                return matches
            
            # Get potential fuzzy matches
            fuzzy_indicators = await self.threat_database.search_similar_indicators(
                observable['type'],
                observable['value'],
                threshold=self.fuzzy_threshold
            )
            
            for indicator in fuzzy_indicators:
                # Calculate fuzzy match confidence
                similarity = await self._calculate_similarity(
                    observable['value'], 
                    indicator.value
                )
                
                if similarity >= self.fuzzy_threshold:
                    # Reduce confidence for fuzzy matches
                    match_confidence = indicator.confidence * similarity * 0.8
                    
                    if match_confidence >= self.minimum_confidence:
                        match = ThreatMatch(
                            event_id=event.id,
                            ioc_id=indicator.id,
                            matched_value=observable['value'],
                            field_name=observable.get('field', 'unknown'),
                            confidence=match_confidence,
                            threat_level=indicator.threat_level
                        )
                        matches.append(match)
            
            return matches
            
        except Exception as e:
            logger.error("Error in fuzzy matching", error=str(e))
            return []

    async def _calculate_similarity(self, value1: str, value2: str) -> float:
        """Calculate similarity between two strings"""
        try:
            # Simple Levenshtein distance-based similarity
            from difflib import SequenceMatcher
            
            similarity = SequenceMatcher(None, value1.lower(), value2.lower()).ratio()
            return similarity
            
        except Exception as e:
            logger.error("Error calculating similarity", error=str(e))
            return 0.0

    def _get_cached_matches(self, cache_key: str) -> Optional[List[ThreatMatch]]:
        """Get cached threat matches"""
        try:
            if cache_key not in self.match_cache:
                return None
            
            # Check if cache entry is still valid
            cached_time = self.cache_timestamps.get(cache_key)
            if not cached_time:
                return None
            
            if (datetime.utcnow() - cached_time).total_seconds() > self.match_cache_ttl:
                # Cache expired
                del self.match_cache[cache_key]
                del self.cache_timestamps[cache_key]
                return None
            
            return self.match_cache[cache_key]
            
        except Exception as e:
            logger.error("Error getting cached matches", error=str(e))
            return None

    def _cache_matches(self, cache_key: str, matches: List[ThreatMatch]):
        """Cache threat matches"""
        try:
            self.match_cache[cache_key] = matches
            self.cache_timestamps[cache_key] = datetime.utcnow()
            
            # Clean old cache entries periodically
            if len(self.match_cache) > 10000:  # Arbitrary limit
                await self._cleanup_cache()
                
        except Exception as e:
            logger.error("Error caching matches", error=str(e))

    async def _cleanup_cache(self):
        """Clean up expired cache entries"""
        try:
            current_time = datetime.utcnow()
            expired_keys = []
            
            for key, timestamp in self.cache_timestamps.items():
                if (current_time - timestamp).total_seconds() > self.match_cache_ttl:
                    expired_keys.append(key)
            
            for key in expired_keys:
                self.match_cache.pop(key, None)
                self.cache_timestamps.pop(key, None)
            
            logger.debug("Cache cleanup completed", expired_entries=len(expired_keys))
            
        except Exception as e:
            logger.error("Error cleaning up cache", error=str(e))

    async def batch_match_events(self, events: List[BaseEvent]) -> Dict[str, List[ThreatMatch]]:
        """Batch process multiple events for threat matching
        
        Args:
            events: List of events to match
            
        Returns:
            Dictionary mapping event IDs to their matches
        """
        try:
            results = {}
            
            # Process events concurrently
            match_tasks = []
            for event in events:
                task = asyncio.create_task(self.match_event(event))
                match_tasks.append((event.id, task))
            
            # Wait for all matches to complete
            for event_id, task in match_tasks:
                try:
                    matches = await task
                    results[event_id] = matches
                except Exception as e:
                    logger.error("Error in batch matching", 
                               event_id=event_id, error=str(e))
                    results[event_id] = []
            
            return results
            
        except Exception as e:
            logger.error("Error in batch event matching", error=str(e))
            return {}

    def get_statistics(self) -> Dict[str, Any]:
        """Get indicator matching statistics"""
        return {
            **self.stats,
            'cache_size': len(self.match_cache),
            'cache_hit_ratio': (
                self.stats['cache_hits'] / 
                (self.stats['cache_hits'] + self.stats['cache_misses'])
                if (self.stats['cache_hits'] + self.stats['cache_misses']) > 0 else 0.0
            ),
            'configuration': {
                'minimum_confidence': self.minimum_confidence,
                'enable_fuzzy_matching': self.enable_fuzzy_matching,
                'fuzzy_threshold': self.fuzzy_threshold,
                'match_cache_ttl': self.match_cache_ttl
            }
        }

    async def clear_cache(self):
        """Clear the match cache"""
        try:
            self.match_cache.clear()
            self.cache_timestamps.clear()
            logger.info("Indicator match cache cleared")
            
        except Exception as e:
            logger.error("Error clearing cache", error=str(e))

    async def update_configuration(self, new_config: Dict[str, Any]):
        """Update matcher configuration
        
        Args:
            new_config: New configuration parameters
        """
        try:
            if 'minimum_confidence' in new_config:
                self.minimum_confidence = float(new_config['minimum_confidence'])
            
            if 'enable_fuzzy_matching' in new_config:
                self.enable_fuzzy_matching = bool(new_config['enable_fuzzy_matching'])
            
            if 'fuzzy_threshold' in new_config:
                self.fuzzy_threshold = float(new_config['fuzzy_threshold'])
            
            if 'match_cache_ttl' in new_config:
                self.match_cache_ttl = int(new_config['match_cache_ttl'])
                # Clear cache to apply new TTL
                await self.clear_cache()
            
            logger.info("Indicator matcher configuration updated", config=new_config)
            
        except Exception as e:
            logger.error("Error updating configuration", error=str(e))