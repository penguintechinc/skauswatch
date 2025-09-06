"""
SkausWatch AAA Monitor Service - STIX Parser

STIX 2.1 parser for processing threat intelligence objects and
converting them to internal IOC format.
"""

import json
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Any, Union, Tuple
from urllib.parse import urlparse
import ipaddress

import structlog
import stix2
from stix2 import MemoryStore
from stix2.utils import new_version

from ..models import IOC, ThreatLevel

logger = structlog.get_logger(__name__)


class STIXParser:
    """Advanced STIX 2.1 parser with full object support and MITRE ATT&CK mapping"""
    
    def __init__(self):
        """Initialize enhanced STIX parser"""
        # STIX object type mappings with comprehensive support
        self.stix_to_ioc_mapping = {
            'indicator': self._parse_indicator,
            'malware': self._parse_malware,
            'malware-analysis': self._parse_malware_analysis,
            'attack-pattern': self._parse_attack_pattern,
            'threat-actor': self._parse_threat_actor,
            'intrusion-set': self._parse_intrusion_set,
            'campaign': self._parse_campaign,
            'course-of-action': self._parse_course_of_action,
            'vulnerability': self._parse_vulnerability,
            'tool': self._parse_tool,
            'infrastructure': self._parse_infrastructure,
            'location': self._parse_location,
            'identity': self._parse_identity,
            'observed-data': self._parse_observed_data,
            'sighting': self._parse_sighting,
            'grouping': self._parse_grouping,
            'note': self._parse_note,
            'opinion': self._parse_opinion
        }
        
        # Enhanced STIX 2.1 memory store for relationship resolution
        self.stix_store = MemoryStore()
        
        # MITRE ATT&CK framework mapping
        self.mitre_attack_mapping = self._initialize_attack_mapping()
        
        # Cyber Kill Chain mapping
        self.kill_chain_mapping = {
            'reconnaissance': 'reconnaissance',
            'weaponization': 'weaponization',
            'delivery': 'delivery',
            'exploitation': 'exploitation',
            'installation': 'installation',
            'command-and-control': 'command-and-control',
            'actions-on-objectives': 'actions-on-objectives'
        }
        
        # Comprehensive SCO (STIX Cyber Observable) mappings for STIX 2.1
        self.sco_mappings = {
            'file': self._extract_file_observables,
            'ipv4-addr': self._extract_ip_observables,
            'ipv6-addr': self._extract_ip_observables,
            'domain-name': self._extract_domain_observables,
            'url': self._extract_url_observables,
            'email-addr': self._extract_email_observables,
            'email-message': self._extract_email_message_observables,
            'user-account': self._extract_user_observables,
            'process': self._extract_process_observables,
            'registry-key': self._extract_registry_observables,
            'network-traffic': self._extract_network_observables,
            'artifact': self._extract_artifact_observables,
            'autonomous-system': self._extract_as_observables,
            'directory': self._extract_directory_observables,
            'mutex': self._extract_mutex_observables,
            'software': self._extract_software_observables,
            'windows-registry-key': self._extract_windows_registry_observables,
            'x509-certificate': self._extract_certificate_observables,
            'mac-addr': self._extract_mac_observables
        }
        
        # Enhanced pattern parsing with STIX 2.1 pattern syntax
        self.pattern_parsers = {
            'comparison': self._parse_comparison_expression,
            'observation': self._parse_observation_expression,
            'compound': self._parse_compound_expression
        }
        
        # Statistics and metrics
        self.parsing_stats = {
            'objects_parsed': 0,
            'indicators_extracted': 0,
            'relationships_resolved': 0,
            'attack_patterns_mapped': 0,
            'observables_extracted': 0,
            'parsing_errors': 0
        }
        
        # Enhanced threat level mappings with STIX labels
        self.threat_level_mappings = {
            # Standard threat levels
            'high': ThreatLevel.HIGH,
            'medium': ThreatLevel.MEDIUM,
            'low': ThreatLevel.LOW,
            'informational': ThreatLevel.LOW,
            'unknown': ThreatLevel.UNKNOWN,
            # STIX indicator labels
            'malicious-activity': ThreatLevel.HIGH,
            'attribution': ThreatLevel.MEDIUM,
            'anomalous-activity': ThreatLevel.MEDIUM,
            'benign': ThreatLevel.LOW,
            # Additional severity mappings
            'critical': ThreatLevel.HIGH,
            'severe': ThreatLevel.HIGH,
            'moderate': ThreatLevel.MEDIUM,
            'minor': ThreatLevel.LOW
        }
    
    def _initialize_attack_mapping(self) -> Dict[str, Any]:
        """Initialize MITRE ATT&CK framework mapping"""
        return {
            'tactics': {
                'reconnaissance': 'TA0043',
                'resource-development': 'TA0042',
                'initial-access': 'TA0001',
                'execution': 'TA0002',
                'persistence': 'TA0003',
                'privilege-escalation': 'TA0004',
                'defense-evasion': 'TA0005',
                'credential-access': 'TA0006',
                'discovery': 'TA0007',
                'lateral-movement': 'TA0008',
                'collection': 'TA0009',
                'command-and-control': 'TA0011',
                'exfiltration': 'TA0010',
                'impact': 'TA0040'
            },
            'common_techniques': {
                # Common technique mappings for quick reference
                'T1566': 'Phishing',
                'T1059': 'Command and Scripting Interpreter',
                'T1055': 'Process Injection',
                'T1027': 'Obfuscated Files or Information',
                'T1021': 'Remote Services',
                'T1053': 'Scheduled Task/Job',
                'T1105': 'Ingress Tool Transfer',
                'T1572': 'Protocol Tunneling',
                'T1041': 'Exfiltration Over C2 Channel',
                'T1486': 'Data Encrypted for Impact'
            }
        }

    async def parse_content(self, content: str, context: Optional[Dict[str, Any]] = None) -> List[IOC]:
        """Enhanced STIX content parsing with relationship resolution and context
        
        Args:
            content: STIX content (JSON or XML)
            context: Optional parsing context for enhanced processing
            
        Returns:
            List of extracted IOCs with enriched metadata
        """
        try:
            # Update parsing statistics
            self.parsing_stats['objects_parsed'] += 1
            
            # Determine content type and parse accordingly
            content = content.strip()
            
            if content.startswith('{') or content.startswith('['):
                # JSON format - enhanced parsing
                iocs = await self._parse_json_content_enhanced(content, context)
            elif content.startswith('<'):
                # XML format - enhanced parsing
                iocs = await self._parse_xml_content_enhanced(content, context)
            else:
                logger.error("Unknown STIX content format")
                self.parsing_stats['parsing_errors'] += 1
                return []
            
            # Post-process IOCs with relationship resolution
            if iocs:
                iocs = await self._post_process_iocs(iocs, context)
            
            self.parsing_stats['indicators_extracted'] += len(iocs)
            
            return iocs
                
        except Exception as e:
            logger.error("Error parsing STIX content", error=str(e))
            self.parsing_stats['parsing_errors'] += 1
            return []

    async def _parse_json_content(self, content: str) -> List[IOC]:
        """Parse JSON STIX content"""
        try:
            data = json.loads(content)
            
            if isinstance(data, dict):
                if data.get('type') == 'bundle':
                    return await self.parse_stix_bundle(data)
                else:
                    # Single STIX object
                    ioc = await self._parse_stix_object(data)
                    return [ioc] if ioc else []
            
            elif isinstance(data, list):
                # Array of STIX objects
                iocs = []
                for obj in data:
                    ioc = await self._parse_stix_object(obj)
                    if ioc:
                        iocs.append(ioc)
                return iocs
            
            return []
            
        except Exception as e:
            logger.error("Error parsing JSON STIX content", error=str(e))
            return []

    async def _parse_xml_content(self, content: str) -> List[IOC]:
        """Parse XML STIX content"""
        try:
            # Parse XML
            root = ET.fromstring(content)
            
            # Extract STIX objects from XML
            # This is a simplified parser - full STIX XML parsing is complex
            iocs = []
            
            # Look for indicators
            for indicator in root.iter():
                if 'indicator' in indicator.tag.lower():
                    ioc = await self._parse_xml_indicator(indicator)
                    if ioc:
                        iocs.append(ioc)
            
            return iocs
            
        except Exception as e:
            logger.error("Error parsing XML STIX content", error=str(e))
            return []

    async def parse_stix_bundle(self, bundle: Dict[str, Any]) -> List[IOC]:
        """Parse STIX bundle and extract IOCs"""
        try:
            iocs = []
            
            objects = bundle.get('objects', [])
            
            for obj in objects:
                ioc = await self._parse_stix_object(obj)
                if ioc:
                    iocs.append(ioc)
            
            logger.debug("STIX bundle parsed", 
                        objects_processed=len(objects),
                        iocs_extracted=len(iocs))
            
            return iocs
            
        except Exception as e:
            logger.error("Error parsing STIX bundle", error=str(e))
            return []

    async def _parse_stix_object(self, obj: Dict[str, Any]) -> Optional[IOC]:
        """Parse individual STIX object"""
        try:
            obj_type = obj.get('type')
            
            if not obj_type:
                return None
            
            # Get parser for object type
            parser = self.stix_to_ioc_mapping.get(obj_type)
            
            if parser:
                return await parser(obj)
            else:
                logger.debug("Unsupported STIX object type", type=obj_type)
                return None
                
        except Exception as e:
            logger.error("Error parsing STIX object", error=str(e))
            return None

    async def _parse_indicator(self, obj: Dict[str, Any]) -> Optional[IOC]:
        """Parse STIX indicator object"""
        try:
            # Extract basic information
            pattern = obj.get('pattern', '')
            description = obj.get('description', '')
            labels = obj.get('labels', [])
            
            # Extract threat level from labels or kill chain phases
            threat_level = self._extract_threat_level(obj)
            
            # Extract confidence
            confidence = obj.get('confidence', 0) / 100.0 if obj.get('confidence') else 0.5
            
            # Extract observables from pattern
            observables = await self._parse_indicator_pattern(pattern)
            
            # Create IOCs for each observable
            iocs = []
            for observable in observables:
                ioc = IOC(
                    type=observable['type'],
                    value=observable['value'],
                    description=description,
                    threat_level=threat_level,
                    confidence=confidence,
                    tags=labels,
                    malware_families=self._extract_malware_families(obj),
                    kill_chain_phases=self._extract_kill_chain_phases(obj)
                )
                iocs.append(ioc)
            
            # If no observables extracted, create generic IOC
            if not iocs and pattern:
                ioc = IOC(
                    type='pattern',
                    value=pattern,
                    description=description,
                    threat_level=threat_level,
                    confidence=confidence,
                    tags=labels,
                    malware_families=self._extract_malware_families(obj),
                    kill_chain_phases=self._extract_kill_chain_phases(obj)
                )
                iocs.append(ioc)
            
            return iocs[0] if iocs else None
            
        except Exception as e:
            logger.error("Error parsing STIX indicator", error=str(e))
            return None

    async def _parse_indicator_pattern(self, pattern: str) -> List[Dict[str, str]]:
        """Parse STIX indicator pattern to extract observables"""
        try:
            observables = []
            
            # STIX patterns use a special syntax: [observable:property = 'value']
            # Extract different types of observables
            
            # IP addresses
            ip_matches = re.findall(r"ipv[46]-addr:value\s*=\s*'([^']+)'", pattern)
            for ip in ip_matches:
                observables.append({'type': 'ip', 'value': ip})
            
            # Domain names
            domain_matches = re.findall(r"domain-name:value\s*=\s*'([^']+)'", pattern)
            for domain in domain_matches:
                observables.append({'type': 'domain', 'value': domain})
            
            # URLs
            url_matches = re.findall(r"url:value\s*=\s*'([^']+)'", pattern)
            for url in url_matches:
                observables.append({'type': 'url', 'value': url})
            
            # File hashes
            hash_matches = re.findall(r"file:hashes\.(\w+)\s*=\s*'([^']+)'", pattern)
            for hash_type, hash_value in hash_matches:
                observables.append({'type': f'hash-{hash_type.lower()}', 'value': hash_value})
            
            # Email addresses
            email_matches = re.findall(r"email-addr:value\s*=\s*'([^']+)'", pattern)
            for email in email_matches:
                observables.append({'type': 'email', 'value': email})
            
            # Registry keys
            reg_matches = re.findall(r"windows-registry-key:key\s*=\s*'([^']+)'", pattern)
            for reg_key in reg_matches:
                observables.append({'type': 'registry', 'value': reg_key})
            
            return observables
            
        except Exception as e:
            logger.error("Error parsing indicator pattern", pattern=pattern, error=str(e))
            return []

    async def _parse_malware(self, obj: Dict[str, Any]) -> Optional[IOC]:
        """Parse STIX malware object"""
        try:
            name = obj.get('name', '')
            description = obj.get('description', '')
            labels = obj.get('labels', [])
            
            if not name:
                return None
            
            return IOC(
                type='malware',
                value=name,
                description=description,
                threat_level=ThreatLevel.HIGH,
                confidence=0.8,
                tags=labels,
                malware_families=[name],
                kill_chain_phases=self._extract_kill_chain_phases(obj)
            )
            
        except Exception as e:
            logger.error("Error parsing STIX malware", error=str(e))
            return None

    async def _parse_attack_pattern(self, obj: Dict[str, Any]) -> Optional[IOC]:
        """Parse STIX attack pattern object"""
        try:
            name = obj.get('name', '')
            description = obj.get('description', '')
            
            # Extract MITRE ATT&CK technique ID if available
            external_refs = obj.get('external_references', [])
            technique_id = None
            
            for ref in external_refs:
                if ref.get('source_name') == 'mitre-attack':
                    technique_id = ref.get('external_id')
                    break
            
            if not name and not technique_id:
                return None
            
            value = technique_id or name
            
            return IOC(
                type='attack-pattern',
                value=value,
                description=description,
                threat_level=ThreatLevel.MEDIUM,
                confidence=0.7,
                tags=['attack-pattern', 'mitre-attack'] if technique_id else ['attack-pattern'],
                kill_chain_phases=self._extract_kill_chain_phases(obj)
            )
            
        except Exception as e:
            logger.error("Error parsing STIX attack pattern", error=str(e))
            return None

    async def _parse_threat_actor(self, obj: Dict[str, Any]) -> Optional[IOC]:
        """Parse STIX threat actor object"""
        try:
            name = obj.get('name', '')
            description = obj.get('description', '')
            labels = obj.get('labels', [])
            aliases = obj.get('aliases', [])
            
            if not name:
                return None
            
            return IOC(
                type='threat-actor',
                value=name,
                description=description,
                threat_level=ThreatLevel.HIGH,
                confidence=0.8,
                tags=labels + aliases,
                kill_chain_phases=self._extract_kill_chain_phases(obj)
            )
            
        except Exception as e:
            logger.error("Error parsing STIX threat actor", error=str(e))
            return None

    async def _parse_intrusion_set(self, obj: Dict[str, Any]) -> Optional[IOC]:
        """Parse STIX intrusion set object"""
        try:
            name = obj.get('name', '')
            description = obj.get('description', '')
            aliases = obj.get('aliases', [])
            
            if not name:
                return None
            
            return IOC(
                type='intrusion-set',
                value=name,
                description=description,
                threat_level=ThreatLevel.HIGH,
                confidence=0.8,
                tags=aliases,
                kill_chain_phases=self._extract_kill_chain_phases(obj)
            )
            
        except Exception as e:
            logger.error("Error parsing STIX intrusion set", error=str(e))
            return None

    async def _parse_campaign(self, obj: Dict[str, Any]) -> Optional[IOC]:
        """Parse STIX campaign object"""
        try:
            name = obj.get('name', '')
            description = obj.get('description', '')
            aliases = obj.get('aliases', [])
            
            if not name:
                return None
            
            return IOC(
                type='campaign',
                value=name,
                description=description,
                threat_level=ThreatLevel.MEDIUM,
                confidence=0.7,
                tags=aliases
            )
            
        except Exception as e:
            logger.error("Error parsing STIX campaign", error=str(e))
            return None

    async def _parse_course_of_action(self, obj: Dict[str, Any]) -> Optional[IOC]:
        """Parse STIX course of action object"""
        try:
            name = obj.get('name', '')
            description = obj.get('description', '')
            
            if not name:
                return None
            
            return IOC(
                type='course-of-action',
                value=name,
                description=description,
                threat_level=ThreatLevel.LOW,
                confidence=0.6,
                tags=['course-of-action', 'mitigation']
            )
            
        except Exception as e:
            logger.error("Error parsing STIX course of action", error=str(e))
            return None

    async def _parse_vulnerability(self, obj: Dict[str, Any]) -> Optional[IOC]:
        """Parse STIX vulnerability object"""
        try:
            name = obj.get('name', '')
            description = obj.get('description', '')
            
            # Extract CVE ID if available
            external_refs = obj.get('external_references', [])
            cve_id = None
            
            for ref in external_refs:
                if ref.get('source_name') == 'cve':
                    cve_id = ref.get('external_id')
                    break
            
            if not name and not cve_id:
                return None
            
            value = cve_id or name
            
            return IOC(
                type='vulnerability',
                value=value,
                description=description,
                threat_level=ThreatLevel.MEDIUM,
                confidence=0.8,
                tags=['vulnerability', 'cve'] if cve_id else ['vulnerability']
            )
            
        except Exception as e:
            logger.error("Error parsing STIX vulnerability", error=str(e))
            return None

    async def _parse_xml_indicator(self, element: ET.Element) -> Optional[IOC]:
        """Parse XML indicator element"""
        try:
            # Extract observable from XML - simplified implementation
            observables = []
            
            # Look for common observable types in XML
            for child in element:
                if 'observable' in child.tag.lower():
                    obs_type, obs_value = self._extract_xml_observable(child)
                    if obs_type and obs_value:
                        observables.append({'type': obs_type, 'value': obs_value})
            
            if not observables:
                return None
            
            # Create IOC from first observable
            obs = observables[0]
            
            return IOC(
                type=obs['type'],
                value=obs['value'],
                description=element.get('description', ''),
                threat_level=ThreatLevel.MEDIUM,
                confidence=0.5,
                tags=['xml-indicator']
            )
            
        except Exception as e:
            logger.error("Error parsing XML indicator", error=str(e))
            return None

    def _extract_xml_observable(self, element: ET.Element) -> tuple[Optional[str], Optional[str]]:
        """Extract observable type and value from XML element"""
        try:
            # Look for different observable types
            for child in element:
                tag = child.tag.lower()
                
                if 'address' in tag:
                    return 'ip', child.text
                elif 'domain' in tag:
                    return 'domain', child.text
                elif 'uri' in tag or 'url' in tag:
                    return 'url', child.text
                elif 'hash' in tag:
                    return 'hash', child.text
                elif 'email' in tag:
                    return 'email', child.text
            
            return None, None
            
        except Exception as e:
            logger.error("Error extracting XML observable", error=str(e))
            return None, None

    def _extract_threat_level(self, obj: Dict[str, Any]) -> ThreatLevel:
        """Extract threat level from STIX object"""
        try:
            # Check labels for threat level indicators
            labels = obj.get('labels', [])
            
            for label in labels:
                label_lower = label.lower()
                if 'high' in label_lower or 'critical' in label_lower:
                    return ThreatLevel.HIGH
                elif 'medium' in label_lower or 'moderate' in label_lower:
                    return ThreatLevel.MEDIUM
                elif 'low' in label_lower:
                    return ThreatLevel.LOW
            
            # Check kill chain phases for threat level
            kill_chains = obj.get('kill_chain_phases', [])
            if kill_chains:
                # Later phases in kill chain typically indicate higher threat
                phase_names = [kc.get('phase_name', '') for kc in kill_chains]
                
                if any(phase in ['actions-on-objectives', 'command-and-control'] for phase in phase_names):
                    return ThreatLevel.HIGH
                elif any(phase in ['exploitation', 'installation'] for phase in phase_names):
                    return ThreatLevel.MEDIUM
            
            # Default based on object type
            obj_type = obj.get('type', '')
            if obj_type in ['malware', 'threat-actor', 'intrusion-set']:
                return ThreatLevel.HIGH
            elif obj_type in ['indicator', 'attack-pattern']:
                return ThreatLevel.MEDIUM
            
            return ThreatLevel.UNKNOWN
            
        except Exception as e:
            logger.error("Error extracting threat level", error=str(e))
            return ThreatLevel.UNKNOWN

    def _extract_malware_families(self, obj: Dict[str, Any]) -> List[str]:
        """Extract malware families from STIX object"""
        try:
            families = []
            
            # Check labels for malware family indicators
            labels = obj.get('labels', [])
            for label in labels:
                if 'malware' in label.lower():
                    families.append(label)
            
            # Check if this is a malware object
            if obj.get('type') == 'malware':
                name = obj.get('name')
                if name:
                    families.append(name)
            
            return families
            
        except Exception as e:
            logger.error("Error extracting malware families", error=str(e))
            return []

    def _extract_kill_chain_phases(self, obj: Dict[str, Any]) -> List[str]:
        """Extract kill chain phases from STIX object"""
        try:
            phases = []
            
            kill_chains = obj.get('kill_chain_phases', [])
            for kc in kill_chains:
                phase_name = kc.get('phase_name')
                if phase_name:
                    phases.append(phase_name)
            
            return phases
            
        except Exception as e:
            logger.error("Error extracting kill chain phases", error=str(e))
            return []

    # Observable extraction methods (placeholders for more complex parsing)
    def _extract_file_observables(self, obj: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract file observables"""
        return []

    def _extract_ip_observables(self, obj: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract IP observables"""
        return []

    def _extract_domain_observables(self, obj: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract domain observables"""
        return []

    def _extract_url_observables(self, obj: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract URL observables"""
        return []

    def _extract_email_observables(self, obj: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract email observables"""
        return []

    def _extract_user_observables(self, obj: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract user account observables"""
        return []

    def _extract_process_observables(self, obj: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract process observables"""
        return []

    def _extract_registry_observables(self, obj: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract registry observables"""
        return []

    def _extract_network_observables(self, obj: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract network traffic observables"""
        return []
    
    # Enhanced parsing methods for STIX 2.1
    
    async def _parse_json_content_enhanced(self, content: str, context: Optional[Dict[str, Any]]) -> List[IOC]:
        """Enhanced JSON STIX content parsing with full STIX 2.1 support"""
        try:
            data = json.loads(content)
            
            # Store objects in memory store for relationship resolution
            if isinstance(data, dict) and data.get('type') == 'bundle':
                for obj in data.get('objects', []):
                    try:
                        # Use STIX2 library to validate and store
                        stix_obj = stix2.parse(obj, allow_custom=True)
                        self.stix_store.add(stix_obj)
                    except Exception as e:
                        logger.warning("Failed to parse STIX object", error=str(e), obj_type=obj.get('type'))
                
                return await self.parse_stix_bundle_enhanced(data, context)
            
            elif isinstance(data, dict):
                # Single STIX object
                try:
                    stix_obj = stix2.parse(data, allow_custom=True)
                    self.stix_store.add(stix_obj)
                    ioc = await self._parse_stix_object_enhanced(data, context)
                    return [ioc] if ioc else []
                except Exception as e:
                    logger.error("Failed to parse single STIX object", error=str(e))
                    return []
            
            elif isinstance(data, list):
                # Array of STIX objects
                iocs = []
                for obj in data:
                    try:
                        stix_obj = stix2.parse(obj, allow_custom=True)
                        self.stix_store.add(stix_obj)
                        ioc = await self._parse_stix_object_enhanced(obj, context)
                        if ioc:
                            iocs.append(ioc)
                    except Exception as e:
                        logger.warning("Failed to parse array STIX object", error=str(e))
                return iocs
            
            return []
            
        except Exception as e:
            logger.error("Error parsing enhanced JSON STIX content", error=str(e))
            return []
    
    async def parse_stix_bundle_enhanced(self, bundle: Dict[str, Any], context: Optional[Dict[str, Any]]) -> List[IOC]:
        """Enhanced STIX bundle parsing with relationship resolution"""
        try:
            iocs = []
            relationships = []
            
            objects = bundle.get('objects', [])
            
            # First pass: parse all objects
            for obj in objects:
                if obj.get('type') == 'relationship':
                    relationships.append(obj)
                else:
                    ioc = await self._parse_stix_object_enhanced(obj, context)
                    if ioc:
                        iocs.append(ioc)
            
            # Second pass: resolve relationships
            if relationships:
                iocs = await self._resolve_relationships(iocs, relationships, context)
                self.parsing_stats['relationships_resolved'] += len(relationships)
            
            logger.debug("Enhanced STIX bundle parsed", 
                        objects_processed=len(objects),
                        iocs_extracted=len(iocs),
                        relationships_resolved=len(relationships))
            
            return iocs
            
        except Exception as e:
            logger.error("Error parsing enhanced STIX bundle", error=str(e))
            return []
    
    async def _parse_stix_object_enhanced(self, obj: Dict[str, Any], context: Optional[Dict[str, Any]]) -> Optional[IOC]:
        """Enhanced STIX object parsing with full 2.1 support"""
        try:
            obj_type = obj.get('type')
            
            if not obj_type:
                return None
            
            # Get enhanced parser for object type
            parser = self.stix_to_ioc_mapping.get(obj_type)
            
            if parser:
                # Pass context to parser if it supports it
                try:
                    ioc = await parser(obj, context) if context else await parser(obj)
                except TypeError:
                    # Fallback for parsers that don't support context
                    ioc = await parser(obj)
                
                if ioc:
                    # Enrich with MITRE ATT&CK mapping if applicable
                    ioc = await self._enrich_with_attack_mapping(ioc, obj, context)
                return ioc
            else:
                logger.debug("Unsupported STIX object type", type=obj_type)
                return None
                
        except Exception as e:
            logger.error("Error parsing enhanced STIX object", error=str(e))
            return None
    
    async def _enrich_with_attack_mapping(self, ioc: IOC, obj: Dict[str, Any], context: Optional[Dict[str, Any]]) -> IOC:
        """Enrich IOC with MITRE ATT&CK framework mapping"""
        try:
            # Check for MITRE ATT&CK external references
            external_refs = obj.get('external_references', [])
            attack_refs = []
            
            for ref in external_refs:
                source_name = ref.get('source_name', '').lower()
                if 'mitre' in source_name or 'attack' in source_name:
                    external_id = ref.get('external_id')
                    if external_id:
                        attack_refs.append({
                            'technique_id': external_id,
                            'technique_name': self.mitre_attack_mapping['common_techniques'].get(external_id),
                            'url': ref.get('url'),
                            'description': ref.get('description')
                        })
            
            # Add ATT&CK information to IOC tags
            if attack_refs:
                for ref in attack_refs:
                    if ref['technique_id']:
                        ioc.tags.append(f"mitre-attack:{ref['technique_id']}")
                    if ref['technique_name']:
                        ioc.tags.append(f"technique:{ref['technique_name'].lower().replace(' ', '-')}")
                
                self.parsing_stats['attack_patterns_mapped'] += 1
            
            # Map kill chain phases to tactics
            kill_chains = obj.get('kill_chain_phases', [])
            for kc in kill_chains:
                kill_chain_name = kc.get('kill_chain_name', '').lower()
                phase_name = kc.get('phase_name', '').lower()
                
                if 'mitre-attack' in kill_chain_name:
                    tactic_id = self.mitre_attack_mapping['tactics'].get(phase_name)
                    if tactic_id:
                        ioc.tags.append(f"mitre-tactic:{tactic_id}")
                        ioc.tags.append(f"tactic:{phase_name}")
            
            return ioc
            
        except Exception as e:
            logger.error("Error enriching with ATT&CK mapping", error=str(e))
            return ioc
    
    def get_parsing_statistics(self) -> Dict[str, Any]:
        """Get parsing statistics"""
        return self.parsing_stats.copy()
    
    def reset_statistics(self):
        """Reset parsing statistics"""
        self.parsing_stats = {
            'objects_parsed': 0,
            'indicators_extracted': 0,
            'relationships_resolved': 0,
            'attack_patterns_mapped': 0,
            'observables_extracted': 0,
            'parsing_errors': 0
        }