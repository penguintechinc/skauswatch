"""
Research service orchestration module.

Coordinates all lookup clients to perform comprehensive threat research
and indicator analysis. Main entry point for research operations.
"""

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import structlog

from .asn_client import ASNClient
from .dns_client import DNSClient
from .indicator_classifier import IndicatorClassifier
from .maltego_client import MaltegoClient
from .shodan_client import ShodanClient
from .whois_client import WhoisClient
from validators.research_models import (
    AsnResult,
    DnsResult,
    IndicatorType,
    MaltegoResult,
    ResearchLookupRequest,
    ResearchLookupResponse,
    ResearchSummary,
    ShodanResult,
    ThreatIntelResult,
    WhoisResult,
)

logger = structlog.get_logger()


@dataclass(slots=True)
class ResearchService:
    """
    Main orchestration service for threat research operations.

    Coordinates DNS, WHOIS, ASN, Shodan, Maltego, and threat intelligence
    lookups to provide comprehensive indicator analysis.
    """

    classifier: IndicatorClassifier
    dns_client: DNSClient
    whois_client: WhoisClient
    asn_client: ASNClient
    shodan_client: ShodanClient
    maltego_client: MaltegoClient
    feed_aggregator: Optional[object] = None

    def __init__(self, config: dict) -> None:
        """
        Initialize research service with all clients.

        Args:
            config: Configuration dictionary with client settings.
                Expected keys:
                - dns_timeout (int): DNS query timeout in seconds
                - whois_timeout (int): WHOIS query timeout in seconds
                - asn_timeout (int): ASN query timeout in seconds
                - shodan_api_key (str): Shodan API key
                - shodan_enabled (bool): Enable Shodan lookups
                - maltego_trx_server (str): Maltego TRX server URL
                - maltego_enabled (bool): Enable Maltego lookups
        """
        logger.info("initializing_research_service", config_keys=list(config.keys()))

        self.classifier = IndicatorClassifier()
        self.dns_client = DNSClient(timeout=config.get("dns_timeout", 5))
        self.whois_client = WhoisClient(timeout=config.get("whois_timeout", 10))
        self.asn_client = ASNClient(timeout=config.get("asn_timeout", 5))
        self.shodan_client = ShodanClient(
            api_key=config.get("shodan_api_key", ""),
            enabled=config.get("shodan_enabled", False),
        )
        self.maltego_client = MaltegoClient(
            trx_server=config.get("maltego_trx_server", ""),
            enabled=config.get("maltego_enabled", False),
        )
        self.feed_aggregator = None

        logger.info(
            "research_service_initialized",
            shodan_enabled=self.shodan_client.enabled,
            maltego_enabled=self.maltego_client.enabled,
        )

    async def lookup(self, request: ResearchLookupRequest) -> ResearchLookupResponse:
        """
        Perform comprehensive indicator lookup.

        Args:
            request: Research lookup request with query and options.

        Returns:
            Complete research response with all available data.
        """
        start_time = time.time()

        logger.info(
            "research_lookup_started",
            query=request.query,
            indicator_type=request.indicator_type,
            include_threat_intel=request.include_threat_intel,
            include_shodan=request.include_shodan,
            include_maltego=request.include_maltego,
        )

        # Step 1: Classify indicator type if not provided
        if request.indicator_type:
            indicator_type_str = request.indicator_type.value
            normalized_value = request.query
        else:
            indicator_type_str, normalized_value = self.classifier.classify(request.query)

        if indicator_type_str == "Unknown":
            logger.warning("unknown_indicator_type", query=request.query)
            # Return minimal response for unknown type
            return ResearchLookupResponse(
                query=request.query,
                indicator_type=IndicatorType.DOMAIN,  # Default fallback
                timestamp=datetime.utcnow(),
                summary=ResearchSummary(
                    indicator_type=IndicatorType.DOMAIN,
                    risk_score=0,
                    key_findings=["Unknown indicator type"],
                ),
                processing_time_ms=int((time.time() - start_time) * 1000),
            )

        # Map classifier types to IndicatorType enum
        indicator_type = self._map_indicator_type(indicator_type_str)

        logger.info(
            "indicator_classified",
            original=request.query,
            normalized=normalized_value,
            type=indicator_type_str,
        )

        # Step 2: Run lookups in parallel
        tasks = []
        tasks.append(self._lookup_whois(indicator_type_str, normalized_value))
        tasks.append(self._lookup_dns(indicator_type_str, normalized_value))
        tasks.append(self._lookup_asn(indicator_type_str, normalized_value))

        if request.include_shodan:
            tasks.append(self._lookup_shodan(indicator_type_str, normalized_value))
        else:
            tasks.append(asyncio.sleep(0, result=None))

        if request.include_maltego:
            tasks.append(self._lookup_maltego(indicator_type_str, normalized_value))
        else:
            tasks.append(asyncio.sleep(0, result=None))

        if request.include_threat_intel:
            tasks.append(self._check_threat_intel(indicator_type_str, normalized_value))
        else:
            tasks.append(asyncio.sleep(0, result=None))

        # Gather all results
        results = await asyncio.gather(*tasks, return_exceptions=True)

        whois_result = results[0] if not isinstance(results[0], Exception) else None
        dns_result = results[1] if not isinstance(results[1], Exception) else None
        asn_result = results[2] if not isinstance(results[2], Exception) else None
        shodan_result = results[3] if not isinstance(results[3], Exception) else None
        maltego_result = results[4] if not isinstance(results[4], Exception) else None
        threat_intel_result = results[5] if not isinstance(results[5], Exception) else None

        # Step 3: Build results dictionary
        all_results = {
            "whois": whois_result,
            "dns": dns_result,
            "asn": asn_result,
            "shodan": shodan_result,
            "maltego": maltego_result,
            "threat_intel": threat_intel_result,
        }

        # Step 4: Calculate risk score
        risk_score = self._calculate_risk_score(all_results)

        # Step 5: Generate summary findings
        key_findings = self._generate_findings(all_results)

        # Step 6: Build complete response
        processing_time_ms = int((time.time() - start_time) * 1000)

        logger.info(
            "research_lookup_completed",
            query=normalized_value,
            risk_score=risk_score,
            findings_count=len(key_findings),
            processing_time_ms=processing_time_ms,
        )

        return ResearchLookupResponse(
            query=normalized_value,
            indicator_type=indicator_type,
            timestamp=datetime.utcnow(),
            summary=ResearchSummary(
                indicator_type=indicator_type,
                risk_score=risk_score,
                key_findings=key_findings,
            ),
            whois=whois_result,
            dns=dns_result,
            asn=asn_result,
            shodan=shodan_result,
            maltego=maltego_result,
            threat_intel=threat_intel_result,
            processing_time_ms=processing_time_ms,
        )

    async def _lookup_whois(
        self, indicator_type: str, value: str
    ) -> Optional[WhoisResult]:
        """
        Perform WHOIS lookup if applicable.

        Args:
            indicator_type: Classified indicator type.
            value: Normalized indicator value.

        Returns:
            WhoisResult or None.
        """
        if indicator_type not in ["IPv4", "IPv6", "Domain"]:
            return None

        try:
            result = await self.whois_client.lookup(value)
            return WhoisResult(
                registrar=result.registrar,
                creation_date=result.creation_date,
                expiration_date=result.expiration_date,
                updated_date=result.updated_date,
                nameservers=result.nameservers,
                registrant=result.registrant,
                raw_data=result.raw_data,
            )
        except Exception as e:
            logger.error("whois_lookup_failed", value=value, error=str(e))
            return None

    async def _lookup_dns(self, indicator_type: str, value: str) -> Optional[DnsResult]:
        """
        Perform DNS lookup if applicable.

        Args:
            indicator_type: Classified indicator type.
            value: Normalized indicator value.

        Returns:
            DnsResult or None.
        """
        if indicator_type not in ["Domain", "IPv4", "IPv6"]:
            return None

        try:
            # For IP addresses, do reverse lookup
            if indicator_type in ["IPv4", "IPv6"]:
                hostname = await self.dns_client.reverse_lookup(value)
                if hostname:
                    # Now lookup the hostname
                    result = await self.dns_client.lookup(hostname)
                else:
                    return None
            else:
                result = await self.dns_client.lookup(value)

            return DnsResult(
                a_records=result.a_records,
                aaaa_records=result.aaaa_records,
                mx_records=result.mx_records,
                ns_records=result.ns_records,
                txt_records=result.txt_records,
                cname_records=[result.cname_record] if result.cname_record else [],
                soa_record=result.soa_record,
            )
        except Exception as e:
            logger.error("dns_lookup_failed", value=value, error=str(e))
            return None

    async def _lookup_asn(self, indicator_type: str, value: str) -> Optional[AsnResult]:
        """
        Perform ASN lookup if applicable.

        Args:
            indicator_type: Classified indicator type.
            value: Normalized indicator value.

        Returns:
            AsnResult or None.
        """
        if indicator_type not in ["IPv4", "IPv6", "ASN"]:
            return None

        try:
            result = await self.asn_client.lookup(value)
            return AsnResult(
                asn=result.asn,
                organization=result.organization,
                country=result.country,
                network=result.network,
                registry=result.registry,
                description=result.description,
            )
        except Exception as e:
            logger.error("asn_lookup_failed", value=value, error=str(e))
            return None

    async def _lookup_shodan(
        self, indicator_type: str, value: str
    ) -> Optional[ShodanResult]:
        """
        Perform Shodan lookup if enabled and applicable.

        Args:
            indicator_type: Classified indicator type.
            value: Normalized indicator value.

        Returns:
            ShodanResult or None.
        """
        if not self.shodan_client.enabled or indicator_type not in ["IPv4", "IPv6"]:
            return None

        try:
            result = await self.shodan_client.lookup(value)
            return ShodanResult(
                ip=result.ip,
                ports=result.ports,
                services=result.services,
                vulns=result.vulns,
                ssl_cert=result.ssl_cert,
                last_update=result.last_update,
            )
        except Exception as e:
            logger.error("shodan_lookup_failed", value=value, error=str(e))
            return None

    async def _lookup_maltego(
        self, indicator_type: str, value: str
    ) -> Optional[MaltegoResult]:
        """
        Perform Maltego lookup if enabled and applicable.

        Args:
            indicator_type: Classified indicator type.
            value: Normalized indicator value.

        Returns:
            MaltegoResult or None.
        """
        if not self.maltego_client.enabled:
            return None

        try:
            result = await self.maltego_client.lookup(value)
            return MaltegoResult(
                related_domains=result.related_domains,
                emails=result.emails,
                social_profiles=result.social_profiles,
                shared_hosting=result.shared_hosting,
                infrastructure=result.infrastructure,
            )
        except Exception as e:
            logger.error("maltego_lookup_failed", value=value, error=str(e))
            return None

    async def _check_threat_intel(
        self, indicator_type: str, value: str
    ) -> Optional[ThreatIntelResult]:
        """
        Check threat intelligence feeds if available.

        Args:
            indicator_type: Classified indicator type.
            value: Normalized indicator value.

        Returns:
            ThreatIntelResult or None.
        """
        if not self.feed_aggregator:
            return None

        try:
            # Assume feed_aggregator has a check_indicator method
            result = await self.feed_aggregator.check_indicator(value)

            return ThreatIntelResult(
                virustotal_malicious=result.get("vt_malicious", 0),
                virustotal_total=result.get("vt_total", 0),
                otx_pulses=result.get("otx_pulses", 0),
                dns_blacklist_hits=result.get("blacklist_hits", []),
                local_ioc_match=result.get("local_match", False),
            )
        except Exception as e:
            logger.error("threat_intel_check_failed", value=value, error=str(e))
            return None

    def _calculate_risk_score(self, results: dict) -> int:
        """
        Calculate risk score based on all lookup results.

        Scoring breakdown:
        - Threat intel (max 90):
            - VT malicious detections * 5 (max 40)
            - OTX pulses * 3 (max 20)
            - Blacklist hits * 10 (max 30)
        - Domain age (max 15):
            - < 30 days: +15
            - < 90 days: +10
        - Shodan dangerous ports (max 20):
            - RDP/VNC/Telnet: +5 each
            - SMB: +5
            - Known vuln services: +10 each

        Args:
            results: Dictionary of all lookup results.

        Returns:
            Risk score (0-100).
        """
        score = 0

        # Threat intelligence scoring (max 90)
        threat_intel = results.get("threat_intel")
        if threat_intel:
            # VT malicious (max 40)
            vt_score = min(threat_intel.virustotal_malicious * 5, 40)
            score += vt_score

            # OTX pulses (max 20)
            otx_score = min(threat_intel.otx_pulses * 3, 20)
            score += otx_score

            # Blacklist hits (max 30)
            blacklist_score = min(len(threat_intel.dns_blacklist_hits) * 10, 30)
            score += blacklist_score

            logger.debug(
                "threat_intel_scoring",
                vt_score=vt_score,
                otx_score=otx_score,
                blacklist_score=blacklist_score,
            )

        # Domain age scoring (max 15)
        whois = results.get("whois")
        if whois and whois.creation_date:
            domain_age_days = (datetime.utcnow() - whois.creation_date).days
            if domain_age_days < 30:
                score += 15
                logger.debug("domain_age_risk", age_days=domain_age_days, score_added=15)
            elif domain_age_days < 90:
                score += 10
                logger.debug("domain_age_risk", age_days=domain_age_days, score_added=10)

        # Shodan dangerous ports scoring (max 20)
        shodan = results.get("shodan")
        if shodan and shodan.ports:
            dangerous_ports = {3389, 5900, 5901, 23, 445, 139}  # RDP, VNC, Telnet, SMB
            found_dangerous = set(shodan.ports) & dangerous_ports
            port_score = min(len(found_dangerous) * 5, 20)
            score += port_score

            if found_dangerous:
                logger.debug(
                    "dangerous_ports_found",
                    ports=list(found_dangerous),
                    score_added=port_score,
                )

        # Cap at 100
        score = min(score, 100)

        logger.info("risk_score_calculated", final_score=score)
        return score

    def _generate_findings(self, results: dict) -> list[str]:
        """
        Generate human-readable key findings from results.

        Args:
            results: Dictionary of all lookup results.

        Returns:
            List of key findings as strings.
        """
        findings = []

        # Threat intel findings
        threat_intel = results.get("threat_intel")
        if threat_intel:
            if threat_intel.virustotal_malicious > 0:
                findings.append(
                    f"VirusTotal: {threat_intel.virustotal_malicious}/"
                    f"{threat_intel.virustotal_total} malicious detections"
                )

            if threat_intel.otx_pulses > 0:
                findings.append(
                    f"AlienVault OTX: Found in {threat_intel.otx_pulses} threat pulses"
                )

            if threat_intel.dns_blacklist_hits:
                findings.append(
                    f"DNS Blacklists: Listed on {len(threat_intel.dns_blacklist_hits)} blacklists"
                )

            if threat_intel.local_ioc_match:
                findings.append("Matches local IOC database")

        # WHOIS findings
        whois = results.get("whois")
        if whois:
            if whois.creation_date:
                domain_age_days = (datetime.utcnow() - whois.creation_date).days
                if domain_age_days < 30:
                    findings.append(f"Very new domain (registered {domain_age_days} days ago)")
                elif domain_age_days < 90:
                    findings.append(f"Recent domain (registered {domain_age_days} days ago)")

            if whois.registrar:
                findings.append(f"Registrar: {whois.registrar}")

        # ASN findings
        asn = results.get("asn")
        if asn and asn.organization:
            findings.append(f"Network: {asn.organization} ({asn.asn})")

        # Shodan findings
        shodan = results.get("shodan")
        if shodan:
            if shodan.ports:
                findings.append(f"Shodan: {len(shodan.ports)} open ports detected")

            dangerous_ports = {3389, 5900, 5901, 23, 445, 139}
            found_dangerous = set(shodan.ports) & dangerous_ports
            if found_dangerous:
                findings.append(f"Dangerous ports exposed: {', '.join(map(str, found_dangerous))}")

            if shodan.vulns:
                findings.append(f"Known vulnerabilities: {len(shodan.vulns)}")

        # Maltego findings
        maltego = results.get("maltego")
        if maltego:
            if maltego.related_domains:
                findings.append(
                    f"Related domains: {len(maltego.related_domains)} found"
                )

            if maltego.emails:
                findings.append(f"Associated emails: {len(maltego.emails)}")

        # If no findings, add default
        if not findings:
            findings.append("No significant threat indicators found")

        logger.debug("findings_generated", count=len(findings))
        return findings

    def _map_indicator_type(self, classifier_type: str) -> IndicatorType:
        """
        Map classifier string type to IndicatorType enum.

        Args:
            classifier_type: String type from classifier.

        Returns:
            Mapped IndicatorType enum value.
        """
        mapping = {
            "IPv4": IndicatorType.IP,
            "IPv6": IndicatorType.IP,
            "Domain": IndicatorType.DOMAIN,
            "URL": IndicatorType.URL,
            "MD5": IndicatorType.HASH,
            "SHA1": IndicatorType.HASH,
            "SHA256": IndicatorType.HASH,
            "ASN": IndicatorType.ASN,
            "Email": IndicatorType.EMAIL,
        }
        return mapping.get(classifier_type, IndicatorType.DOMAIN)
