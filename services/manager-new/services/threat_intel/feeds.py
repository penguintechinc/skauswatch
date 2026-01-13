"""Threat Intelligence Feed Aggregator."""
import asyncio
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

import structlog

from services.threat_intel.sources.dns_blacklist import DNSBlacklistSource
from services.threat_intel.sources.ip_blacklist import IPBlacklistSource
from services.threat_intel.sources.otx import OTXSource
from services.threat_intel.sources.virustotal import VirusTotalSource
from services.threat_intel.sources.stix_taxii import TAXIISource
from services.threat_intel.sources.openioc import OpenIOCSource
from services.threat_intel.sources.yara_rules import YARASource

logger = structlog.get_logger()


class FeedAggregator:
    """Aggregates threat intelligence from multiple sources."""

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize feed aggregator with configuration."""
        self.config = config or {}
        self.sources = {}
        self._last_update = {}
        self._update_intervals = {}

    async def initialize(self) -> None:
        """Initialize all configured threat intel sources."""
        # DNS Blacklists (free, no API key)
        self.sources["dns_blacklist"] = DNSBlacklistSource()
        self._update_intervals["dns_blacklist"] = 3600  # 1 hour

        # IP Blacklists (free, no API key)
        self.sources["ip_blacklist"] = IPBlacklistSource()
        self._update_intervals["ip_blacklist"] = 3600

        # AlienVault OTX (free API key)
        if self.config.get("otx_api_key"):
            self.sources["otx"] = OTXSource(
                api_key=self.config["otx_api_key"],
                base_url=self.config.get("otx_base_url", "https://otx.alienvault.com/api/v1")
            )
            self._update_intervals["otx"] = 1800  # 30 minutes

        # VirusTotal (free tier with API key)
        if self.config.get("virustotal_api_key"):
            self.sources["virustotal"] = VirusTotalSource(
                api_key=self.config["virustotal_api_key"]
            )
            self._update_intervals["virustotal"] = 900  # 15 minutes (rate limited)

        # STIX/TAXII feeds
        taxii_feeds = self.config.get("taxii_feeds", [])
        for i, feed in enumerate(taxii_feeds):
            source_name = f"taxii_{i}"
            self.sources[source_name] = TAXIISource(
                server_url=feed["url"],
                collection_id=feed.get("collection_id"),
                username=feed.get("username"),
                password=feed.get("password"),
            )
            self._update_intervals[source_name] = feed.get("interval", 3600)

        # OpenIOC files
        openioc_paths = self.config.get("openioc_paths", [])
        if openioc_paths:
            self.sources["openioc"] = OpenIOCSource(paths=openioc_paths)
            self._update_intervals["openioc"] = 3600

        # YARA rules
        yara_paths = self.config.get("yara_paths", [])
        if yara_paths:
            self.sources["yara"] = YARASource(rule_paths=yara_paths)
            self._update_intervals["yara"] = 3600

        logger.info(
            "Feed aggregator initialized",
            sources=list(self.sources.keys())
        )

    async def check_indicator(
        self,
        indicator_type: str,
        value: str,
        sources: List[str] = None
    ) -> Dict[str, Any]:
        """Check an indicator against all or specified sources."""
        results = {
            "indicator_type": indicator_type,
            "value": value,
            "matches": [],
            "checked_sources": [],
            "timestamp": datetime.utcnow().isoformat(),
        }

        check_sources = sources or list(self.sources.keys())

        for source_name in check_sources:
            if source_name not in self.sources:
                continue

            source = self.sources[source_name]
            results["checked_sources"].append(source_name)

            try:
                match = await source.check_indicator(indicator_type, value)
                if match:
                    results["matches"].append({
                        "source": source_name,
                        "data": match,
                    })
            except Exception as e:
                logger.error(
                    "Source check failed",
                    source=source_name,
                    error=str(e)
                )

        results["is_malicious"] = len(results["matches"]) > 0
        results["match_count"] = len(results["matches"])

        return results

    async def fetch_updates(
        self, sources: List[str] = None, force: bool = False
    ) -> Dict[str, Any]:
        """Fetch updates from threat intel sources."""
        results = {
            "updated_sources": [],
            "skipped_sources": [],
            "failed_sources": [],
            "new_indicators": 0,
            "timestamp": datetime.utcnow().isoformat(),
        }

        check_sources = sources or list(self.sources.keys())
        now = datetime.utcnow()

        for source_name in check_sources:
            if source_name not in self.sources:
                continue

            # Check if update is needed
            last_update = self._last_update.get(source_name)
            interval = self._update_intervals.get(source_name, 3600)

            if not force and last_update:
                if (now - last_update).total_seconds() < interval:
                    results["skipped_sources"].append(source_name)
                    continue

            source = self.sources[source_name]

            try:
                indicators = await source.fetch_indicators()
                results["new_indicators"] += len(indicators)
                results["updated_sources"].append({
                    "name": source_name,
                    "indicators": len(indicators),
                })
                self._last_update[source_name] = now

            except Exception as e:
                logger.error(
                    "Source update failed",
                    source=source_name,
                    error=str(e)
                )
                results["failed_sources"].append({
                    "name": source_name,
                    "error": str(e),
                })

        return results

    async def enrich_indicator(
        self, indicator_type: str, value: str
    ) -> Dict[str, Any]:
        """Enrich an indicator with data from all sources."""
        enrichment = {
            "indicator_type": indicator_type,
            "value": value,
            "enrichments": {},
            "risk_score": 0.0,
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Collect enrichment from all sources
        tasks = []
        for source_name, source in self.sources.items():
            if hasattr(source, "enrich_indicator"):
                tasks.append(
                    self._enrich_from_source(source_name, source, indicator_type, value)
                )

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    continue
                if result:
                    source_name, data = result
                    enrichment["enrichments"][source_name] = data

        # Calculate risk score
        enrichment["risk_score"] = self._calculate_risk_score(enrichment)

        return enrichment

    async def _enrich_from_source(
        self,
        source_name: str,
        source: Any,
        indicator_type: str,
        value: str
    ) -> Optional[tuple]:
        """Enrich indicator from a single source."""
        try:
            data = await source.enrich_indicator(indicator_type, value)
            if data:
                return (source_name, data)
        except Exception as e:
            logger.error(
                "Enrichment failed",
                source=source_name,
                error=str(e)
            )
        return None

    def _calculate_risk_score(self, enrichment: Dict[str, Any]) -> float:
        """Calculate aggregate risk score from enrichments."""
        if not enrichment.get("enrichments"):
            return 0.0

        scores = []
        weights = {
            "virustotal": 2.0,
            "otx": 1.5,
            "dns_blacklist": 1.0,
            "ip_blacklist": 1.0,
        }

        for source, data in enrichment["enrichments"].items():
            if "risk_score" in data:
                weight = weights.get(source, 1.0)
                scores.append(data["risk_score"] * weight)
            elif "malicious" in data and data["malicious"]:
                weight = weights.get(source, 1.0)
                scores.append(0.8 * weight)

        if not scores:
            return 0.0

        # Weighted average
        return min(sum(scores) / len(scores), 1.0)

    def get_source_status(self) -> Dict[str, Any]:
        """Get status of all configured sources."""
        status = {}

        for name, source in self.sources.items():
            last_update = self._last_update.get(name)
            interval = self._update_intervals.get(name, 3600)

            status[name] = {
                "enabled": True,
                "last_update": last_update.isoformat() if last_update else None,
                "update_interval": interval,
                "type": source.__class__.__name__,
            }

        return status

    def get_available_sources(self) -> List[Dict[str, Any]]:
        """Get list of available source types."""
        return [
            {
                "name": "dns_blacklist",
                "description": "DNS-based blacklists (SpamHaus, Spamcop, etc.)",
                "requires_api_key": False,
            },
            {
                "name": "ip_blacklist",
                "description": "IP blacklists (Abuse.ch, Blocklist.de, etc.)",
                "requires_api_key": False,
            },
            {
                "name": "otx",
                "description": "AlienVault Open Threat Exchange",
                "requires_api_key": True,
            },
            {
                "name": "virustotal",
                "description": "VirusTotal file and URL scanning",
                "requires_api_key": True,
            },
            {
                "name": "taxii",
                "description": "STIX/TAXII 2.1 threat intelligence feeds",
                "requires_api_key": False,
            },
            {
                "name": "openioc",
                "description": "OpenIOC format indicator files",
                "requires_api_key": False,
            },
            {
                "name": "yara",
                "description": "YARA rule files for malware detection",
                "requires_api_key": False,
            },
        ]
