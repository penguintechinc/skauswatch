"""Async TI enrichment module for VirusTotal and OTX integration."""

import logging
from typing import Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)


class TIEnricher:
    """Async threat intelligence enrichment using VirusTotal and OTX APIs."""

    VT_BASE_URL = "https://www.virustotal.com/api/v3"
    OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(
        self, vt_api_key: Optional[str] = None, otx_api_key: Optional[str] = None
    ):
        """Initialize TI enricher with API keys.

        Args:
            vt_api_key: VirusTotal API key
            otx_api_key: OTX API key
        """
        self.vt_api_key = vt_api_key
        self.otx_api_key = otx_api_key
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()

    async def enrich(
        self, sha256: str, md5: str, threat_names: List[str]
    ) -> Dict:
        """Enrich hash with threat intelligence from multiple sources.

        Args:
            sha256: SHA256 hash of file
            md5: MD5 hash of file
            threat_names: List of threat names from YARA rules

        Returns:
            Dictionary containing:
                - vt_score: VirusTotal detection ratio
                - otx_pulses: OTX pulse information
                - threat_family: Identified threat family
                - severity: Calculated severity level
                - related_iocs: Related indicators of compromise
        """
        if not self.session:
            self.session = aiohttp.ClientSession()

        result = {
            "vt_score": None,
            "otx_pulses": [],
            "threat_family": None,
            "severity": "unknown",
            "related_iocs": [],
        }

        try:
            # Query VirusTotal and OTX in parallel
            vt_result, otx_result = await self._query_virustotal(
                sha256
            ), await self._query_otx(sha256)

            if vt_result:
                result["vt_score"] = vt_result.get("detection_ratio")
                result["threat_family"] = vt_result.get("threat_family")
                result["severity"] = self._calculate_severity(
                    vt_result.get("detection_ratio", 0)
                )

            if otx_result:
                result["otx_pulses"] = otx_result.get("pulses", [])
                result["related_iocs"] = otx_result.get("related_iocs", [])

            # If threat names provided, try to identify family
            if threat_names and not result["threat_family"]:
                result["threat_family"] = self._extract_family_from_names(
                    threat_names
                )

        except Exception as e:
            logger.error(f"Error enriching hash {sha256}: {e}")

        return result

    async def _query_virustotal(self, sha256: str) -> Optional[Dict]:
        """Query VirusTotal for file information.

        Args:
            sha256: SHA256 hash to query

        Returns:
            Dictionary with VT file info or None on error
        """
        if not self.vt_api_key or not self.session:
            return None

        try:
            headers = {"x-apikey": self.vt_api_key}
            url = f"{self.VT_BASE_URL}/files/{sha256}"

            async with self.session.get(url, headers=headers, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    attrs = data.get("data", {}).get("attributes", {})

                    # Extract detection ratio
                    analysis = attrs.get("last_analysis_stats", {})
                    total = analysis.get("malicious", 0) + analysis.get("undetected", 0)
                    malicious = analysis.get("malicious", 0)
                    ratio = (malicious / total * 100) if total > 0 else 0

                    # Try to extract threat family from names
                    names = attrs.get("names", []) or attrs.get("meaningful_names", [])
                    threat_family = None
                    if names:
                        threat_family = names[0] if isinstance(names, list) else names

                    return {
                        "detection_ratio": ratio,
                        "threat_family": threat_family,
                        "tags": attrs.get("tags", []),
                    }

                elif resp.status == 404:
                    logger.debug(f"Hash {sha256} not found in VirusTotal")
                    return None

                elif resp.status == 429:
                    logger.warning("VirusTotal rate limit exceeded")
                    return None

                else:
                    logger.warning(f"VirusTotal error: {resp.status}")
                    return None

        except asyncio.TimeoutError:
            logger.warning(f"VirusTotal timeout for {sha256}")
            return None

        except Exception as e:
            logger.error(f"VirusTotal query error: {e}")
            return None

    async def _query_otx(self, sha256: str) -> Optional[Dict]:
        """Query OTX for file pulses and related IOCs.

        Args:
            sha256: SHA256 hash to query

        Returns:
            Dictionary with OTX pulse info or None on error
        """
        if not self.otx_api_key or not self.session:
            return None

        try:
            headers = {"X-OTX-API-KEY": self.otx_api_key}
            url = f"{self.OTX_BASE_URL}/indicators/file/{sha256}/pulses"

            async with self.session.get(url, headers=headers, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    pulses = data.get("results", [])

                    # Extract related IOCs
                    related_iocs = []
                    for pulse in pulses:
                        indicators = pulse.get("indicators", [])
                        for ind in indicators:
                            ioc = {
                                "type": ind.get("type"),
                                "indicator": ind.get("indicator"),
                                "pulse_id": pulse.get("id"),
                            }
                            related_iocs.append(ioc)

                    return {
                        "pulses": [
                            {
                                "id": p.get("id"),
                                "name": p.get("name"),
                                "tags": p.get("tags", []),
                                "adversary": p.get("adversary"),
                            }
                            for p in pulses
                        ],
                        "related_iocs": related_iocs[:10],  # Limit to 10
                    }

                elif resp.status == 404:
                    logger.debug(f"Hash {sha256} not found in OTX")
                    return None

                elif resp.status == 429:
                    logger.warning("OTX rate limit exceeded")
                    return None

                else:
                    logger.warning(f"OTX error: {resp.status}")
                    return None

        except asyncio.TimeoutError:
            logger.warning(f"OTX timeout for {sha256}")
            return None

        except Exception as e:
            logger.error(f"OTX query error: {e}")
            return None

    @staticmethod
    def _calculate_severity(detection_ratio: float) -> str:
        """Calculate severity based on detection ratio.

        Args:
            detection_ratio: Detection ratio as percentage (0-100)

        Returns:
            Severity level: critical, high, medium, low, or unknown
        """
        if detection_ratio >= 75:
            return "critical"
        elif detection_ratio >= 50:
            return "high"
        elif detection_ratio >= 25:
            return "medium"
        elif detection_ratio > 0:
            return "low"
        else:
            return "unknown"

    @staticmethod
    def _extract_family_from_names(threat_names: List[str]) -> Optional[str]:
        """Extract threat family from YARA rule names.

        Args:
            threat_names: List of threat names

        Returns:
            Extracted family name or None
        """
        if not threat_names:
            return None

        # Use first threat name, remove common prefixes
        name = threat_names[0]
        prefixes = ("Win32.", "Win64.", "Android.", "Linux.", "OSX.", "YARA_")

        for prefix in prefixes:
            if name.startswith(prefix):
                name = name[len(prefix) :]
                break

        return name if name else None


import asyncio
