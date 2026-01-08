"""OpenIOC threat intelligence source."""
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

import structlog

logger = structlog.get_logger()


class OpenIOCSource:
    """
    OpenIOC (Open Indicators of Compromise) parser.

    OpenIOC is an XML-based format for sharing threat intelligence
    developed by Mandiant. It allows describing complex IOCs with
    boolean logic.

    File format: .ioc (XML)
    """

    # OpenIOC indicator item to internal type mapping
    TYPE_MAPPING = {
        "Network/DNS": "domain",
        "PortItem/remoteIP": "ip",
        "Network/String": "url",
        "FileItem/Md5sum": "hash",
        "FileItem/Sha256sum": "hash",
        "FileItem/FileName": "file",
        "RegistryItem/Path": "registry",
        "Email/From": "email",
        "Email/Subject": "email_subject",
        "ProcessItem/name": "process",
    }

    def __init__(self, paths: List[str] = None):
        """Initialize OpenIOC source."""
        self.paths = paths or []
        self._indicators_cache: List[Dict[str, Any]] = []

    async def check_indicator(
        self, indicator_type: str, value: str
    ) -> Optional[Dict[str, Any]]:
        """Check if indicator exists in loaded IOC files."""
        # Ensure indicators are loaded
        if not self._indicators_cache:
            await self.fetch_indicators()

        for ind in self._indicators_cache:
            if ind.get("indicator_type") == indicator_type and ind.get("value") == value:
                return ind

        return None

    async def fetch_indicators(self) -> List[Dict[str, Any]]:
        """Parse all configured OpenIOC files."""
        self._indicators_cache = []

        for path_str in self.paths:
            path = Path(path_str)

            if path.is_file() and path.suffix == ".ioc":
                indicators = self._parse_ioc_file(path)
                self._indicators_cache.extend(indicators)

            elif path.is_dir():
                for ioc_file in path.glob("**/*.ioc"):
                    indicators = self._parse_ioc_file(ioc_file)
                    self._indicators_cache.extend(indicators)

        logger.info(
            "OpenIOC files parsed",
            paths=len(self.paths),
            indicators=len(self._indicators_cache)
        )

        return self._indicators_cache

    def _parse_ioc_file(self, filepath: Path) -> List[Dict[str, Any]]:
        """Parse a single OpenIOC file."""
        indicators = []

        try:
            tree = ET.parse(filepath)
            root = tree.getroot()

            # Handle namespace
            ns = {"ioc": "http://schemas.mandiant.com/2010/ioc"}

            # Try with namespace first, then without
            ioc_id = root.get("id", "")

            # Get IOC metadata
            short_desc = root.find(".//ioc:short_description", ns)
            if short_desc is None:
                short_desc = root.find(".//short_description")

            description = short_desc.text if short_desc is not None else ""

            authored_date = root.find(".//ioc:authored_date", ns)
            if authored_date is None:
                authored_date = root.find(".//authored_date")

            created = authored_date.text if authored_date is not None else None

            # Parse indicator items
            for indicator_item in self._find_indicator_items(root, ns):
                parsed = self._parse_indicator_item(indicator_item, ns)
                if parsed:
                    parsed["ioc_id"] = ioc_id
                    parsed["ioc_description"] = description
                    parsed["ioc_file"] = str(filepath)
                    parsed["created"] = created
                    parsed["source"] = "openioc"
                    indicators.append(parsed)

        except ET.ParseError as e:
            logger.error(
                "OpenIOC parse error",
                file=str(filepath),
                error=str(e)
            )
        except Exception as e:
            logger.error(
                "OpenIOC processing error",
                file=str(filepath),
                error=str(e)
            )

        return indicators

    def _find_indicator_items(self, root: ET.Element, ns: Dict[str, str]) -> List[ET.Element]:
        """Find all IndicatorItem elements."""
        items = []

        # Try with namespace
        items.extend(root.findall(".//ioc:IndicatorItem", ns))

        # Try without namespace
        items.extend(root.findall(".//IndicatorItem"))

        return items

    def _parse_indicator_item(
        self, item: ET.Element, ns: Dict[str, str]
    ) -> Optional[Dict[str, Any]]:
        """Parse a single IndicatorItem element."""
        # Get Context (indicator type)
        context = item.find("Context", ns)
        if context is None:
            context = item.find("Context")

        if context is None:
            return None

        search_path = context.get("search", "")

        # Get Content (indicator value)
        content = item.find("Content", ns)
        if content is None:
            content = item.find("Content")

        if content is None or content.text is None:
            return None

        value = content.text.strip()
        content_type = content.get("type", "string")

        # Map to internal type
        indicator_type = self._map_search_path(search_path)

        if not indicator_type:
            return None

        return {
            "indicator_type": indicator_type,
            "value": value,
            "content_type": content_type,
            "search_path": search_path,
            "condition": item.get("condition", "is"),
            "preserve_case": item.get("preserve-case", "false") == "true",
            "negate": item.get("negate", "false") == "true",
            "threat_level": "medium",
            "confidence": 0.7,
        }

    def _map_search_path(self, search_path: str) -> Optional[str]:
        """Map OpenIOC search path to internal indicator type."""
        # Direct mapping
        if search_path in self.TYPE_MAPPING:
            return self.TYPE_MAPPING[search_path]

        # Partial matching
        search_lower = search_path.lower()

        if "md5" in search_lower or "sha" in search_lower:
            return "hash"
        elif "ip" in search_lower or "address" in search_lower:
            return "ip"
        elif "dns" in search_lower or "domain" in search_lower:
            return "domain"
        elif "url" in search_lower or "uri" in search_lower:
            return "url"
        elif "file" in search_lower:
            return "file"
        elif "registry" in search_lower:
            return "registry"
        elif "email" in search_lower:
            return "email"

        return None

    async def enrich_indicator(
        self, indicator_type: str, value: str
    ) -> Optional[Dict[str, Any]]:
        """Enrich indicator with OpenIOC context."""
        match = await self.check_indicator(indicator_type, value)

        if match:
            return {
                "indicator_type": indicator_type,
                "value": value,
                "source": "openioc",
                "ioc_id": match.get("ioc_id"),
                "ioc_description": match.get("ioc_description"),
                "search_path": match.get("search_path"),
                "condition": match.get("condition"),
                "malicious": True,
                "risk_score": 0.7,
            }

        return None

    def add_path(self, path: str) -> None:
        """Add an IOC file or directory path."""
        if path not in self.paths:
            self.paths.append(path)

    def get_loaded_iocs(self) -> List[str]:
        """Get list of loaded IOC IDs."""
        return list(set(ind.get("ioc_id") for ind in self._indicators_cache))
