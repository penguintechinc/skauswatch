"""YARA rules threat intelligence source."""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger()


class YARASource:
    """
    YARA rule management and matching.

    YARA is a tool for identifying and classifying malware samples
    based on textual or binary patterns.

    This source manages YARA rule files and can:
    - Load rules from files/directories
    - Extract metadata and strings as IOCs
    - Match files/data against loaded rules
    """

    def __init__(self, rule_paths: List[str] = None):
        """Initialize YARA source."""
        self.rule_paths = rule_paths or []
        self._rules = None
        self._rule_metadata: List[Dict[str, Any]] = []
        self._yara_available = False

        try:
            import yara

            self._yara_available = True
        except ImportError:
            logger.warning("yara-python not installed, YARA matching unavailable")

    async def initialize(self) -> None:
        """Load and compile YARA rules."""
        if not self._yara_available:
            return

        import yara

        rule_files = {}

        for path_str in self.rule_paths:
            path = Path(path_str)

            if path.is_file() and path.suffix in (".yar", ".yara"):
                rule_files[str(path)] = str(path)

            elif path.is_dir():
                for rule_file in path.glob("**/*.yar"):
                    rule_files[str(rule_file)] = str(rule_file)
                for rule_file in path.glob("**/*.yara"):
                    rule_files[str(rule_file)] = str(rule_file)

        if rule_files:
            try:
                self._rules = yara.compile(filepaths=rule_files)
                self._extract_metadata(rule_files)
                logger.info("YARA rules loaded", rule_count=len(rule_files))
            except yara.SyntaxError as e:
                logger.error("YARA syntax error", error=str(e))
            except Exception as e:
                logger.error("YARA compilation failed", error=str(e))

    def _extract_metadata(self, rule_files: Dict[str, str]) -> None:
        """Extract metadata and IOCs from rule files."""
        self._rule_metadata = []

        for rule_name, rule_path in rule_files.items():
            try:
                with open(rule_path, "r") as f:
                    content = f.read()

                # Parse rule metadata
                metadata = self._parse_rule_file(content, rule_path)
                self._rule_metadata.extend(metadata)

            except Exception as e:
                logger.error("Failed to parse rule file", file=rule_path, error=str(e))

    def _parse_rule_file(self, content: str, filepath: str) -> List[Dict[str, Any]]:
        """Parse YARA rule file for metadata and IOCs."""
        import re

        rules = []

        # Find all rule definitions
        rule_pattern = re.compile(
            r"rule\s+(\w+)(?:\s*:\s*([\w\s]+))?\s*\{([^}]+)\}", re.DOTALL
        )

        for match in rule_pattern.finditer(content):
            rule_name = match.group(1)
            tags = match.group(2).split() if match.group(2) else []
            body = match.group(3)

            rule_data = {
                "rule_name": rule_name,
                "tags": tags,
                "file": filepath,
                "source": "yara",
                "indicator_type": "yara_rule",
                "value": rule_name,
                "strings": [],
                "metadata": {},
            }

            # Extract metadata section
            meta_match = re.search(
                r"meta\s*:\s*(.+?)(?=strings|condition|$)", body, re.DOTALL
            )
            if meta_match:
                meta_content = meta_match.group(1)
                for meta_line in meta_content.split("\n"):
                    meta_line = meta_line.strip()
                    if "=" in meta_line:
                        key, value = meta_line.split("=", 1)
                        key = key.strip()
                        value = value.strip().strip('"')
                        rule_data["metadata"][key] = value

            # Extract strings section
            strings_match = re.search(
                r"strings\s*:\s*(.+?)(?=condition|$)", body, re.DOTALL
            )
            if strings_match:
                strings_content = strings_match.group(1)
                for string_line in strings_content.split("\n"):
                    string_line = string_line.strip()
                    if string_line.startswith("$"):
                        # Parse string definition
                        string_def = self._parse_string_definition(string_line)
                        if string_def:
                            rule_data["strings"].append(string_def)

            # Determine threat level from metadata
            rule_data["threat_level"] = self._determine_threat_level(rule_data)

            rules.append(rule_data)

        return rules

    def _parse_string_definition(self, line: str) -> Optional[Dict[str, str]]:
        """Parse a YARA string definition."""
        import re

        # Match: $name = "value" or $name = { hex } or $name = /regex/
        string_match = re.match(
            r'\$(\w+)\s*=\s*(?:"([^"]+)"|{([^}]+)}|/([^/]+)/)', line
        )

        if string_match:
            name = string_match.group(1)
            text_value = string_match.group(2)
            hex_value = string_match.group(3)
            regex_value = string_match.group(4)

            if text_value:
                return {"name": name, "type": "text", "value": text_value}
            elif hex_value:
                return {"name": name, "type": "hex", "value": hex_value}
            elif regex_value:
                return {"name": name, "type": "regex", "value": regex_value}

        return None

    def _determine_threat_level(self, rule_data: Dict[str, Any]) -> str:
        """Determine threat level from rule metadata and tags."""
        metadata = rule_data.get("metadata", {})
        tags = rule_data.get("tags", [])

        # Check metadata
        severity = metadata.get("severity", "").lower()
        if severity in ("critical", "high"):
            return "critical"
        elif severity == "medium":
            return "high"

        # Check tags
        tag_lower = [t.lower() for t in tags]
        if any(t in tag_lower for t in ("apt", "ransomware", "rootkit")):
            return "critical"
        elif any(t in tag_lower for t in ("trojan", "backdoor", "rat")):
            return "high"
        elif any(t in tag_lower for t in ("malware", "suspicious")):
            return "medium"

        return "low"

    async def check_indicator(
        self, indicator_type: str, value: str
    ) -> Optional[Dict[str, Any]]:
        """
        Check if value matches any YARA rules.
        For string/hash indicators, check against rule strings.
        """
        for rule in self._rule_metadata:
            # Check rule name
            if indicator_type == "yara_rule" and value == rule.get("rule_name"):
                return rule

            # Check strings in rules
            for string in rule.get("strings", []):
                if string.get("type") == "text" and value in string.get("value", ""):
                    return {
                        "indicator_type": indicator_type,
                        "value": value,
                        "matched_rule": rule.get("rule_name"),
                        "matched_string": string.get("name"),
                        "source": "yara",
                        "malicious": True,
                    }

        return None

    async def fetch_indicators(self) -> List[Dict[str, Any]]:
        """Return loaded rule metadata as indicators."""
        if not self._rule_metadata:
            await self.initialize()
        return self._rule_metadata

    async def scan_data(self, data: bytes) -> List[Dict[str, Any]]:
        """Scan binary data against loaded YARA rules."""
        if not self._yara_available or self._rules is None:
            return []

        matches = []

        try:
            yara_matches = self._rules.match(data=data)

            for match in yara_matches:
                match_info = {
                    "rule": match.rule,
                    "tags": match.tags,
                    "meta": match.meta,
                    "strings": [],
                    "source": "yara",
                    "timestamp": datetime.utcnow().isoformat(),
                }

                for string_match in match.strings:
                    match_info["strings"].append(
                        {
                            "identifier": string_match.identifier,
                            "offset": (
                                string_match.instances[0].offset
                                if string_match.instances
                                else None
                            ),
                        }
                    )

                matches.append(match_info)

        except Exception as e:
            logger.error("YARA scan failed", error=str(e))

        return matches

    async def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Scan a file against loaded YARA rules."""
        if not self._yara_available or self._rules is None:
            return []

        matches = []

        try:
            yara_matches = self._rules.match(filepath=filepath)

            for match in yara_matches:
                match_info = {
                    "rule": match.rule,
                    "tags": match.tags,
                    "meta": match.meta,
                    "file": filepath,
                    "source": "yara",
                    "timestamp": datetime.utcnow().isoformat(),
                }
                matches.append(match_info)

        except Exception as e:
            logger.error("YARA file scan failed", file=filepath, error=str(e))

        return matches

    def get_rule_count(self) -> int:
        """Get number of loaded rules."""
        return len(self._rule_metadata)

    def get_rule_names(self) -> List[str]:
        """Get list of loaded rule names."""
        return [r.get("rule_name") for r in self._rule_metadata]

    async def enrich_indicator(
        self, indicator_type: str, value: str
    ) -> Optional[Dict[str, Any]]:
        """Enrich indicator with YARA rule context."""
        match = await self.check_indicator(indicator_type, value)

        if match:
            match["risk_score"] = 0.8
            return match

        return None
