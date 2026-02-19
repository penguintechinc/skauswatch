"""
YARA rule-based scanner for pattern matching and malware detection.

This module provides synchronous YARA scanning capabilities.
"""

from dataclasses import dataclass
import logging
import os
from typing import Optional

try:
    import yara
except ImportError:
    yara = None


logger = logging.getLogger(__name__)


@dataclass
class YaraMatch:
    """Result of a YARA rule match."""

    rule_name: str
    namespace: str
    tags: list[str]
    matched_strings: list[tuple[int, str, bytes]]

    def __post_init__(self) -> None:
        """Validate fields after initialization."""
        if not self.rule_name:
            raise ValueError("rule_name cannot be empty")


class YaraScanner:
    """
    Synchronous YARA scanner.

    Compiles and applies YARA rules to detect patterns and threats.
    """

    def __init__(self, rules_path: str) -> None:
        """
        Initialize YARA scanner with rules file.

        Args:
            rules_path: Path to YARA rules file

        Raises:
            ImportError: If yara-python library is not installed
            FileNotFoundError: If rules file does not exist
            yara.Error: If rules file has compilation errors
        """
        if yara is None:
            raise ImportError(
                "yara-python library is required for YARA scanning. "
                "Install it with: pip install yara-python"
            )

        if not os.path.exists(rules_path):
            raise FileNotFoundError(f"YARA rules file not found: {rules_path}")

        self.rules_path = rules_path
        self._rules: Optional[yara.Rules] = None

        # Try to compile rules on initialization
        self._compile_rules()

    def _compile_rules(self) -> None:
        """
        Compile YARA rules from file.

        Raises:
            yara.Error: If rules have syntax errors or cannot be compiled
        """
        try:
            self._rules = yara.compile(self.rules_path)
            logger.info(f"Successfully compiled YARA rules from {self.rules_path}")
        except yara.Error as e:
            logger.error(f"YARA rules compilation failed for {self.rules_path}: {e}")
            raise

    def _get_rules(self) -> yara.Rules:
        """
        Get compiled YARA rules, recompiling if necessary.

        Returns:
            Compiled yara.Rules instance

        Raises:
            yara.Error: If rules cannot be compiled
        """
        if self._rules is None:
            self._compile_rules()

        return self._rules

    def scan_file(self, file_path: str) -> list[YaraMatch]:
        """
        Scan a file against YARA rules.

        Args:
            file_path: Path to file to scan

        Returns:
            List of YaraMatch objects for matched rules

        Raises:
            FileNotFoundError: If file does not exist
            yara.Error: If YARA scan fails
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        try:
            rules = self._get_rules()
            matches = rules.match(file_path)

            results: list[YaraMatch] = []

            for match in matches:
                # match is a yara.Match object with:
                # - rule: Rule name
                # - namespace: Namespace
                # - tags: List of tags
                # - strings: List of matched strings

                yara_match = YaraMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    tags=list(match.tags) if match.tags else [],
                    matched_strings=match.strings if match.strings else [],
                )
                results.append(yara_match)

            if results:
                logger.info(f"YARA scan of {file_path}: {len(results)} rule(s) matched")
                for result in results:
                    logger.debug(f"  - {result.rule_name} (tags: {result.tags})")
            else:
                logger.debug(f"YARA scan of {file_path}: no matches")

            return results

        except yara.Error as e:
            logger.error(f"YARA scan failed for {file_path}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error scanning {file_path} with YARA: {e}")
            raise

    def scan_data(self, data: bytes) -> list[YaraMatch]:
        """
        Scan data in memory against YARA rules.

        Args:
            data: Bytes to scan

        Returns:
            List of YaraMatch objects for matched rules

        Raises:
            yara.Error: If YARA scan fails
            TypeError: If data is not bytes
        """
        if not isinstance(data, bytes):
            raise TypeError(f"Expected bytes, got {type(data).__name__}")

        try:
            rules = self._get_rules()
            matches = rules.match(data=data)

            results: list[YaraMatch] = []

            for match in matches:
                yara_match = YaraMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    tags=list(match.tags) if match.tags else [],
                    matched_strings=match.strings if match.strings else [],
                )
                results.append(yara_match)

            if results:
                logger.info(f"YARA memory scan: {len(results)} rule(s) matched")
                for result in results:
                    logger.debug(f"  - {result.rule_name} (tags: {result.tags})")
            else:
                logger.debug("YARA memory scan: no matches")

            return results

        except yara.Error as e:
            logger.error(f"YARA memory scan failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error scanning data with YARA: {e}")
            raise

    def reload_rules(self) -> None:
        """
        Reload and recompile YARA rules from disk.

        Useful if rules file has been updated.

        Raises:
            yara.Error: If rules cannot be compiled
        """
        logger.info(f"Reloading YARA rules from {self.rules_path}")
        self._rules = None
        self._compile_rules()

    def get_rule_count(self) -> int:
        """
        Get number of rules in compiled ruleset.

        Returns:
            Number of rules

        Raises:
            yara.Error: If rules cannot be compiled
        """
        rules = self._get_rules()
        # Rules don't expose rule count directly, so we count them
        count = len([rule for rule in rules])
        logger.debug(f"YARA ruleset contains {count} rule(s)")
        return count
