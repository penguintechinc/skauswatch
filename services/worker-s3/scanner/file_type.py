"""
File type detection using libmagic.

This module provides synchronous file type detection capabilities.
"""

import logging
from typing import Optional

try:
    import magic
except ImportError:
    magic = None


logger = logging.getLogger(__name__)


class FileTypeDetector:
    """
    Synchronous file type detector using libmagic.

    Identifies MIME types and determines if files should be scanned.
    """

    def __init__(self) -> None:
        """
        Initialize file type detector.

        Raises:
            ImportError: If python-magic library is not installed
        """
        if magic is None:
            raise ImportError(
                "python-magic library is required for file type detection. "
                "Install it with: pip install python-magic"
            )

        self._mime_detector: Optional[magic.Magic] = None
        self._type_detector: Optional[magic.Magic] = None

    def _get_mime_detector(self) -> magic.Magic:
        """
        Get or create MIME type detector instance.

        Returns:
            magic.Magic instance configured for MIME types
        """
        if self._mime_detector is None:
            self._mime_detector = magic.Magic(mime=True)
        return self._mime_detector

    def _get_type_detector(self) -> magic.Magic:
        """
        Get or create file type detector instance.

        Returns:
            magic.Magic instance configured for file descriptions
        """
        if self._type_detector is None:
            self._type_detector = magic.Magic(mime=False)
        return self._type_detector

    def detect(self, file_path: str) -> str:
        """
        Detect MIME type of a file.

        Args:
            file_path: Path to file to analyze

        Returns:
            MIME type string (e.g., 'application/pdf')

        Raises:
            FileNotFoundError: If file does not exist
            OSError: If file cannot be read
        """
        import os

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        try:
            detector = self._get_mime_detector()
            mime_type = detector.from_file(file_path)
            logger.debug(f"Detected MIME type for {file_path}: {mime_type}")
            return mime_type
        except Exception as e:
            logger.error(f"Failed to detect MIME type for {file_path}: {e}")
            raise OSError(f"Cannot detect file type: {e}") from e

    def get_description(self, file_path: str) -> str:
        """
        Get human-readable description of file type.

        Args:
            file_path: Path to file to analyze

        Returns:
            File type description string

        Raises:
            FileNotFoundError: If file does not exist
            OSError: If file cannot be read
        """
        import os

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        try:
            detector = self._get_type_detector()
            description = detector.from_file(file_path)
            logger.debug(f"Detected file description for {file_path}: {description}")
            return description
        except Exception as e:
            logger.error(f"Failed to detect file description for {file_path}: {e}")
            raise OSError(f"Cannot detect file description: {e}") from e

    def is_scannable(self, mime_type: str, allowed_types: list[str]) -> bool:
        """
        Determine if a file should be scanned based on MIME type.

        Args:
            mime_type: MIME type to check
            allowed_types: List of allowed MIME types or patterns
                          (supports wildcards like 'application/*')

        Returns:
            True if file should be scanned, False otherwise
        """
        if not allowed_types:
            # If no restrictions, all files are scannable
            return True

        mime_type_lower = mime_type.lower()

        for allowed in allowed_types:
            allowed_lower = allowed.lower()

            # Exact match
            if mime_type_lower == allowed_lower:
                return True

            # Wildcard match (e.g., 'application/*' matches 'application/pdf')
            if allowed_lower.endswith("/*"):
                prefix = allowed_lower[:-2]
                if mime_type_lower.startswith(prefix + "/"):
                    return True

        logger.debug(f"MIME type {mime_type} not in allowed list: {allowed_types}")
        return False
