"""
File hashing utilities for checksum computation.

This module provides synchronous file hashing capabilities
for computing MD5, SHA1, and SHA256 hashes.
"""

import hashlib
import logging
import os

logger = logging.getLogger(__name__)

# Chunk size for streaming file reads (1 MB)
CHUNK_SIZE = 1024 * 1024


class FileHasher:
    """
    Synchronous file hasher.

    Computes multiple hash types (MD5, SHA1, SHA256) efficiently
    using streaming reads for large files.
    """

    @staticmethod
    def compute_all(file_path: str) -> dict[str, str]:
        """
        Compute all supported hash types for a file.

        Args:
            file_path: Path to file to hash

        Returns:
            Dictionary with hash types as keys and hex digests as values
            Example: {'md5': 'abc123...', 'sha1': 'def456...', 'sha256': 'ghi789...'}

        Raises:
            FileNotFoundError: If file does not exist
            OSError: If file cannot be read
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        if not os.path.isfile(file_path):
            raise OSError(f"Path is not a file: {file_path}")

        hashes: dict[str, str] = {}

        try:
            # Create hash objects
            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256()

            # Read file in chunks and update hashes
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)

            # Get hex digests
            hashes["md5"] = md5_hash.hexdigest()
            hashes["sha1"] = sha1_hash.hexdigest()
            hashes["sha256"] = sha256_hash.hexdigest()

            logger.debug(
                f"Computed hashes for {file_path}: "
                f"md5={hashes['md5']}, sha1={hashes['sha1']}, "
                f"sha256={hashes['sha256']}"
            )

            return hashes

        except IOError as e:
            logger.error(f"Failed to read file {file_path} for hashing: {e}")
            raise OSError(f"Cannot read file for hashing: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error computing hashes for {file_path}: {e}")
            raise

    @staticmethod
    def compute_hash(file_path: str, hash_type: str = "sha256") -> str:
        """
        Compute a single hash type for a file.

        Args:
            file_path: Path to file to hash
            hash_type: Hash algorithm ('md5', 'sha1', or 'sha256')

        Returns:
            Hex digest of the hash

        Raises:
            FileNotFoundError: If file does not exist
            ValueError: If hash_type is not supported
            OSError: If file cannot be read
        """
        if hash_type not in ("md5", "sha1", "sha256"):
            raise ValueError(
                f"Unsupported hash type: {hash_type}. "
                f"Supported types: md5, sha1, sha256"
            )

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        if not os.path.isfile(file_path):
            raise OSError(f"Path is not a file: {file_path}")

        try:
            hash_obj = hashlib.new(hash_type)

            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    hash_obj.update(chunk)

            digest = hash_obj.hexdigest()
            logger.debug(f"Computed {hash_type} hash for {file_path}: {digest}")
            return digest

        except IOError as e:
            logger.error(f"Failed to read file {file_path} for hashing: {e}")
            raise OSError(f"Cannot read file for hashing: {e}") from e
        except Exception as e:
            logger.error(
                f"Unexpected error computing {hash_type} hash for {file_path}: {e}"
            )
            raise

    @staticmethod
    def verify_hash(
        file_path: str, expected_hash: str, hash_type: str = "sha256"
    ) -> bool:
        """
        Verify a file hash against an expected value.

        Args:
            file_path: Path to file to verify
            expected_hash: Expected hex digest value
            hash_type: Hash algorithm to use

        Returns:
            True if hash matches, False otherwise

        Raises:
            FileNotFoundError: If file does not exist
            ValueError: If hash_type is not supported
            OSError: If file cannot be read
        """
        computed = FileHasher.compute_hash(file_path, hash_type)
        matches = computed.lower() == expected_hash.lower()

        if matches:
            logger.debug(f"Hash verification passed for {file_path}")
        else:
            logger.warning(
                f"Hash mismatch for {file_path}: "
                f"expected={expected_hash}, computed={computed}"
            )

        return matches
