"""Unit tests for envelope encryption (AES-256-GCM DEK/MEK)."""
import os
import pytest
from unittest.mock import patch

# Set required env var before import
os.environ.setdefault("ICEBOX_MEK", "test-mek-32-chars-minimum-length!")

from crypto.envelope import EnvelopeEncryption


@pytest.fixture
def enc() -> EnvelopeEncryption:
    """Envelope encryption instance with test MEK."""
    return EnvelopeEncryption(mek_source="test-mek-32-chars-minimum-length!")


class TestEncryptDecrypt:
    def test_roundtrip_short_value(self, enc: EnvelopeEncryption) -> None:
        """Short plaintext survives encrypt → decrypt."""
        plaintext = "my-api-key-abc123"
        ciphertext, encrypted_dek, dek_version = enc.encrypt(plaintext)

        recovered = enc.decrypt(ciphertext, encrypted_dek, dek_version)
        assert recovered == plaintext

    def test_roundtrip_long_value(self, enc: EnvelopeEncryption) -> None:
        """Long plaintext (e.g. JSON blob) survives encrypt → decrypt."""
        plaintext = '{"key": "' + "x" * 4000 + '"}'
        ciphertext, encrypted_dek, dek_version = enc.encrypt(plaintext)
        recovered = enc.decrypt(ciphertext, encrypted_dek, dek_version)
        assert recovered == plaintext

    def test_roundtrip_empty_value(self, enc: EnvelopeEncryption) -> None:
        """Empty string is handled correctly."""
        ciphertext, encrypted_dek, dek_version = enc.encrypt("")
        recovered = enc.decrypt(ciphertext, encrypted_dek, dek_version)
        assert recovered == ""

    def test_roundtrip_unicode_value(self, enc: EnvelopeEncryption) -> None:
        """Unicode secrets survive encrypt → decrypt."""
        plaintext = "密钥-секрет-🔐"
        ciphertext, encrypted_dek, dek_version = enc.encrypt(plaintext)
        recovered = enc.decrypt(ciphertext, encrypted_dek, dek_version)
        assert recovered == plaintext

    def test_ciphertext_is_not_plaintext(self, enc: EnvelopeEncryption) -> None:
        """Ciphertext must not contain the plaintext."""
        plaintext = "super-secret-value-12345"
        ciphertext, _, _ = enc.encrypt(plaintext)
        assert plaintext.encode() not in ciphertext

    def test_different_encryptions_produce_different_ciphertext(
        self, enc: EnvelopeEncryption
    ) -> None:
        """AES-GCM nonce is random — same plaintext yields different ciphertext."""
        plaintext = "same-value"
        ct1, dek1, _ = enc.encrypt(plaintext)
        ct2, dek2, _ = enc.encrypt(plaintext)
        # Each encryption gets a fresh DEK and nonce
        assert ct1 != ct2 or dek1 != dek2

    def test_tampered_ciphertext_raises(self, enc: EnvelopeEncryption) -> None:
        """Tampered ciphertext must fail authentication tag verification."""
        plaintext = "real-secret"
        ciphertext, encrypted_dek, dek_version = enc.encrypt(plaintext)

        # Flip a byte in the ciphertext
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0xFF
        with pytest.raises(Exception):
            enc.decrypt(bytes(tampered), encrypted_dek, dek_version)

    def test_tampered_dek_raises(self, enc: EnvelopeEncryption) -> None:
        """Tampered DEK must fail unwrapping."""
        plaintext = "real-secret"
        ciphertext, encrypted_dek, dek_version = enc.encrypt(plaintext)

        # Flip a byte in the encrypted DEK
        tampered_dek = bytearray(encrypted_dek)
        tampered_dek[-1] ^= 0xFF
        with pytest.raises(Exception):
            enc.decrypt(ciphertext, bytes(tampered_dek), dek_version)


class TestDekVersion:
    def test_dek_version_starts_at_1(self, enc: EnvelopeEncryption) -> None:
        """First encryption uses dek_version 1."""
        _, _, dek_version = enc.encrypt("test")
        assert dek_version == 1

    def test_dek_version_is_included_in_output(self, enc: EnvelopeEncryption) -> None:
        """dek_version is returned and non-zero."""
        _, _, dek_version = enc.encrypt("val")
        assert isinstance(dek_version, int)
        assert dek_version >= 1


class TestMekRotation:
    def test_rotate_mek_allows_decrypt_with_new_mek(self) -> None:
        """After MEK rotation, secrets remain accessible via new MEK."""
        old_mek = "old-mek-32-chars-minimum-length!!"
        new_mek = "new-mek-32-chars-minimum-length!!"
        enc_old = EnvelopeEncryption(mek_source=old_mek)
        enc_new = EnvelopeEncryption(mek_source=new_mek)

        plaintext = "rotatable-secret"
        ciphertext, encrypted_dek, dek_version = enc_old.encrypt(plaintext)

        # Re-wrap the DEK with the new MEK
        new_encrypted_dek = enc_old.rewrap_dek(encrypted_dek, enc_new)
        recovered = enc_new.decrypt(ciphertext, new_encrypted_dek, dek_version)
        assert recovered == plaintext

    def test_old_mek_cannot_decrypt_after_rewrap(self) -> None:
        """Old MEK cannot decrypt a re-wrapped DEK."""
        old_mek = "old-mek-32-chars-minimum-length!!"
        new_mek = "new-mek-32-chars-minimum-length!!"
        enc_old = EnvelopeEncryption(mek_source=old_mek)
        enc_new = EnvelopeEncryption(mek_source=new_mek)

        ciphertext, encrypted_dek, dek_version = enc_old.encrypt("secret")
        new_encrypted_dek = enc_old.rewrap_dek(encrypted_dek, enc_new)

        # Old enc cannot unwrap the new DEK
        with pytest.raises(Exception):
            enc_old.decrypt(ciphertext, new_encrypted_dek, dek_version)
