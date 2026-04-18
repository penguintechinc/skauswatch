"""
Unit tests for ssh-ca async_ssh_processor data models.

Tests cover the dataclasses (SSHCertificateRequest, SSHCertificateResponse,
KRLEntry, SSHProcessingMetrics) and enums (SSHCertificateType,
SSHCertificateStatus) without instantiating AsyncSSHProcessor or requiring
shared.performance to be fully functional.
"""

from datetime import datetime

import pytest


# ---------------------------------------------------------------------------
# SSHCertificateType enum
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSSHCertificateType:
    """Tests for SSHCertificateType enum values."""

    def test_user_value(self, ssh_models):
        assert ssh_models.SSHCertificateType.USER.value == "user"

    def test_host_value(self, ssh_models):
        assert ssh_models.SSHCertificateType.HOST.value == "host"

    def test_only_two_members(self, ssh_models):
        members = list(ssh_models.SSHCertificateType)
        assert len(members) == 2

    def test_user_and_host_are_distinct(self, ssh_models):
        assert (
            ssh_models.SSHCertificateType.USER != ssh_models.SSHCertificateType.HOST
        )

    def test_enum_names(self, ssh_models):
        names = {m.name for m in ssh_models.SSHCertificateType}
        assert names == {"USER", "HOST"}


# ---------------------------------------------------------------------------
# SSHCertificateStatus enum
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSSHCertificateStatus:
    """Tests for SSHCertificateStatus enum values."""

    def test_active_value(self, ssh_models):
        assert ssh_models.SSHCertificateStatus.ACTIVE.value == "active"

    def test_revoked_value(self, ssh_models):
        assert ssh_models.SSHCertificateStatus.REVOKED.value == "revoked"

    def test_expired_value(self, ssh_models):
        assert ssh_models.SSHCertificateStatus.EXPIRED.value == "expired"

    def test_exactly_three_members(self, ssh_models):
        members = list(ssh_models.SSHCertificateStatus)
        assert len(members) == 3

    def test_all_statuses_distinct(self, ssh_models):
        st = ssh_models.SSHCertificateStatus
        assert st.ACTIVE != st.REVOKED
        assert st.ACTIVE != st.EXPIRED
        assert st.REVOKED != st.EXPIRED

    def test_enum_names(self, ssh_models):
        names = {m.name for m in ssh_models.SSHCertificateStatus}
        assert names == {"ACTIVE", "REVOKED", "EXPIRED"}


# ---------------------------------------------------------------------------
# SSHCertificateRequest dataclass
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSSHCertificateRequest:
    """Tests for SSHCertificateRequest dataclass."""

    def test_basic_initialization(self, ssh_models):
        req = ssh_models.SSHCertificateRequest(
            request_id="req-001",
            certificate_type=ssh_models.SSHCertificateType.USER,
            public_key="ssh-rsa AAAA test@host",
            principals=["alice"],
        )
        assert req.request_id == "req-001"
        assert req.certificate_type == ssh_models.SSHCertificateType.USER
        assert req.public_key == "ssh-rsa AAAA test@host"
        assert req.principals == ["alice"]

    def test_default_validity_duration(self, ssh_models):
        req = ssh_models.SSHCertificateRequest(
            request_id="req-002",
            certificate_type=ssh_models.SSHCertificateType.HOST,
            public_key="ssh-rsa AAAA host@example.com",
            principals=["web01.example.com"],
        )
        assert req.validity_duration == 3600

    def test_default_empty_extensions(self, ssh_models):
        req = ssh_models.SSHCertificateRequest(
            request_id="req-003",
            certificate_type=ssh_models.SSHCertificateType.USER,
            public_key="ssh-rsa AAAA user@host",
            principals=["bob"],
        )
        assert req.extensions == {}

    def test_default_empty_critical_options(self, ssh_models):
        req = ssh_models.SSHCertificateRequest(
            request_id="req-004",
            certificate_type=ssh_models.SSHCertificateType.USER,
            public_key="ssh-rsa AAAA user@host",
            principals=["carol"],
        )
        assert req.critical_options == {}

    def test_default_none_source_address(self, ssh_models):
        req = ssh_models.SSHCertificateRequest(
            request_id="req-005",
            certificate_type=ssh_models.SSHCertificateType.USER,
            public_key="ssh-rsa AAAA user@host",
            principals=["dave"],
        )
        assert req.source_address is None

    def test_default_none_force_command(self, ssh_models):
        req = ssh_models.SSHCertificateRequest(
            request_id="req-006",
            certificate_type=ssh_models.SSHCertificateType.USER,
            public_key="ssh-rsa AAAA user@host",
            principals=["eve"],
        )
        assert req.force_command is None

    def test_default_empty_requester_id(self, ssh_models):
        req = ssh_models.SSHCertificateRequest(
            request_id="req-007",
            certificate_type=ssh_models.SSHCertificateType.USER,
            public_key="ssh-rsa AAAA user@host",
            principals=["frank"],
        )
        assert req.requester_id == ""

    def test_default_empty_metadata(self, ssh_models):
        req = ssh_models.SSHCertificateRequest(
            request_id="req-008",
            certificate_type=ssh_models.SSHCertificateType.USER,
            public_key="ssh-rsa AAAA user@host",
            principals=["grace"],
        )
        assert req.metadata == {}

    def test_multiple_principals(self, ssh_models):
        req = ssh_models.SSHCertificateRequest(
            request_id="req-009",
            certificate_type=ssh_models.SSHCertificateType.USER,
            public_key="ssh-rsa AAAA user@host",
            principals=["alice", "ops", "admin"],
        )
        assert len(req.principals) == 3
        assert "ops" in req.principals

    def test_custom_validity_duration(self, ssh_models):
        req = ssh_models.SSHCertificateRequest(
            request_id="req-010",
            certificate_type=ssh_models.SSHCertificateType.USER,
            public_key="ssh-rsa AAAA user@host",
            principals=["heidi"],
            validity_duration=7200,
        )
        assert req.validity_duration == 7200

    def test_custom_extensions(self, ssh_models):
        extensions = {"permit-pty": "", "permit-user-rc": ""}
        req = ssh_models.SSHCertificateRequest(
            request_id="req-011",
            certificate_type=ssh_models.SSHCertificateType.USER,
            public_key="ssh-rsa AAAA user@host",
            principals=["ivan"],
            extensions=extensions,
        )
        assert req.extensions == extensions

    def test_custom_critical_options(self, ssh_models):
        opts = {"force-command": "/usr/bin/rsync"}
        req = ssh_models.SSHCertificateRequest(
            request_id="req-012",
            certificate_type=ssh_models.SSHCertificateType.USER,
            public_key="ssh-rsa AAAA user@host",
            principals=["judy"],
            critical_options=opts,
        )
        assert req.critical_options == opts

    def test_source_address_set(self, ssh_models):
        req = ssh_models.SSHCertificateRequest(
            request_id="req-013",
            certificate_type=ssh_models.SSHCertificateType.USER,
            public_key="ssh-rsa AAAA user@host",
            principals=["mallory"],
            source_address="192.168.1.0/24",
        )
        assert req.source_address == "192.168.1.0/24"

    def test_metadata_set(self, ssh_models):
        meta = {"department": "engineering", "team": "platform"}
        req = ssh_models.SSHCertificateRequest(
            request_id="req-014",
            certificate_type=ssh_models.SSHCertificateType.USER,
            public_key="ssh-rsa AAAA user@host",
            principals=["niaj"],
            metadata=meta,
        )
        assert req.metadata["department"] == "engineering"

    def test_extensions_not_shared_between_instances(self, ssh_models):
        """Verify default_factory produces independent dicts per instance."""
        req1 = ssh_models.SSHCertificateRequest(
            request_id="req-015a",
            certificate_type=ssh_models.SSHCertificateType.USER,
            public_key="ssh-rsa AAAA user@host",
            principals=["oscar"],
        )
        req2 = ssh_models.SSHCertificateRequest(
            request_id="req-015b",
            certificate_type=ssh_models.SSHCertificateType.USER,
            public_key="ssh-rsa AAAA user@host",
            principals=["peggy"],
        )
        req1.extensions["test"] = "value"
        assert "test" not in req2.extensions


# ---------------------------------------------------------------------------
# SSHCertificateResponse dataclass
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSSHCertificateResponse:
    """Tests for SSHCertificateResponse dataclass."""

    def test_basic_initialization(self, ssh_models):
        valid_after = datetime(2025, 6, 1, 0, 0, 0)
        valid_before = datetime(2025, 6, 1, 1, 0, 0)
        resp = ssh_models.SSHCertificateResponse(
            certificate_id="cert-001",
            certificate_type=ssh_models.SSHCertificateType.USER,
            signed_certificate="ssh-rsa-cert-v01@openssh.com AAAA...",
            serial_number=1000001,
            principals=["alice"],
            valid_after=valid_after,
            valid_before=valid_before,
            public_key_fingerprint="SHA256:abcdef1234",
            ca_fingerprint="SHA256:cafp1234",
        )
        assert resp.certificate_id == "cert-001"
        assert resp.serial_number == 1000001
        assert resp.principals == ["alice"]
        assert resp.valid_after == valid_after
        assert resp.valid_before == valid_before
        assert resp.public_key_fingerprint == "SHA256:abcdef1234"
        assert resp.ca_fingerprint == "SHA256:cafp1234"

    def test_certificate_type_user(self, ssh_models):
        resp = ssh_models.SSHCertificateResponse(
            certificate_id="cert-002",
            certificate_type=ssh_models.SSHCertificateType.USER,
            signed_certificate="ssh-rsa-cert-v01@openssh.com BBBB...",
            serial_number=1000002,
            principals=["bob"],
            valid_after=datetime(2025, 1, 1),
            valid_before=datetime(2025, 1, 2),
            public_key_fingerprint="fp001",
            ca_fingerprint="cafp001",
        )
        assert resp.certificate_type == ssh_models.SSHCertificateType.USER

    def test_certificate_type_host(self, ssh_models):
        resp = ssh_models.SSHCertificateResponse(
            certificate_id="cert-003",
            certificate_type=ssh_models.SSHCertificateType.HOST,
            signed_certificate="ssh-rsa-cert-v01@openssh.com CCCC...",
            serial_number=1000003,
            principals=["web01.example.com"],
            valid_after=datetime(2025, 1, 1),
            valid_before=datetime(2025, 1, 2),
            public_key_fingerprint="fp002",
            ca_fingerprint="cafp002",
        )
        assert resp.certificate_type == ssh_models.SSHCertificateType.HOST

    def test_default_empty_metadata(self, ssh_models):
        resp = ssh_models.SSHCertificateResponse(
            certificate_id="cert-004",
            certificate_type=ssh_models.SSHCertificateType.USER,
            signed_certificate="ssh-rsa-cert-v01@openssh.com DDDD...",
            serial_number=1000004,
            principals=["carol"],
            valid_after=datetime(2025, 1, 1),
            valid_before=datetime(2025, 1, 2),
            public_key_fingerprint="fp003",
            ca_fingerprint="cafp003",
        )
        assert resp.metadata == {}

    def test_custom_metadata(self, ssh_models):
        meta = {"issued_by": "automation", "reason": "deploy"}
        resp = ssh_models.SSHCertificateResponse(
            certificate_id="cert-005",
            certificate_type=ssh_models.SSHCertificateType.USER,
            signed_certificate="ssh-rsa-cert-v01@openssh.com EEEE...",
            serial_number=1000005,
            principals=["dave"],
            valid_after=datetime(2025, 1, 1),
            valid_before=datetime(2025, 1, 2),
            public_key_fingerprint="fp004",
            ca_fingerprint="cafp004",
            metadata=meta,
        )
        assert resp.metadata["issued_by"] == "automation"

    def test_multiple_principals(self, ssh_models):
        resp = ssh_models.SSHCertificateResponse(
            certificate_id="cert-006",
            certificate_type=ssh_models.SSHCertificateType.USER,
            signed_certificate="ssh-rsa-cert-v01@openssh.com FFFF...",
            serial_number=1000006,
            principals=["eve", "ops", "admin"],
            valid_after=datetime(2025, 1, 1),
            valid_before=datetime(2025, 1, 2),
            public_key_fingerprint="fp005",
            ca_fingerprint="cafp005",
        )
        assert len(resp.principals) == 3

    def test_validity_window_ordering(self, ssh_models):
        """valid_before should be stored as given (dataclass does not enforce ordering)."""
        valid_after = datetime(2025, 3, 1, 8, 0, 0)
        valid_before = datetime(2025, 3, 1, 9, 0, 0)
        resp = ssh_models.SSHCertificateResponse(
            certificate_id="cert-007",
            certificate_type=ssh_models.SSHCertificateType.USER,
            signed_certificate="ssh-rsa-cert-v01@openssh.com GGGG...",
            serial_number=1000007,
            principals=["frank"],
            valid_after=valid_after,
            valid_before=valid_before,
            public_key_fingerprint="fp006",
            ca_fingerprint="cafp006",
        )
        assert resp.valid_before > resp.valid_after

    def test_metadata_not_shared_between_instances(self, ssh_models):
        """Verify default_factory produces independent dicts per instance."""
        resp1 = ssh_models.SSHCertificateResponse(
            certificate_id="cert-008a",
            certificate_type=ssh_models.SSHCertificateType.USER,
            signed_certificate="ssh-rsa-cert-v01@openssh.com HHHH...",
            serial_number=1000008,
            principals=["grace"],
            valid_after=datetime(2025, 1, 1),
            valid_before=datetime(2025, 1, 2),
            public_key_fingerprint="fp007",
            ca_fingerprint="cafp007",
        )
        resp2 = ssh_models.SSHCertificateResponse(
            certificate_id="cert-008b",
            certificate_type=ssh_models.SSHCertificateType.USER,
            signed_certificate="ssh-rsa-cert-v01@openssh.com IIII...",
            serial_number=1000009,
            principals=["heidi"],
            valid_after=datetime(2025, 1, 1),
            valid_before=datetime(2025, 1, 2),
            public_key_fingerprint="fp008",
            ca_fingerprint="cafp008",
        )
        resp1.metadata["key"] = "value"
        assert "key" not in resp2.metadata


# ---------------------------------------------------------------------------
# KRLEntry dataclass
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestKRLEntry:
    """Tests for KRLEntry dataclass."""

    def test_basic_initialization(self, ssh_models):
        revocation_time = datetime(2025, 6, 15, 10, 30, 0)
        entry = ssh_models.KRLEntry(
            serial_number=1000001,
            revocation_time=revocation_time,
            reason="key compromise",
        )
        assert entry.serial_number == 1000001
        assert entry.revocation_time == revocation_time
        assert entry.reason == "key compromise"

    def test_default_none_fingerprint(self, ssh_models):
        entry = ssh_models.KRLEntry(
            serial_number=1000002,
            revocation_time=datetime(2025, 7, 1),
            reason="superseded",
        )
        assert entry.certificate_fingerprint is None

    def test_fingerprint_set(self, ssh_models):
        entry = ssh_models.KRLEntry(
            serial_number=1000003,
            revocation_time=datetime(2025, 8, 1),
            reason="ca compromise",
            certificate_fingerprint="SHA256:deadbeef",
        )
        assert entry.certificate_fingerprint == "SHA256:deadbeef"

    def test_reason_stored_verbatim(self, ssh_models):
        entry = ssh_models.KRLEntry(
            serial_number=9999999,
            revocation_time=datetime(2025, 12, 31),
            reason="  unspecified  ",
        )
        assert entry.reason == "  unspecified  "

    def test_serial_number_preserved(self, ssh_models):
        """Serial numbers can be very large integers."""
        big_serial = 2**62
        entry = ssh_models.KRLEntry(
            serial_number=big_serial,
            revocation_time=datetime(2026, 1, 1),
            reason="routine rotation",
        )
        assert entry.serial_number == big_serial


# ---------------------------------------------------------------------------
# SSHProcessingMetrics dataclass
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSSHProcessingMetrics:
    """Tests for SSHProcessingMetrics dataclass default zero values."""

    def test_certificates_signed_default_zero(self, ssh_models):
        m = ssh_models.SSHProcessingMetrics()
        assert m.certificates_signed == 0

    def test_certificates_revoked_default_zero(self, ssh_models):
        m = ssh_models.SSHProcessingMetrics()
        assert m.certificates_revoked == 0

    def test_krl_updates_default_zero(self, ssh_models):
        m = ssh_models.SSHProcessingMetrics()
        assert m.krl_updates == 0

    def test_config_generations_default_zero(self, ssh_models):
        m = ssh_models.SSHProcessingMetrics()
        assert m.config_generations == 0

    def test_average_signing_time_default_zero(self, ssh_models):
        m = ssh_models.SSHProcessingMetrics()
        assert m.average_signing_time == 0.0

    def test_queue_size_default_zero(self, ssh_models):
        m = ssh_models.SSHProcessingMetrics()
        assert m.queue_size == 0

    def test_cache_hit_rate_default_zero(self, ssh_models):
        m = ssh_models.SSHProcessingMetrics()
        assert m.cache_hit_rate == 0.0

    def test_error_count_default_zero(self, ssh_models):
        m = ssh_models.SSHProcessingMetrics()
        assert m.error_count == 0

    def test_all_defaults_at_once(self, ssh_models):
        m = ssh_models.SSHProcessingMetrics()
        assert (
            m.certificates_signed == 0
            and m.certificates_revoked == 0
            and m.krl_updates == 0
            and m.config_generations == 0
            and m.average_signing_time == 0.0
            and m.queue_size == 0
            and m.cache_hit_rate == 0.0
            and m.error_count == 0
        )

    def test_metrics_are_mutable(self, ssh_models):
        """Metrics should be updatable (used by processor at runtime)."""
        m = ssh_models.SSHProcessingMetrics()
        m.certificates_signed += 5
        m.error_count += 2
        assert m.certificates_signed == 5
        assert m.error_count == 2

    def test_instances_are_independent(self, ssh_models):
        m1 = ssh_models.SSHProcessingMetrics()
        m2 = ssh_models.SSHProcessingMetrics()
        m1.certificates_signed = 100
        assert m2.certificates_signed == 0
