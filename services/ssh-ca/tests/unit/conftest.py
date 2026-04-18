"""
Pytest configuration and fixtures for ssh-ca unit tests.

These tests target the data models (dataclasses and enums) in
async_ssh_processor.py, which can be imported without the heavy
shared.performance dependency chain by patching sys.modules first.
"""

import sys
import types
from datetime import datetime
from unittest.mock import MagicMock

import pytest


def _create_performance_mock():
    """Build a minimal mock of shared.performance so the module can be imported."""
    perf_mock = types.ModuleType("shared.performance")

    # Decorators that pass-through the wrapped function unchanged
    def _passthrough_decorator(*args, **kwargs):
        """Decorator factory that returns a no-op decorator."""
        def decorator(func):
            return func
        return decorator

    def _simple_decorator(func):
        """Simple no-op decorator."""
        return func

    perf_mock.async_retry = _passthrough_decorator
    perf_mock.async_timeout = _passthrough_decorator
    perf_mock.cache_decorator = _passthrough_decorator
    perf_mock.async_batch_processor = _passthrough_decorator

    # Stub manager classes
    for cls_name in (
        "AsyncTaskManager",
        "ThreadPoolManager",
        "CacheManager",
        "CPUBoundTaskManager",
        "IOBoundTaskManager",
        "RateLimiter",
    ):
        setattr(perf_mock, cls_name, MagicMock)

    # Stub config / enum classes
    for cls_name in ("CacheConfig", "RateLimitConfig", "RateLimitStrategy", "TaskType"):
        setattr(perf_mock, cls_name, MagicMock)

    return perf_mock


def _patch_shared_imports():
    """Inject mock modules so that the relative import chain resolves."""
    # Build the hierarchy: shared -> shared.performance
    shared_mock = types.ModuleType("shared")
    perf_mock = _create_performance_mock()

    shared_mock.performance = perf_mock
    sys.modules.setdefault("shared", shared_mock)
    sys.modules.setdefault("shared.performance", perf_mock)

    # The source file uses a relative import (`from ...shared.performance import …`).
    # When imported as a plain module (not a package) we also need the parent
    # package stubs that Python resolves during relative-import resolution.
    # We expose the processor under a flat name for test convenience.
    for stub in (
        "services",
        "services.ssh_ca",
        "services.ssh_ca.shared",
        "services.ssh_ca.shared.performance",
    ):
        sys.modules.setdefault(stub, types.ModuleType(stub))

    # Also stub out paramiko and cryptography to avoid hard dependencies
    paramiko_mock = types.ModuleType("paramiko")
    paramiko_mock.RSAKey = MagicMock()
    sys.modules.setdefault("paramiko", paramiko_mock)

    crypto_mock = types.ModuleType("cryptography")
    hazmat = types.ModuleType("cryptography.hazmat")
    primitives = types.ModuleType("cryptography.hazmat.primitives")
    serialization_mod = types.ModuleType("cryptography.hazmat.primitives.serialization")
    asymmetric = types.ModuleType("cryptography.hazmat.primitives.asymmetric")
    ed25519_mod = types.ModuleType("cryptography.hazmat.primitives.asymmetric.ed25519")
    rsa_mod = types.ModuleType("cryptography.hazmat.primitives.asymmetric.rsa")

    for mod, name in (
        (crypto_mock, "cryptography"),
        (hazmat, "cryptography.hazmat"),
        (primitives, "cryptography.hazmat.primitives"),
        (serialization_mod, "cryptography.hazmat.primitives.serialization"),
        (asymmetric, "cryptography.hazmat.primitives.asymmetric"),
        (ed25519_mod, "cryptography.hazmat.primitives.asymmetric.ed25519"),
        (rsa_mod, "cryptography.hazmat.primitives.asymmetric.rsa"),
    ):
        sys.modules.setdefault(name, mod)


# Patch before any test module is collected
_patch_shared_imports()


# ---------------------------------------------------------------------------
# Re-usable fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ssh_models():
    """
    Import and return the data-model symbols from async_ssh_processor.

    Uses importlib so that we control exactly when the import happens (after
    the sys.modules patches above are in place).
    """
    import importlib.util
    import os

    source = os.path.join(
        os.path.dirname(__file__), "..", "..", "async_ssh_processor.py"
    )
    spec = importlib.util.spec_from_file_location(
        "async_ssh_processor", os.path.abspath(source)
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def sample_certificate_request(ssh_models):
    """Return a minimal SSHCertificateRequest for testing."""
    return ssh_models.SSHCertificateRequest(
        request_id="req-001",
        certificate_type=ssh_models.SSHCertificateType.USER,
        public_key="ssh-rsa AAAAB3NzaC1yc2EAAAA test@host",
        principals=["alice", "ops"],
    )


@pytest.fixture
def sample_certificate_response(ssh_models):
    """Return a minimal SSHCertificateResponse for testing."""
    now = datetime(2025, 1, 1, 12, 0, 0)
    return ssh_models.SSHCertificateResponse(
        certificate_id="cert-001",
        certificate_type=ssh_models.SSHCertificateType.USER,
        signed_certificate="ssh-rsa-cert-v01@openssh.com AAAA...",
        serial_number=1000001,
        principals=["alice"],
        valid_after=now,
        valid_before=datetime(2025, 1, 1, 13, 0, 0),
        public_key_fingerprint="abc123",
        ca_fingerprint="ca_fp_xyz",
    )
