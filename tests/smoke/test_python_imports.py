"""Smoke tests: verify core Python service modules can be imported."""

import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


@pytest.mark.smoke
def test_import_manager_config():
    """services/manager-new config module should be importable."""
    manager_dir = os.path.join(REPO_ROOT, "services", "manager-new")
    if not os.path.isdir(manager_dir):
        pytest.skip("services/manager-new directory not found")

    if manager_dir not in sys.path:
        sys.path.insert(0, manager_dir)

    try:
        from config import ManagerConfig

        assert ManagerConfig is not None
    except ImportError as exc:
        pytest.fail(f"Failed to import ManagerConfig: {exc}")
    finally:
        if manager_dir in sys.path:
            sys.path.remove(manager_dir)


@pytest.mark.smoke
def test_import_worker_scanner_app():
    """services/worker-scanner app module should be importable."""
    scanner_dir = os.path.join(REPO_ROOT, "services", "worker-scanner")
    if not os.path.isdir(scanner_dir):
        pytest.skip("services/worker-scanner directory not found")

    # Check if there is an app.py or main.py to import
    has_app = os.path.isfile(os.path.join(scanner_dir, "app.py"))
    has_main = os.path.isfile(os.path.join(scanner_dir, "main.py"))
    if not has_app and not has_main:
        pytest.skip("No app.py or main.py in worker-scanner")

    if scanner_dir not in sys.path:
        sys.path.insert(0, scanner_dir)

    try:
        if has_app:
            import app  # noqa: F401
        else:
            import main  # noqa: F401
    except ImportError as exc:
        pytest.fail(f"Failed to import worker-scanner module: {exc}")
    finally:
        if scanner_dir in sys.path:
            sys.path.remove(scanner_dir)


@pytest.mark.smoke
def test_import_worker_s3_config():
    """services/worker-s3 config module should be importable."""
    s3_dir = os.path.join(REPO_ROOT, "services", "worker-s3")
    if not os.path.isdir(s3_dir):
        pytest.skip("services/worker-s3 directory not found")

    has_config = os.path.isfile(os.path.join(s3_dir, "config.py"))
    if not has_config:
        pytest.skip("No config.py in worker-s3")

    if s3_dir not in sys.path:
        sys.path.insert(0, s3_dir)

    try:
        import config  # noqa: F401

        assert config is not None
    except ImportError as exc:
        pytest.fail(f"Failed to import worker-s3 config: {exc}")
    finally:
        if s3_dir in sys.path:
            sys.path.remove(s3_dir)
