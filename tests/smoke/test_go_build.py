"""Smoke tests: verify Go edr-agent builds and passes vet."""

import os
import shutil
import subprocess

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
EDR_AGENT_DIR = os.path.join(REPO_ROOT, "services", "edr-agent")

_go_available = shutil.which("go") is not None
_edr_exists = os.path.isdir(EDR_AGENT_DIR) and os.path.isfile(
    os.path.join(EDR_AGENT_DIR, "go.mod")
)

pytestmark = [
    pytest.mark.smoke,
    pytest.mark.skipif(not _go_available, reason="go toolchain not installed"),
    pytest.mark.skipif(not _edr_exists, reason="services/edr-agent not found"),
]


def test_go_build_edr_agent():
    """'go build ./...' must succeed in edr-agent directory."""
    result = subprocess.run(
        ["go", "build", "./..."],
        cwd=EDR_AGENT_DIR,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"go build failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_go_vet_edr_agent():
    """'go vet ./...' must succeed in edr-agent directory."""
    result = subprocess.run(
        ["go", "vet", "./..."],
        cwd=EDR_AGENT_DIR,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"go vet failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
