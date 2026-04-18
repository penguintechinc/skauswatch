"""Smoke tests: verify WebUI npm install and build succeed."""

import os
import shutil
import subprocess

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WEBUI_DIR = os.path.join(REPO_ROOT, "services", "webui")

_npm_available = shutil.which("npm") is not None
_webui_exists = os.path.isdir(WEBUI_DIR) and os.path.isfile(
    os.path.join(WEBUI_DIR, "package.json")
)

pytestmark = [
    pytest.mark.smoke,
    pytest.mark.skipif(not _npm_available, reason="npm not installed"),
    pytest.mark.skipif(not _webui_exists, reason="services/webui not found"),
]


@pytest.mark.slow
def test_npm_install():
    """'npm ci' (or 'npm install') must succeed in webui directory."""
    # Prefer npm ci for reproducible installs; fall back to npm install
    lock_file = os.path.join(WEBUI_DIR, "package-lock.json")
    cmd = ["npm", "ci"] if os.path.isfile(lock_file) else ["npm", "install"]

    result = subprocess.run(
        cmd,
        cwd=WEBUI_DIR,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, (
        f"{' '.join(cmd)} failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )


@pytest.mark.slow
def test_npm_build():
    """'npm run build' must succeed in webui directory."""
    result = subprocess.run(
        ["npm", "run", "build"],
        cwd=WEBUI_DIR,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, (
        f"npm run build failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
