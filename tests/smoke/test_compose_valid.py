"""Smoke tests: validate docker-compose files parse correctly."""

import os
import subprocess

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


@pytest.mark.smoke
def test_docker_compose_yml_valid():
    """docker-compose.yml must parse without errors."""
    compose_file = os.path.join(REPO_ROOT, "docker-compose.yml")
    if not os.path.isfile(compose_file):
        pytest.skip("docker-compose.yml not found")

    result = subprocess.run(
        ["docker", "compose", "-f", compose_file, "config", "--quiet"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"docker-compose.yml failed validation:\n{result.stderr}"
    )


@pytest.mark.smoke
def test_docker_compose_test_yml_valid():
    """docker-compose.test.yml must parse without errors."""
    compose_file = os.path.join(REPO_ROOT, "docker-compose.test.yml")
    if not os.path.isfile(compose_file):
        pytest.skip("docker-compose.test.yml not found")

    result = subprocess.run(
        ["docker", "compose", "-f", compose_file, "config", "--quiet"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"docker-compose.test.yml failed validation:\n{result.stderr}"
    )
