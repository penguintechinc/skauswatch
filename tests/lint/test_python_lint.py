"""Python lint validation tests.

Runs black, isort, and flake8 checks against the codebase.
These are also run in CI but running them as pytest tests
provides a unified test interface.
"""

import shutil
import subprocess

import pytest

SERVICES_DIR = "services"
TESTS_DIR = "tests"


def _tool_available(name: str) -> bool:
    """Check if a CLI tool is available."""
    return shutil.which(name) is not None


@pytest.mark.lint
class TestBlack:
    """Black code formatter checks."""

    @pytest.mark.skipif(not _tool_available("black"), reason="black not installed")
    def test_black_check(self):
        """All Python code passes black formatting."""
        result = subprocess.run(
            ["black", "--check", "--quiet", SERVICES_DIR, TESTS_DIR],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            # Get list of files that need formatting
            detail_result = subprocess.run(
                ["black", "--check", "--diff", SERVICES_DIR, TESTS_DIR],
                capture_output=True,
                text=True,
                timeout=120,
            )
            pytest.fail(
                f"black formatting issues found. Run 'black services/ tests/' to fix.\n"
                f"{detail_result.stdout[:1000]}"
            )


@pytest.mark.lint
class TestIsort:
    """Import ordering checks."""

    @pytest.mark.skipif(not _tool_available("isort"), reason="isort not installed")
    def test_isort_check(self):
        """All Python imports are properly ordered."""
        result = subprocess.run(
            [
                "isort",
                "--check-only",
                "--profile",
                "black",
                SERVICES_DIR,
                TESTS_DIR,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            pytest.fail(
                f"isort issues found. Run 'isort --profile black services/ tests/' to fix.\n"
                f"{result.stdout[:1000]}"
            )


@pytest.mark.lint
class TestFlake8:
    """Flake8 linting checks."""

    @pytest.mark.skipif(not _tool_available("flake8"), reason="flake8 not installed")
    def test_flake8(self):
        """All Python code passes flake8 linting."""
        result = subprocess.run(
            [
                "flake8",
                SERVICES_DIR,
                TESTS_DIR,
                "--max-line-length=120",
                "--exclude=__pycache__,.git,node_modules,venv,.venv",
                "--count",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            pytest.fail(
                f"flake8 issues found ({result.stdout.strip().split(chr(10))[-1]}):\n"
                f"{result.stdout[:2000]}"
            )
