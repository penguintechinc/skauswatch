"""Go lint validation tests for edr-agent."""

import shutil
import subprocess

import pytest

EDR_AGENT_DIR = "services/edr-agent"


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


@pytest.mark.lint
class TestGoLint:
    """Go code quality checks."""

    @pytest.mark.skipif(not _tool_available("go"), reason="go not installed")
    def test_gofmt_check(self):
        """All Go code passes gofmt formatting."""
        result = subprocess.run(
            ["gofmt", "-l", "."],
            capture_output=True,
            text=True,
            cwd=EDR_AGENT_DIR,
            timeout=60,
        )
        unformatted = result.stdout.strip()
        if unformatted:
            pytest.fail(
                f"gofmt: unformatted files found:\n{unformatted}\n"
                f"Run 'gofmt -w .' in {EDR_AGENT_DIR} to fix."
            )

    @pytest.mark.skipif(not _tool_available("go"), reason="go not installed")
    def test_go_vet(self):
        """Go vet passes with no issues."""
        result = subprocess.run(
            ["go", "vet", "./..."],
            capture_output=True,
            text=True,
            cwd=EDR_AGENT_DIR,
            timeout=120,
        )
        assert result.returncode == 0, (
            f"go vet failed:\n{result.stderr[:1000]}"
        )
