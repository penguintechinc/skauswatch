"""TypeScript lint validation tests for webui."""

import shutil
import subprocess

import pytest

WEBUI_DIR = "services/webui"


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


@pytest.mark.lint
class TestTypeScriptLint:
    """TypeScript/ESLint checks."""

    @pytest.mark.skipif(not _tool_available("npm"), reason="npm not installed")
    def test_eslint(self):
        """WebUI passes ESLint checks."""
        # Check if lint script exists in package.json
        result = subprocess.run(
            ["npm", "run", "lint", "--if-present"],
            capture_output=True,
            text=True,
            cwd=WEBUI_DIR,
            timeout=120,
        )
        if result.returncode != 0:
            pytest.fail(
                f"ESLint failed:\n{result.stdout[:1000]}\n{result.stderr[:1000]}"
            )

    @pytest.mark.skipif(not _tool_available("npm"), reason="npm not installed")
    def test_typecheck(self):
        """WebUI passes TypeScript type checking."""
        result = subprocess.run(
            ["npm", "run", "typecheck", "--if-present"],
            capture_output=True,
            text=True,
            cwd=WEBUI_DIR,
            timeout=120,
        )
        if result.returncode != 0:
            pytest.fail(
                f"TypeScript type check failed:\n{result.stdout[:1000]}\n{result.stderr[:1000]}"
            )
