"""
Unit tests for aaa-monitor HealthChecker (health.py).

All psutil calls that block (e.g. cpu_percent(interval=1)) are mocked so
the test suite runs without real system delays.
"""

import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helper: build a psutil patch dictionary with safe defaults
# ---------------------------------------------------------------------------

def _make_psutil_mocks(
    cpu_percent=10.0,
    mem_percent=50.0,
    mem_available=4 * 1024 ** 3,
    disk_used=20 * 1024 ** 3,
    disk_total=100 * 1024 ** 3,
    disk_free=80 * 1024 ** 3,
    load_avg=(0.5, 0.4, 0.3),
    cpu_count=4,
):
    """Return a dict of patch targets -> mock return values for psutil helpers."""
    disk_mock = MagicMock()
    disk_mock.used = disk_used
    disk_mock.total = disk_total
    disk_mock.free = disk_free

    mem_mock = MagicMock()
    mem_mock.percent = mem_percent
    mem_mock.available = mem_available

    net_mock = MagicMock()
    net_mock.bytes_sent = 1000
    net_mock.bytes_recv = 2000

    proc_mem_mock = MagicMock()
    proc_mem_mock.rss = 128 * 1024 ** 2

    process_mock = MagicMock()
    process_mock.memory_info.return_value = proc_mem_mock
    process_mock.cpu_percent.return_value = 5.0

    return {
        "cpu_percent": cpu_percent,
        "virtual_memory": mem_mock,
        "disk_usage": disk_mock,
        "getloadavg": load_avg,
        "cpu_count": cpu_count,
        "net_io_counters": net_mock,
        "Process": process_mock,
    }


def _apply_psutil_patches(ctx, mocks):
    """
    Patch psutil functions used by _check_system_health.

    ctx: the 'with' block context where patches are applied via patch.object or patch.
    Returns a dict of started patches (callers should stop them in finally blocks).
    """
    import psutil

    patches = {}
    for name, value in mocks.items():
        if name == "Process":
            p = patch("psutil.Process", return_value=value)
        elif callable(value) or isinstance(value, (int, float)):
            p = patch(f"psutil.{name}", return_value=value)
        else:
            p = patch(f"psutil.{name}", return_value=value)
        patches[name] = p.start()
    return patches


# ---------------------------------------------------------------------------
# TestHealthCheckerInit
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestHealthCheckerInit:
    """Tests for HealthChecker __init__."""

    def test_config_stored(self, health_checker, health_config):
        assert health_checker.config is health_config

    def test_redis_client_stored(self, health_checker, mock_redis):
        assert health_checker.redis_client is mock_redis

    def test_components_stored(self, health_checker, mock_component):
        assert "collector1" in health_checker.components
        assert health_checker.components["collector1"] is mock_component

    def test_initial_last_check_is_none(self, health_checker):
        assert health_checker.last_check is None

    def test_initial_check_history_empty(self, health_checker):
        assert health_checker.check_history == []

    def test_max_history_from_config(self, health_checker):
        assert health_checker.max_history == 10

    def test_running_initially_false(self, health_checker):
        assert health_checker.running is False

    def test_no_redis_client_accepted(self, health_config):
        from health import HealthChecker

        checker = HealthChecker(health_config, None, {})
        assert checker.redis_client is None

    def test_empty_components_accepted(self, health_config, mock_redis):
        from health import HealthChecker

        checker = HealthChecker(health_config, mock_redis, {})
        assert checker.components == {}

    def test_default_max_history_when_not_in_config(self, mock_redis):
        from health import HealthChecker

        checker = HealthChecker({}, mock_redis, {})
        assert checker.max_history == 100


# ---------------------------------------------------------------------------
# TestCheckAll
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCheckAll:
    """Tests for HealthChecker.check_all()."""

    @pytest.mark.asyncio
    async def test_returns_dict_with_status(self, health_checker):
        mocks = _make_psutil_mocks()
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            result = await health_checker.check_all()
        assert "status" in result

    @pytest.mark.asyncio
    async def test_healthy_when_all_checks_pass(self, health_checker, mock_component):
        mock_component.get_health_status = AsyncMock(
            return_value={"status": "healthy", "issues": []}
        )
        mocks = _make_psutil_mocks()
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            result = await health_checker.check_all()
        assert result["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_degraded_when_component_degraded(self, health_checker, mock_component):
        mock_component.get_health_status = AsyncMock(
            return_value={"status": "degraded", "issues": ["queue high"]}
        )
        mocks = _make_psutil_mocks()
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            result = await health_checker.check_all()
        assert result["status"] in ("degraded", "unhealthy")

    @pytest.mark.asyncio
    async def test_unhealthy_when_component_unhealthy(
        self, health_checker, mock_component
    ):
        mock_component.get_health_status = AsyncMock(
            return_value={"status": "unhealthy", "issues": ["critical error"]}
        )
        mocks = _make_psutil_mocks()
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            result = await health_checker.check_all()
        assert result["status"] == "unhealthy"

    @pytest.mark.asyncio
    async def test_result_contains_checks_key(self, health_checker, mock_component):
        mock_component.get_health_status = AsyncMock(
            return_value={"status": "healthy", "issues": []}
        )
        mocks = _make_psutil_mocks()
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            result = await health_checker.check_all()
        assert "checks" in result
        assert "system" in result["checks"]

    @pytest.mark.asyncio
    async def test_result_contains_timestamp(self, health_checker, mock_component):
        mock_component.get_health_status = AsyncMock(
            return_value={"status": "healthy", "issues": []}
        )
        mocks = _make_psutil_mocks()
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            result = await health_checker.check_all()
        assert "timestamp" in result

    @pytest.mark.asyncio
    async def test_last_check_updated(self, health_checker, mock_component):
        mock_component.get_health_status = AsyncMock(
            return_value={"status": "healthy", "issues": []}
        )
        mocks = _make_psutil_mocks()
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            await health_checker.check_all()
        assert health_checker.last_check is not None

    @pytest.mark.asyncio
    async def test_redis_skipped_when_no_client(self, health_config):
        from health import HealthChecker

        checker = HealthChecker(health_config, None, {})
        mocks = _make_psutil_mocks()
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            result = await checker.check_all()
        assert "redis" not in result["checks"]


# ---------------------------------------------------------------------------
# TestSystemHealthCheck
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSystemHealthCheck:
    """Tests for HealthChecker._check_system_health() with mocked psutil."""

    @pytest.mark.asyncio
    async def test_healthy_when_resources_normal(self, health_checker):
        mocks = _make_psutil_mocks(cpu_percent=20.0, mem_percent=50.0)
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            result = await health_checker._check_system_health()
        assert result["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_degraded_when_cpu_above_75(self, health_checker):
        mocks = _make_psutil_mocks(cpu_percent=80.0)
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            result = await health_checker._check_system_health()
        assert result["status"] in ("degraded", "unhealthy")

    @pytest.mark.asyncio
    async def test_unhealthy_when_cpu_above_90(self, health_checker):
        mocks = _make_psutil_mocks(cpu_percent=95.0)
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            result = await health_checker._check_system_health()
        assert result["status"] == "unhealthy"

    @pytest.mark.asyncio
    async def test_degraded_when_memory_above_85(self, health_checker):
        mocks = _make_psutil_mocks(mem_percent=87.0)
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            result = await health_checker._check_system_health()
        assert result["status"] in ("degraded", "unhealthy")

    @pytest.mark.asyncio
    async def test_unhealthy_when_memory_above_95(self, health_checker):
        mocks = _make_psutil_mocks(mem_percent=97.0)
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            result = await health_checker._check_system_health()
        assert result["status"] == "unhealthy"

    @pytest.mark.asyncio
    async def test_degraded_when_disk_above_85(self, health_checker):
        # 87 GB used out of 100 GB
        mocks = _make_psutil_mocks(
            disk_used=87 * 1024 ** 3,
            disk_total=100 * 1024 ** 3,
            disk_free=13 * 1024 ** 3,
        )
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            result = await health_checker._check_system_health()
        assert result["status"] in ("degraded", "unhealthy")

    @pytest.mark.asyncio
    async def test_unhealthy_when_disk_above_95(self, health_checker):
        # 96 GB used out of 100 GB
        mocks = _make_psutil_mocks(
            disk_used=96 * 1024 ** 3,
            disk_total=100 * 1024 ** 3,
            disk_free=4 * 1024 ** 3,
        )
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            result = await health_checker._check_system_health()
        assert result["status"] == "unhealthy"

    @pytest.mark.asyncio
    async def test_result_contains_metrics(self, health_checker):
        mocks = _make_psutil_mocks()
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            result = await health_checker._check_system_health()
        assert "metrics" in result
        assert "cpu_percent" in result["metrics"]

    @pytest.mark.asyncio
    async def test_result_contains_issues_list(self, health_checker):
        mocks = _make_psutil_mocks()
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            result = await health_checker._check_system_health()
        assert "issues" in result
        assert isinstance(result["issues"], list)


# ---------------------------------------------------------------------------
# TestRedisHealthCheck
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRedisHealthCheck:
    """Tests for HealthChecker._check_redis_health()."""

    @pytest.mark.asyncio
    async def test_healthy_with_fast_ping(self, health_checker, mock_redis):
        mock_redis.info = AsyncMock(
            return_value={
                "used_memory": 512 * 1024,
                "used_memory_peak": 1024 * 1024,
                "connected_clients": 2,
                "total_commands_processed": 500,
                "maxmemory": 0,
            }
        )
        with patch("health.time.time", side_effect=[0.0, 0.005]):
            result = await health_checker._check_redis_health()
        # Low latency and no memory limit -> healthy
        assert result["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_degraded_when_latency_above_100ms(self, health_checker, mock_redis):
        with patch("health.time.time", side_effect=[0.0, 0.15]):
            result = await health_checker._check_redis_health()
        assert result["status"] in ("degraded", "unhealthy")

    @pytest.mark.asyncio
    async def test_unhealthy_when_redis_ping_raises(self, health_checker, mock_redis):
        mock_redis.ping = AsyncMock(side_effect=ConnectionError("refused"))
        result = await health_checker._check_redis_health()
        assert result["status"] == "unhealthy"
        assert "error" in result

    @pytest.mark.asyncio
    async def test_result_contains_latency_ms(self, health_checker, mock_redis):
        result = await health_checker._check_redis_health()
        assert "latency_ms" in result

    @pytest.mark.asyncio
    async def test_result_contains_metrics(self, health_checker, mock_redis):
        result = await health_checker._check_redis_health()
        assert "metrics" in result
        assert "used_memory" in result["metrics"]

    @pytest.mark.asyncio
    async def test_unhealthy_when_memory_above_95_percent_of_max(
        self, health_checker, mock_redis
    ):
        max_mem = 100 * 1024 * 1024
        used_mem = 97 * 1024 * 1024
        mock_redis.info = AsyncMock(
            return_value={
                "used_memory": used_mem,
                "used_memory_peak": max_mem,
                "connected_clients": 5,
                "total_commands_processed": 10000,
                "maxmemory": max_mem,
            }
        )
        result = await health_checker._check_redis_health()
        assert result["status"] == "unhealthy"

    @pytest.mark.asyncio
    async def test_degraded_when_memory_above_85_percent_of_max(
        self, health_checker, mock_redis
    ):
        max_mem = 100 * 1024 * 1024
        used_mem = 87 * 1024 * 1024
        mock_redis.info = AsyncMock(
            return_value={
                "used_memory": used_mem,
                "used_memory_peak": max_mem,
                "connected_clients": 5,
                "total_commands_processed": 10000,
                "maxmemory": max_mem,
            }
        )
        result = await health_checker._check_redis_health()
        assert result["status"] in ("degraded", "unhealthy")


# ---------------------------------------------------------------------------
# TestComponentHealthCheck
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestComponentHealthCheck:
    """Tests for HealthChecker._check_component_health() dispatch logic."""

    @pytest.mark.asyncio
    async def test_uses_get_health_status_when_available(self, health_checker):
        comp = MagicMock()
        comp.get_health_status = AsyncMock(
            return_value={"status": "healthy", "issues": []}
        )
        result = await health_checker._check_component_health("test_comp", comp)
        comp.get_health_status.assert_awaited_once()
        assert result["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_uses_health_check_when_no_get_health_status(self, health_checker):
        comp = MagicMock(spec=[])  # spec=[] means no attributes by default
        comp.health_check = AsyncMock(
            return_value={"status": "degraded", "issues": ["minor issue"]}
        )
        result = await health_checker._check_component_health("test_comp2", comp)
        comp.health_check.assert_awaited_once()
        assert result["status"] == "degraded"

    @pytest.mark.asyncio
    async def test_uses_get_statistics_when_no_health_methods(self, health_checker):
        comp = MagicMock(spec=["get_statistics"])
        comp.get_statistics.return_value = {"errors": 0, "queue_size": 100}
        result = await health_checker._check_component_health("test_comp3", comp)
        assert result["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_falls_back_to_basic_check(self, health_checker):
        comp = MagicMock(spec=["running", "initialized"])
        comp.running = True
        comp.initialized = True
        result = await health_checker._check_component_health("test_comp4", comp)
        assert result["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_unhealthy_when_get_health_status_raises(self, health_checker):
        comp = MagicMock()
        comp.get_health_status = AsyncMock(side_effect=RuntimeError("boom"))
        result = await health_checker._check_component_health("bad_comp", comp)
        assert result["status"] == "unhealthy"
        assert "error" in result

    @pytest.mark.asyncio
    async def test_basic_check_unhealthy_when_not_running(self, health_checker):
        comp = MagicMock(spec=["running"])
        comp.running = False
        result = await health_checker._check_component_health("stopped_comp", comp)
        assert result["status"] == "unhealthy"

    @pytest.mark.asyncio
    async def test_basic_check_unhealthy_when_not_initialized(self, health_checker):
        comp = MagicMock(spec=["initialized"])
        comp.initialized = False
        result = await health_checker._check_component_health("uninit_comp", comp)
        assert result["status"] == "unhealthy"


# ---------------------------------------------------------------------------
# TestCheckHistory
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCheckHistory:
    """Tests for check_history tracking in HealthChecker."""

    @pytest.mark.asyncio
    async def test_history_grows_after_check(self, health_checker, mock_component):
        mock_component.get_health_status = AsyncMock(
            return_value={"status": "healthy", "issues": []}
        )
        mocks = _make_psutil_mocks()
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            await health_checker.check_all()
        assert len(health_checker.check_history) == 1

    @pytest.mark.asyncio
    async def test_history_entries_have_expected_keys(
        self, health_checker, mock_component
    ):
        mock_component.get_health_status = AsyncMock(
            return_value={"status": "healthy", "issues": []}
        )
        mocks = _make_psutil_mocks()
        with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
             patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
             patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
             patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
             patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
             patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
             patch("psutil.Process", return_value=mocks["Process"]):
            await health_checker.check_all()
        entry = health_checker.check_history[0]
        assert "timestamp" in entry
        assert "status" in entry
        assert "duration" in entry

    @pytest.mark.asyncio
    async def test_history_capped_at_max_history(self, health_config, mock_redis):
        """History should not exceed max_history entries."""
        from health import HealthChecker

        config = {**health_config, "max_history": 3, "checks": []}
        checker = HealthChecker(config, None, {})

        mocks = _make_psutil_mocks()
        for _ in range(5):
            with patch("psutil.cpu_percent", return_value=mocks["cpu_percent"]), \
                 patch("psutil.virtual_memory", return_value=mocks["virtual_memory"]), \
                 patch("psutil.disk_usage", return_value=mocks["disk_usage"]), \
                 patch("psutil.getloadavg", return_value=mocks["getloadavg"]), \
                 patch("psutil.cpu_count", return_value=mocks["cpu_count"]), \
                 patch("psutil.net_io_counters", return_value=mocks["net_io_counters"]), \
                 patch("psutil.Process", return_value=mocks["Process"]):
                await checker.check_all()

        assert len(checker.check_history) <= 3

    def test_get_check_history_returns_copy(self, health_checker):
        health_checker.check_history = [{"status": "healthy"}]
        history = health_checker.get_check_history()
        history.append({"status": "injected"})
        # Original should be unchanged
        assert len(health_checker.check_history) == 1

    def test_get_check_history_with_limit(self, health_checker):
        health_checker.check_history = [
            {"status": "healthy"},
            {"status": "degraded"},
            {"status": "healthy"},
        ]
        limited = health_checker.get_check_history(limit=2)
        assert len(limited) == 2
        # Should return the LAST 2 entries
        assert limited[-1]["status"] == "healthy"


# ---------------------------------------------------------------------------
# TestAnalyzeComponentStats
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAnalyzeComponentStats:
    """Tests for HealthChecker._analyze_component_stats()."""

    def test_healthy_when_no_errors(self, health_checker):
        stats = {"errors": 0, "queue_size": 0}
        result = health_checker._analyze_component_stats("comp", stats)
        assert result["status"] == "healthy"

    def test_degraded_when_low_error_count(self, health_checker):
        stats = {"errors": 5}
        result = health_checker._analyze_component_stats("comp", stats)
        assert result["status"] in ("degraded", "unhealthy")

    def test_unhealthy_when_high_error_count(self, health_checker):
        stats = {"errors": 150}
        result = health_checker._analyze_component_stats("comp", stats)
        assert result["status"] == "unhealthy"

    def test_degraded_when_low_processing_errors(self, health_checker):
        stats = {"processing_errors": 10}
        result = health_checker._analyze_component_stats("comp", stats)
        assert result["status"] in ("degraded", "unhealthy")

    def test_unhealthy_when_high_processing_errors(self, health_checker):
        stats = {"processing_errors": 75}
        result = health_checker._analyze_component_stats("comp", stats)
        assert result["status"] == "unhealthy"

    def test_degraded_when_queue_size_above_5000(self, health_checker):
        stats = {"queue_size": 6000}
        result = health_checker._analyze_component_stats("comp", stats)
        assert result["status"] in ("degraded", "unhealthy")

    def test_unhealthy_when_queue_size_above_10000(self, health_checker):
        stats = {"queue_size": 15000}
        result = health_checker._analyze_component_stats("comp", stats)
        assert result["status"] == "unhealthy"

    def test_unhealthy_when_connection_failures_above_10(self, health_checker):
        stats = {"connection_failures": 11}
        result = health_checker._analyze_component_stats("comp", stats)
        assert result["status"] == "unhealthy"

    def test_healthy_when_connection_failures_at_limit(self, health_checker):
        stats = {"connection_failures": 10}
        result = health_checker._analyze_component_stats("comp", stats)
        # Exactly 10 is NOT > 10, so stays healthy
        assert result["status"] == "healthy"

    def test_result_contains_statistics(self, health_checker):
        stats = {"errors": 0}
        result = health_checker._analyze_component_stats("comp", stats)
        assert "statistics" in result
        assert result["statistics"] == stats

    def test_result_contains_issues_list(self, health_checker):
        stats = {"errors": 5}
        result = health_checker._analyze_component_stats("comp", stats)
        assert "issues" in result
        assert isinstance(result["issues"], list)

    def test_unhealthy_when_no_recent_activity(self, health_checker):
        two_hours_ago = (datetime.utcnow() - timedelta(hours=2)).isoformat()
        stats = {"last_activity": two_hours_ago}
        result = health_checker._analyze_component_stats("comp", stats)
        assert result["status"] in ("degraded", "unhealthy")
