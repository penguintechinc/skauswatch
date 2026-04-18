"""
Unit tests for worker-s3 WorkerConfig Pydantic model and load_worker_config()
(config.py).

Tests cover required fields, defaults, field constraints, the db_uri property,
and environment-variable loading.
"""

import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from config import WorkerConfig, load_worker_config


# ---------------------------------------------------------------------------
# TestWorkerConfig
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestWorkerConfig:
    """Tests for WorkerConfig Pydantic model."""

    def test_valid_creation_with_consumer_name(self):
        config = WorkerConfig(consumer_name="worker-01")
        assert config.consumer_name == "worker-01"

    def test_missing_consumer_name_raises(self):
        with pytest.raises(ValidationError):
            WorkerConfig()

    def test_default_redis_url(self):
        config = WorkerConfig(consumer_name="worker-01")
        assert config.redis_url == "redis://redis:6379/0"

    def test_default_redis_prefix(self):
        config = WorkerConfig(consumer_name="worker-01")
        assert config.redis_prefix == "skauswatch"

    def test_default_consumer_group(self):
        config = WorkerConfig(consumer_name="worker-01")
        assert config.consumer_group == "s3scan-workers"

    def test_default_db_type(self):
        config = WorkerConfig(consumer_name="worker-01")
        assert config.db_type == "postgres"

    def test_default_db_host(self):
        config = WorkerConfig(consumer_name="worker-01")
        assert config.db_host == "postgres"

    def test_default_db_port(self):
        config = WorkerConfig(consumer_name="worker-01")
        assert config.db_port == 5432

    def test_default_db_name(self):
        config = WorkerConfig(consumer_name="worker-01")
        assert config.db_name == "skauswatch"

    def test_default_db_user(self):
        config = WorkerConfig(consumer_name="worker-01")
        assert config.db_user == "skauswatch"

    def test_default_db_pass_empty(self):
        config = WorkerConfig(consumer_name="worker-01")
        assert config.db_pass == ""

    def test_default_thread_pool_size(self):
        config = WorkerConfig(consumer_name="worker-01")
        assert config.thread_pool_size == 4

    def test_default_max_concurrent_tasks(self):
        config = WorkerConfig(consumer_name="worker-01")
        assert config.max_concurrent_tasks == 10

    def test_default_max_file_size_mb(self):
        config = WorkerConfig(consumer_name="worker-01")
        assert config.max_file_size_mb == 100

    def test_default_scan_timeout_sec(self):
        config = WorkerConfig(consumer_name="worker-01")
        assert config.scan_timeout_sec == 120

    def test_default_yara_enabled_false(self):
        config = WorkerConfig(consumer_name="worker-01")
        assert config.yara_enabled is False

    def test_default_ti_enabled_true(self):
        config = WorkerConfig(consumer_name="worker-01")
        assert config.ti_enabled is True

    def test_default_sandbox_enabled_false(self):
        config = WorkerConfig(consumer_name="worker-01")
        assert config.sandbox_enabled is False

    def test_default_optional_api_keys_none(self):
        config = WorkerConfig(consumer_name="worker-01")
        assert config.virustotal_api_key is None
        assert config.otx_api_key is None
        assert config.sandbox_api_url is None
        assert config.sandbox_api_key is None

    # --- Field constraints ---

    def test_thread_pool_size_minimum_1(self):
        config = WorkerConfig(consumer_name="w", thread_pool_size=1)
        assert config.thread_pool_size == 1

    def test_thread_pool_size_maximum_16(self):
        config = WorkerConfig(consumer_name="w", thread_pool_size=16)
        assert config.thread_pool_size == 16

    def test_thread_pool_size_below_minimum_raises(self):
        with pytest.raises(ValidationError):
            WorkerConfig(consumer_name="w", thread_pool_size=0)

    def test_thread_pool_size_above_maximum_raises(self):
        with pytest.raises(ValidationError):
            WorkerConfig(consumer_name="w", thread_pool_size=17)

    def test_max_concurrent_tasks_minimum_1(self):
        config = WorkerConfig(consumer_name="w", max_concurrent_tasks=1)
        assert config.max_concurrent_tasks == 1

    def test_max_concurrent_tasks_maximum_50(self):
        config = WorkerConfig(consumer_name="w", max_concurrent_tasks=50)
        assert config.max_concurrent_tasks == 50

    def test_max_concurrent_tasks_below_minimum_raises(self):
        with pytest.raises(ValidationError):
            WorkerConfig(consumer_name="w", max_concurrent_tasks=0)

    def test_max_concurrent_tasks_above_maximum_raises(self):
        with pytest.raises(ValidationError):
            WorkerConfig(consumer_name="w", max_concurrent_tasks=51)

    def test_max_file_size_mb_minimum_1(self):
        config = WorkerConfig(consumer_name="w", max_file_size_mb=1)
        assert config.max_file_size_mb == 1

    def test_max_file_size_mb_maximum_500(self):
        config = WorkerConfig(consumer_name="w", max_file_size_mb=500)
        assert config.max_file_size_mb == 500

    def test_max_file_size_mb_below_minimum_raises(self):
        with pytest.raises(ValidationError):
            WorkerConfig(consumer_name="w", max_file_size_mb=0)

    def test_max_file_size_mb_above_maximum_raises(self):
        with pytest.raises(ValidationError):
            WorkerConfig(consumer_name="w", max_file_size_mb=501)

    def test_scan_timeout_sec_minimum_30(self):
        config = WorkerConfig(consumer_name="w", scan_timeout_sec=30)
        assert config.scan_timeout_sec == 30

    def test_scan_timeout_sec_maximum_600(self):
        config = WorkerConfig(consumer_name="w", scan_timeout_sec=600)
        assert config.scan_timeout_sec == 600

    def test_scan_timeout_sec_below_minimum_raises(self):
        with pytest.raises(ValidationError):
            WorkerConfig(consumer_name="w", scan_timeout_sec=29)

    def test_scan_timeout_sec_above_maximum_raises(self):
        with pytest.raises(ValidationError):
            WorkerConfig(consumer_name="w", scan_timeout_sec=601)

    # --- db_uri property ---

    def test_db_uri_without_password(self):
        config = WorkerConfig(
            consumer_name="w",
            db_type="postgres",
            db_user="appuser",
            db_pass="",
            db_host="localhost",
            db_port=5432,
            db_name="mydb",
        )
        assert config.db_uri == "postgres://appuser@localhost:5432/mydb"

    def test_db_uri_with_password(self):
        config = WorkerConfig(
            consumer_name="w",
            db_type="postgres",
            db_user="appuser",
            db_pass="s3cr3t",
            db_host="localhost",
            db_port=5432,
            db_name="mydb",
        )
        assert config.db_uri == "postgres://appuser:s3cr3t@localhost:5432/mydb"

    def test_db_uri_mysql_type(self):
        config = WorkerConfig(
            consumer_name="w",
            db_type="mysql",
            db_user="root",
            db_pass="rootpass",
            db_host="db-host",
            db_port=3306,
            db_name="skauswatch",
        )
        assert config.db_uri.startswith("mysql://")

    def test_db_uri_custom_port(self):
        config = WorkerConfig(
            consumer_name="w",
            db_type="postgres",
            db_user="u",
            db_pass="p",
            db_host="h",
            db_port=9999,
            db_name="d",
        )
        assert ":9999/" in config.db_uri

    def test_db_uri_contains_db_name(self):
        config = WorkerConfig(
            consumer_name="w",
            db_type="postgres",
            db_user="u",
            db_pass="",
            db_host="h",
            db_port=5432,
            db_name="special_db",
        )
        assert "special_db" in config.db_uri


# ---------------------------------------------------------------------------
# TestLoadWorkerConfig
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLoadWorkerConfig:
    """Tests for load_worker_config() environment variable loading."""

    def test_loads_consumer_name_from_env(self):
        env = {"CONSUMER_NAME": "env-worker-01"}
        with patch.dict(os.environ, env, clear=False):
            config = load_worker_config()
        assert config.consumer_name == "env-worker-01"

    def test_falls_back_to_worker_name_env(self):
        # CONSUMER_NAME not set, WORKER_NAME used
        clean_env = {k: v for k, v in os.environ.items() if k not in ("CONSUMER_NAME",)}
        clean_env["WORKER_NAME"] = "fallback-worker"
        with patch.dict(os.environ, clean_env, clear=True):
            config = load_worker_config()
        assert config.consumer_name == "fallback-worker"

    def test_missing_consumer_name_produces_empty_string(self):
        """When neither CONSUMER_NAME nor WORKER_NAME is set, load_worker_config
        passes an empty string which Pydantic accepts (str field is present but
        empty). This documents the actual runtime behavior."""
        clean_env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("CONSUMER_NAME", "WORKER_NAME")
        }
        with patch.dict(os.environ, clean_env, clear=True):
            config = load_worker_config()
        assert config.consumer_name == ""

    def test_loads_redis_url_from_env(self):
        env = {"CONSUMER_NAME": "w", "REDIS_URL": "redis://custom-redis:6380/1"}
        with patch.dict(os.environ, env, clear=False):
            config = load_worker_config()
        assert config.redis_url == "redis://custom-redis:6380/1"

    def test_loads_db_type_from_env(self):
        env = {"CONSUMER_NAME": "w", "DB_TYPE": "mysql"}
        with patch.dict(os.environ, env, clear=False):
            config = load_worker_config()
        assert config.db_type == "mysql"

    def test_loads_db_host_from_env(self):
        env = {"CONSUMER_NAME": "w", "DB_HOST": "mydb-host"}
        with patch.dict(os.environ, env, clear=False):
            config = load_worker_config()
        assert config.db_host == "mydb-host"

    def test_loads_db_port_from_env(self):
        env = {"CONSUMER_NAME": "w", "DB_PORT": "3306"}
        with patch.dict(os.environ, env, clear=False):
            config = load_worker_config()
        assert config.db_port == 3306

    def test_loads_db_pass_from_env(self):
        env = {"CONSUMER_NAME": "w", "DB_PASS": "supersecret"}
        with patch.dict(os.environ, env, clear=False):
            config = load_worker_config()
        assert config.db_pass == "supersecret"

    def test_loads_thread_pool_size_from_env(self):
        env = {"CONSUMER_NAME": "w", "THREAD_POOL_SIZE": "8"}
        with patch.dict(os.environ, env, clear=False):
            config = load_worker_config()
        assert config.thread_pool_size == 8

    def test_loads_max_concurrent_tasks_from_env(self):
        env = {"CONSUMER_NAME": "w", "MAX_CONCURRENT_TASKS": "20"}
        with patch.dict(os.environ, env, clear=False):
            config = load_worker_config()
        assert config.max_concurrent_tasks == 20

    def test_loads_yara_enabled_true_from_env(self):
        env = {"CONSUMER_NAME": "w", "YARA_ENABLED": "true"}
        with patch.dict(os.environ, env, clear=False):
            config = load_worker_config()
        assert config.yara_enabled is True

    def test_loads_yara_enabled_false_from_env(self):
        env = {"CONSUMER_NAME": "w", "YARA_ENABLED": "false"}
        with patch.dict(os.environ, env, clear=False):
            config = load_worker_config()
        assert config.yara_enabled is False

    def test_loads_ti_enabled_false_from_env(self):
        env = {"CONSUMER_NAME": "w", "TI_ENABLED": "false"}
        with patch.dict(os.environ, env, clear=False):
            config = load_worker_config()
        assert config.ti_enabled is False

    def test_loads_sandbox_enabled_true_from_env(self):
        env = {"CONSUMER_NAME": "w", "SANDBOX_ENABLED": "true"}
        with patch.dict(os.environ, env, clear=False):
            config = load_worker_config()
        assert config.sandbox_enabled is True

    def test_loads_virustotal_api_key_from_env(self):
        env = {"CONSUMER_NAME": "w", "VIRUSTOTAL_API_KEY": "vt-key-abc123"}
        with patch.dict(os.environ, env, clear=False):
            config = load_worker_config()
        assert config.virustotal_api_key == "vt-key-abc123"

    def test_loads_otx_api_key_from_env(self):
        env = {"CONSUMER_NAME": "w", "OTX_API_KEY": "otx-key-xyz789"}
        with patch.dict(os.environ, env, clear=False):
            config = load_worker_config()
        assert config.otx_api_key == "otx-key-xyz789"

    def test_returns_worker_config_instance(self):
        env = {"CONSUMER_NAME": "w"}
        with patch.dict(os.environ, env, clear=False):
            config = load_worker_config()
        assert isinstance(config, WorkerConfig)

    def test_thread_pool_size_out_of_range_raises(self):
        env = {"CONSUMER_NAME": "w", "THREAD_POOL_SIZE": "0"}
        with patch.dict(os.environ, env, clear=False):
            with pytest.raises(ValidationError):
                load_worker_config()
