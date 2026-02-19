"""
Comprehensive Performance Monitoring for SkausWatch

Provides unified performance monitoring, metrics collection, alerting,
and performance profiling across all SkausWatch services.
"""

import asyncio
import json
import logging
import statistics
import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from uuid import uuid4

import psutil

# Prometheus metrics (conditional)
try:
    from prometheus_client import (
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        Summary,
        generate_latest,
    )

    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False

from .async_utils import AsyncTaskManager
from .cache_manager import CacheConfig, CacheManager
from .connection_pool import ConnectionPoolManager

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Metric types"""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


class AlertSeverity(Enum):
    """Alert severity levels"""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class HealthStatus(Enum):
    """Health status values"""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class Metric:
    """Individual metric data point"""

    name: str
    value: float
    metric_type: MetricType
    timestamp: datetime = field(default_factory=datetime.utcnow)
    labels: Dict[str, str] = field(default_factory=dict)
    help_text: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "type": self.metric_type.value,
            "timestamp": self.timestamp.isoformat(),
            "labels": self.labels,
            "help_text": self.help_text,
        }


@dataclass
class Alert:
    """Performance alert"""

    alert_id: str
    service: str
    metric_name: str
    severity: AlertSeverity
    message: str
    value: float
    threshold: float
    created_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    labels: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthCheck:
    """Health check result"""

    name: str
    status: HealthStatus
    response_time: float
    timestamp: datetime = field(default_factory=datetime.utcnow)
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceProfile:
    """Performance profiling data"""

    profile_id: str
    service: str
    operation: str
    start_time: datetime
    end_time: datetime
    duration: float
    cpu_usage: float
    memory_usage: float
    io_operations: int
    network_bytes: int
    custom_metrics: Dict[str, float] = field(default_factory=dict)


class BaseMetricsCollector(ABC):
    """Base class for metrics collectors"""

    @abstractmethod
    async def collect_metrics(self) -> List[Metric]:
        """Collect metrics from source"""
        pass

    @abstractmethod
    def get_name(self) -> str:
        """Get collector name"""
        pass


class SystemMetricsCollector(BaseMetricsCollector):
    """System-level metrics collector"""

    def __init__(self):
        self.process = psutil.Process()

    def get_name(self) -> str:
        return "system"

    async def collect_metrics(self) -> List[Metric]:
        """Collect system metrics"""
        metrics = []

        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            metrics.append(
                Metric(
                    name="system_cpu_usage_percent",
                    value=cpu_percent,
                    metric_type=MetricType.GAUGE,
                    help_text="System CPU usage percentage",
                )
            )

            # Memory metrics
            memory = psutil.virtual_memory()
            metrics.append(
                Metric(
                    name="system_memory_usage_percent",
                    value=memory.percent,
                    metric_type=MetricType.GAUGE,
                    help_text="System memory usage percentage",
                )
            )

            metrics.append(
                Metric(
                    name="system_memory_available_bytes",
                    value=memory.available,
                    metric_type=MetricType.GAUGE,
                    help_text="System available memory in bytes",
                )
            )

            # Disk metrics
            disk = psutil.disk_usage("/")
            metrics.append(
                Metric(
                    name="system_disk_usage_percent",
                    value=(disk.used / disk.total) * 100,
                    metric_type=MetricType.GAUGE,
                    help_text="System disk usage percentage",
                )
            )

            # Network metrics
            network = psutil.net_io_counters()
            metrics.append(
                Metric(
                    name="system_network_bytes_sent_total",
                    value=network.bytes_sent,
                    metric_type=MetricType.COUNTER,
                    help_text="Total network bytes sent",
                )
            )

            metrics.append(
                Metric(
                    name="system_network_bytes_recv_total",
                    value=network.bytes_recv,
                    metric_type=MetricType.COUNTER,
                    help_text="Total network bytes received",
                )
            )

            # Process-specific metrics
            process_memory = self.process.memory_info()
            metrics.append(
                Metric(
                    name="process_memory_rss_bytes",
                    value=process_memory.rss,
                    metric_type=MetricType.GAUGE,
                    help_text="Process resident set size in bytes",
                )
            )

            metrics.append(
                Metric(
                    name="process_cpu_percent",
                    value=self.process.cpu_percent(),
                    metric_type=MetricType.GAUGE,
                    help_text="Process CPU usage percentage",
                )
            )

            metrics.append(
                Metric(
                    name="process_num_threads",
                    value=self.process.num_threads(),
                    metric_type=MetricType.GAUGE,
                    help_text="Number of process threads",
                )
            )

            # File descriptors
            try:
                metrics.append(
                    Metric(
                        name="process_open_fds",
                        value=self.process.num_fds(),
                        metric_type=MetricType.GAUGE,
                        help_text="Number of open file descriptors",
                    )
                )
            except AttributeError:
                # Windows doesn't have num_fds
                pass

        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")

        return metrics


class ApplicationMetricsCollector(BaseMetricsCollector):
    """Application-level metrics collector"""

    def __init__(self, service_name: str):
        self.service_name = service_name
        self.counters: Dict[str, float] = defaultdict(float)
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()

    def get_name(self) -> str:
        return f"application_{self.service_name}"

    def increment_counter(
        self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None
    ):
        """Increment counter metric"""
        key = f"{name}_{self._labels_to_key(labels)}"
        with self.lock:
            self.counters[key] += value

    def set_gauge(
        self, name: str, value: float, labels: Optional[Dict[str, str]] = None
    ):
        """Set gauge metric"""
        key = f"{name}_{self._labels_to_key(labels)}"
        with self.lock:
            self.gauges[key] = value

    def observe_histogram(
        self, name: str, value: float, labels: Optional[Dict[str, str]] = None
    ):
        """Observe histogram metric"""
        key = f"{name}_{self._labels_to_key(labels)}"
        with self.lock:
            self.histograms[key].append(value)
            # Keep only last 1000 observations to manage memory
            if len(self.histograms[key]) > 1000:
                self.histograms[key] = self.histograms[key][-1000:]

    def _labels_to_key(self, labels: Optional[Dict[str, str]]) -> str:
        """Convert labels to string key"""
        if not labels:
            return ""
        return "_".join(f"{k}_{v}" for k, v in sorted(labels.items()))

    async def collect_metrics(self) -> List[Metric]:
        """Collect application metrics"""
        metrics = []

        with self.lock:
            # Counter metrics
            for key, value in self.counters.items():
                name, labels_part = key.split("_", 1) if "_" in key else (key, "")
                labels = self._parse_labels_from_key(labels_part)
                labels["service"] = self.service_name

                metrics.append(
                    Metric(
                        name=name,
                        value=value,
                        metric_type=MetricType.COUNTER,
                        labels=labels,
                    )
                )

            # Gauge metrics
            for key, value in self.gauges.items():
                name, labels_part = key.split("_", 1) if "_" in key else (key, "")
                labels = self._parse_labels_from_key(labels_part)
                labels["service"] = self.service_name

                metrics.append(
                    Metric(
                        name=name,
                        value=value,
                        metric_type=MetricType.GAUGE,
                        labels=labels,
                    )
                )

            # Histogram metrics
            for key, values in self.histograms.items():
                if not values:
                    continue

                name, labels_part = key.split("_", 1) if "_" in key else (key, "")
                labels = self._parse_labels_from_key(labels_part)
                labels["service"] = self.service_name

                # Create histogram summary metrics
                metrics.extend(
                    [
                        Metric(
                            name=f"{name}_count",
                            value=len(values),
                            metric_type=MetricType.COUNTER,
                            labels=labels,
                        ),
                        Metric(
                            name=f"{name}_sum",
                            value=sum(values),
                            metric_type=MetricType.COUNTER,
                            labels=labels,
                        ),
                        Metric(
                            name=f"{name}_avg",
                            value=statistics.mean(values),
                            metric_type=MetricType.GAUGE,
                            labels=labels,
                        ),
                        Metric(
                            name=f"{name}_p50",
                            value=statistics.median(values),
                            metric_type=MetricType.GAUGE,
                            labels=labels,
                        ),
                        Metric(
                            name=f"{name}_p95",
                            value=(
                                statistics.quantiles(values, n=20)[18]
                                if len(values) > 1
                                else values[0]
                            ),
                            metric_type=MetricType.GAUGE,
                            labels=labels,
                        ),
                    ]
                )

        return metrics

    def _parse_labels_from_key(self, labels_part: str) -> Dict[str, str]:
        """Parse labels from key string"""
        labels = {}
        if labels_part:
            parts = labels_part.split("_")
            for i in range(0, len(parts) - 1, 2):
                if i + 1 < len(parts):
                    labels[parts[i]] = parts[i + 1]
        return labels


class AlertManager:
    """Alert management system"""

    def __init__(self):
        self.alert_rules: List[Dict[str, Any]] = []
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: deque = deque(maxlen=10000)
        self.handlers: List[Callable[[Alert], None]] = []

    def add_alert_rule(
        self,
        name: str,
        metric_name: str,
        condition: str,  # "gt", "lt", "eq", "ne"
        threshold: float,
        severity: AlertSeverity = AlertSeverity.WARNING,
        labels: Optional[Dict[str, str]] = None,
        message_template: str = "",
    ):
        """Add alert rule"""
        rule = {
            "name": name,
            "metric_name": metric_name,
            "condition": condition,
            "threshold": threshold,
            "severity": severity,
            "labels": labels or {},
            "message_template": message_template
            or f"{metric_name} {condition} {threshold}",
        }
        self.alert_rules.append(rule)

    def add_alert_handler(self, handler: Callable[[Alert], None]):
        """Add alert handler"""
        self.handlers.append(handler)

    async def evaluate_metrics(self, metrics: List[Metric]):
        """Evaluate metrics against alert rules"""
        for metric in metrics:
            await self._evaluate_metric_against_rules(metric)

    async def _evaluate_metric_against_rules(self, metric: Metric):
        """Evaluate single metric against all rules"""
        for rule in self.alert_rules:
            if not self._rule_matches_metric(rule, metric):
                continue

            should_alert = self._evaluate_condition(
                metric.value, rule["condition"], rule["threshold"]
            )

            alert_key = (
                f"{rule['name']}_{metric.name}_{self._labels_to_key(metric.labels)}"
            )

            if should_alert:
                if alert_key not in self.active_alerts:
                    # Create new alert
                    alert = Alert(
                        alert_id=str(uuid4()),
                        service=metric.labels.get("service", "unknown"),
                        metric_name=metric.name,
                        severity=rule["severity"],
                        message=rule["message_template"].format(
                            value=metric.value, threshold=rule["threshold"]
                        ),
                        value=metric.value,
                        threshold=rule["threshold"],
                        labels=metric.labels,
                    )

                    self.active_alerts[alert_key] = alert
                    self.alert_history.append(alert)

                    # Send to handlers
                    for handler in self.handlers:
                        try:
                            handler(alert)
                        except Exception as e:
                            logger.error(f"Alert handler error: {e}")

            else:
                # Resolve alert if it exists
                if alert_key in self.active_alerts:
                    alert = self.active_alerts[alert_key]
                    alert.resolved_at = datetime.utcnow()
                    del self.active_alerts[alert_key]

    def _rule_matches_metric(self, rule: Dict[str, Any], metric: Metric) -> bool:
        """Check if rule matches metric"""
        if rule["metric_name"] != metric.name:
            return False

        # Check label filters
        rule_labels = rule.get("labels", {})
        for key, value in rule_labels.items():
            if metric.labels.get(key) != value:
                return False

        return True

    def _evaluate_condition(
        self, value: float, condition: str, threshold: float
    ) -> bool:
        """Evaluate alert condition"""
        if condition == "gt":
            return value > threshold
        elif condition == "lt":
            return value < threshold
        elif condition == "eq":
            return abs(value - threshold) < 0.001
        elif condition == "ne":
            return abs(value - threshold) >= 0.001
        else:
            return False

    def _labels_to_key(self, labels: Dict[str, str]) -> str:
        """Convert labels to string key"""
        return "_".join(f"{k}_{v}" for k, v in sorted(labels.items()))

    def get_active_alerts(self) -> List[Alert]:
        """Get active alerts"""
        return list(self.active_alerts.values())

    def get_alert_history(self, limit: int = 100) -> List[Alert]:
        """Get alert history"""
        return list(self.alert_history)[-limit:]


class HealthMonitor:
    """Health monitoring system"""

    def __init__(self):
        self.health_checks: Dict[str, Callable[[], HealthCheck]] = {}
        self.health_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

    def register_health_check(self, name: str, check_func: Callable[[], HealthCheck]):
        """Register health check"""
        self.health_checks[name] = check_func

    async def run_health_checks(self) -> Dict[str, HealthCheck]:
        """Run all health checks"""
        results = {}

        for name, check_func in self.health_checks.items():
            try:
                start_time = time.time()
                result = check_func()
                result.response_time = time.time() - start_time

                results[name] = result
                self.health_history[name].append(result)

            except Exception as e:
                logger.error(f"Health check {name} failed: {e}")
                result = HealthCheck(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    response_time=0.0,
                    message=f"Health check failed: {str(e)}",
                )
                results[name] = result
                self.health_history[name].append(result)

        return results

    def get_overall_health(self) -> HealthStatus:
        """Get overall system health"""
        if not self.health_checks:
            return HealthStatus.UNKNOWN

        # Get latest results
        latest_results = {}
        for name, history in self.health_history.items():
            if history:
                latest_results[name] = history[-1]

        if not latest_results:
            return HealthStatus.UNKNOWN

        # Determine overall status
        statuses = [result.status for result in latest_results.values()]

        if all(status == HealthStatus.HEALTHY for status in statuses):
            return HealthStatus.HEALTHY
        elif any(status == HealthStatus.UNHEALTHY for status in statuses):
            return HealthStatus.UNHEALTHY
        else:
            return HealthStatus.DEGRADED


class PerformanceProfiler:
    """Performance profiling system"""

    def __init__(self):
        self.active_profiles: Dict[str, PerformanceProfile] = {}
        self.completed_profiles: deque = deque(maxlen=10000)

    @asynccontextmanager
    async def profile_operation(self, service: str, operation: str):
        """Context manager for profiling operations"""
        profile_id = str(uuid4())
        start_time = datetime.utcnow()

        # Get initial resource usage
        process = psutil.Process()
        initial_cpu = process.cpu_percent()
        initial_memory = process.memory_info().rss
        initial_io = process.io_counters() if hasattr(process, "io_counters") else None
        initial_net = psutil.net_io_counters()

        profile = PerformanceProfile(
            profile_id=profile_id,
            service=service,
            operation=operation,
            start_time=start_time,
            end_time=start_time,  # Will be updated
            duration=0.0,
            cpu_usage=0.0,
            memory_usage=initial_memory,
            io_operations=0,
            network_bytes=0,
        )

        self.active_profiles[profile_id] = profile

        try:
            yield profile
        finally:
            # Calculate final metrics
            end_time = datetime.utcnow()
            profile.end_time = end_time
            profile.duration = (end_time - start_time).total_seconds()

            try:
                final_cpu = process.cpu_percent()
                final_memory = process.memory_info().rss
                final_io = (
                    process.io_counters() if hasattr(process, "io_counters") else None
                )
                final_net = psutil.net_io_counters()

                profile.cpu_usage = max(0, final_cpu - initial_cpu)
                profile.memory_usage = final_memory - initial_memory

                if initial_io and final_io:
                    profile.io_operations = (
                        final_io.read_count - initial_io.read_count
                    ) + (final_io.write_count - initial_io.write_count)

                profile.network_bytes = (
                    final_net.bytes_sent - initial_net.bytes_sent
                ) + (final_net.bytes_recv - initial_net.bytes_recv)

            except Exception as e:
                logger.error(f"Error calculating profile metrics: {e}")

            # Move to completed profiles
            self.completed_profiles.append(profile)
            del self.active_profiles[profile_id]

    def get_profile_stats(
        self, service: Optional[str] = None, operation: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get profiling statistics"""
        profiles = list(self.completed_profiles)

        # Filter profiles
        if service:
            profiles = [p for p in profiles if p.service == service]
        if operation:
            profiles = [p for p in profiles if p.operation == operation]

        if not profiles:
            return {}

        durations = [p.duration for p in profiles]
        cpu_usages = [p.cpu_usage for p in profiles]
        memory_usages = [p.memory_usage for p in profiles]

        return {
            "count": len(profiles),
            "avg_duration": statistics.mean(durations),
            "p50_duration": statistics.median(durations),
            "p95_duration": (
                statistics.quantiles(durations, n=20)[18]
                if len(durations) > 1
                else durations[0]
            ),
            "avg_cpu_usage": statistics.mean(cpu_usages),
            "avg_memory_usage": statistics.mean(memory_usages),
            "total_io_operations": sum(p.io_operations for p in profiles),
            "total_network_bytes": sum(p.network_bytes for p in profiles),
        }


class PerformanceMonitor:
    """Main performance monitoring system"""

    def __init__(self, service_name: str, config: Optional[Dict[str, Any]] = None):
        self.service_name = service_name
        self.config = config or {}

        # Components
        self.collectors: List[BaseMetricsCollector] = []
        self.alert_manager = AlertManager()
        self.health_monitor = HealthMonitor()
        self.profiler = PerformanceProfiler()

        # Task management
        self.task_manager: Optional[AsyncTaskManager] = None
        self.monitoring_tasks: List[asyncio.Task] = []
        self.running = False

        # Metrics storage
        self.metrics_cache: Optional[CacheManager] = None

        # Prometheus integration
        self.prometheus_registry = None
        if HAS_PROMETHEUS:
            self.prometheus_registry = CollectorRegistry()

    async def initialize(self):
        """Initialize monitoring system"""
        # Initialize task manager
        self.task_manager = AsyncTaskManager()
        await self.task_manager.start()

        # Initialize metrics cache
        self.metrics_cache = CacheManager()
        cache_config = CacheConfig(
            max_size=50000, default_ttl=300.0, eviction_policy="lru"  # 5 minutes
        )
        self.metrics_cache.create_memory_cache("metrics", cache_config)

        # Add default collectors
        self.collectors.append(SystemMetricsCollector())
        self.collectors.append(ApplicationMetricsCollector(self.service_name))

        # Set up default alert rules
        self._setup_default_alerts()

        # Set up default health checks
        self._setup_default_health_checks()

        # Add default alert handler
        self.alert_manager.add_alert_handler(self._default_alert_handler)

        logger.info(f"Performance monitor initialized for {self.service_name}")

    async def start(self):
        """Start monitoring"""
        self.running = True

        # Start metrics collection
        task = asyncio.create_task(self._metrics_collection_loop())
        self.monitoring_tasks.append(task)

        # Start health monitoring
        task = asyncio.create_task(self._health_monitoring_loop())
        self.monitoring_tasks.append(task)

        # Start alert evaluation
        task = asyncio.create_task(self._alert_evaluation_loop())
        self.monitoring_tasks.append(task)

        logger.info(f"Performance monitoring started for {self.service_name}")

    async def stop(self):
        """Stop monitoring"""
        self.running = False

        # Cancel monitoring tasks
        for task in self.monitoring_tasks:
            task.cancel()

        if self.monitoring_tasks:
            await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)

        # Shutdown components
        if self.task_manager:
            await self.task_manager.stop()

        if self.metrics_cache:
            await self.metrics_cache.close_all()

        logger.info(f"Performance monitoring stopped for {self.service_name}")

    def _setup_default_alerts(self):
        """Set up default alert rules"""
        # High CPU usage
        self.alert_manager.add_alert_rule(
            name="high_cpu_usage",
            metric_name="system_cpu_usage_percent",
            condition="gt",
            threshold=80.0,
            severity=AlertSeverity.WARNING,
            message_template="High CPU usage: {value:.1f}% > {threshold:.1f}%",
        )

        # High memory usage
        self.alert_manager.add_alert_rule(
            name="high_memory_usage",
            metric_name="system_memory_usage_percent",
            condition="gt",
            threshold=85.0,
            severity=AlertSeverity.WARNING,
            message_template="High memory usage: {value:.1f}% > {threshold:.1f}%",
        )

        # Low disk space
        self.alert_manager.add_alert_rule(
            name="low_disk_space",
            metric_name="system_disk_usage_percent",
            condition="gt",
            threshold=90.0,
            severity=AlertSeverity.CRITICAL,
            message_template="Low disk space: {value:.1f}% > {threshold:.1f}%",
        )

    def _setup_default_health_checks(self):
        """Set up default health checks"""

        def system_health_check() -> HealthCheck:
            try:
                cpu_percent = psutil.cpu_percent(interval=0.1)
                memory_percent = psutil.virtual_memory().percent

                if cpu_percent > 95 or memory_percent > 95:
                    status = HealthStatus.UNHEALTHY
                    message = f"High resource usage: CPU {cpu_percent:.1f}%, Memory {memory_percent:.1f}%"
                elif cpu_percent > 80 or memory_percent > 80:
                    status = HealthStatus.DEGRADED
                    message = f"Moderate resource usage: CPU {cpu_percent:.1f}%, Memory {memory_percent:.1f}%"
                else:
                    status = HealthStatus.HEALTHY
                    message = f"Normal resource usage: CPU {cpu_percent:.1f}%, Memory {memory_percent:.1f}%"

                return HealthCheck(
                    name="system_resources",
                    status=status,
                    response_time=0.0,
                    message=message,
                    details={
                        "cpu_percent": cpu_percent,
                        "memory_percent": memory_percent,
                    },
                )

            except Exception as e:
                return HealthCheck(
                    name="system_resources",
                    status=HealthStatus.UNHEALTHY,
                    response_time=0.0,
                    message=f"Health check failed: {str(e)}",
                )

        self.health_monitor.register_health_check("system", system_health_check)

    def _default_alert_handler(self, alert: Alert):
        """Default alert handler"""
        logger.warning(
            f"ALERT [{alert.severity.value.upper()}] {alert.service}: {alert.message}"
        )

    async def _metrics_collection_loop(self):
        """Metrics collection loop"""
        interval = self.config.get("metrics_interval", 30.0)

        while self.running:
            try:
                await self._collect_all_metrics()
                await asyncio.sleep(interval)

            except Exception as e:
                logger.error(f"Metrics collection error: {e}")
                await asyncio.sleep(5.0)

    async def _health_monitoring_loop(self):
        """Health monitoring loop"""
        interval = self.config.get("health_check_interval", 60.0)

        while self.running:
            try:
                await self.health_monitor.run_health_checks()
                await asyncio.sleep(interval)

            except Exception as e:
                logger.error(f"Health monitoring error: {e}")
                await asyncio.sleep(5.0)

    async def _alert_evaluation_loop(self):
        """Alert evaluation loop"""
        interval = self.config.get("alert_evaluation_interval", 15.0)

        while self.running:
            try:
                # Get recent metrics from cache
                cache = self.metrics_cache.get_cache("metrics")
                if cache:
                    recent_metrics_data = await cache.get("recent_metrics")
                    if recent_metrics_data:
                        recent_metrics = [Metric(**m) for m in recent_metrics_data]
                        await self.alert_manager.evaluate_metrics(recent_metrics)

                await asyncio.sleep(interval)

            except Exception as e:
                logger.error(f"Alert evaluation error: {e}")
                await asyncio.sleep(5.0)

    async def _collect_all_metrics(self):
        """Collect metrics from all collectors"""
        all_metrics = []

        for collector in self.collectors:
            try:
                metrics = await collector.collect_metrics()
                all_metrics.extend(metrics)
            except Exception as e:
                logger.error(
                    f"Error collecting metrics from {collector.get_name()}: {e}"
                )

        # Cache metrics
        if self.metrics_cache:
            cache = self.metrics_cache.get_cache("metrics")
            if cache:
                metrics_data = [m.to_dict() for m in all_metrics]
                await cache.set("recent_metrics", metrics_data, ttl=300.0)

        logger.debug(f"Collected {len(all_metrics)} metrics")

    def get_application_collector(self) -> ApplicationMetricsCollector:
        """Get application metrics collector"""
        for collector in self.collectors:
            if isinstance(collector, ApplicationMetricsCollector):
                return collector
        raise RuntimeError("Application metrics collector not found")

    def add_collector(self, collector: BaseMetricsCollector):
        """Add custom metrics collector"""
        self.collectors.append(collector)

    async def get_current_metrics(self) -> List[Metric]:
        """Get current metrics"""
        all_metrics = []

        for collector in self.collectors:
            try:
                metrics = await collector.collect_metrics()
                all_metrics.extend(metrics)
            except Exception as e:
                logger.error(f"Error collecting metrics: {e}")

        return all_metrics

    async def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary"""
        metrics = await self.get_current_metrics()
        active_alerts = self.alert_manager.get_active_alerts()
        health_results = await self.health_monitor.run_health_checks()
        overall_health = self.health_monitor.get_overall_health()

        return {
            "service": self.service_name,
            "timestamp": datetime.utcnow().isoformat(),
            "overall_health": overall_health.value,
            "metrics_count": len(metrics),
            "active_alerts_count": len(active_alerts),
            "health_checks": {
                name: result.status.value for name, result in health_results.items()
            },
            "active_alerts": [
                {
                    "id": alert.alert_id,
                    "severity": alert.severity.value,
                    "message": alert.message,
                    "metric": alert.metric_name,
                }
                for alert in active_alerts
            ],
        }

    def profile_operation(self, operation: str):
        """Get profiler context manager for operation"""
        return self.profiler.profile_operation(self.service_name, operation)


# Global performance monitor instance
_global_monitor: Optional[PerformanceMonitor] = None


async def initialize_global_monitor(
    service_name: str, config: Optional[Dict[str, Any]] = None
) -> PerformanceMonitor:
    """Initialize global performance monitor"""
    global _global_monitor
    _global_monitor = PerformanceMonitor(service_name, config)
    await _global_monitor.initialize()
    await _global_monitor.start()
    return _global_monitor


def get_global_monitor() -> PerformanceMonitor:
    """Get global performance monitor"""
    if _global_monitor is None:
        raise RuntimeError("Global performance monitor not initialized")
    return _global_monitor


async def cleanup_global_monitor():
    """Cleanup global performance monitor"""
    global _global_monitor
    if _global_monitor is not None:
        await _global_monitor.stop()
        _global_monitor = None
