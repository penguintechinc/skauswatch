"""
SkausWatch AAA Monitor Service - Configuration

Configuration management for the AAA monitor service supporting
environment variables, YAML, and JSON configuration files.
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class RedisConfig:
    """Redis configuration"""

    enabled: bool = True
    url: str = "redis://localhost:6379/0"
    password: Optional[str] = None
    ssl: bool = False
    timeout: int = 5


@dataclass
class DatabaseConfig:
    """Database configuration"""

    type: str = "postgresql"  # postgresql, mysql, sqlite
    host: str = "localhost"
    port: int = 5432
    database: str = "aaa_monitor"
    username: str = "postgres"
    password: str = ""
    pool_size: int = 20
    ssl: bool = False


@dataclass
class LoggingConfig:
    """Logging configuration"""

    level: str = "INFO"
    format: str = "json"
    file_path: Optional[str] = None
    max_file_size: str = "100MB"
    backup_count: int = 5
    structured: bool = True


@dataclass
class APIConfig:
    """API configuration"""

    host: str = "0.0.0.0"
    port: int = 8003
    docs_enabled: bool = True
    cors_enabled: bool = True
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    cors_methods: List[str] = field(
        default_factory=lambda: ["GET", "POST", "PUT", "DELETE"]
    )
    cors_headers: List[str] = field(default_factory=lambda: ["*"])
    rate_limit: str = "1000/hour"
    max_request_size: str = "16MB"


@dataclass
class SecurityConfig:
    """Security configuration"""

    secret_key: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expiration: int = 3600
    trusted_hosts: List[str] = field(default_factory=list)
    require_https: bool = False
    auth_enabled: bool = True


@dataclass
class KubernetesAPI:
    """Kubernetes API connection configuration"""

    server: str = "https://kubernetes.default.svc"
    token_file: Optional[str] = None
    token: Optional[str] = None
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    ca_file: Optional[str] = None
    verify_ssl: bool = True
    timeout: int = 30
    max_retries: int = 3
    retry_delay: int = 5


@dataclass
class KubernetesCollectorConfig:
    """Kubernetes collector configuration - fully clientless via APIs"""

    enabled: bool = True

    # API connections - support multiple clusters
    api_servers: List[KubernetesAPI] = field(default_factory=lambda: [KubernetesAPI()])

    # Collection settings
    namespaces: List[str] = field(default_factory=lambda: ["default"])
    collect_pod_logs: bool = True
    collect_events: bool = True
    collect_audit_logs: bool = True
    monitor_rbac: bool = True

    # API polling settings
    log_poll_interval: int = 30
    event_watch_timeout: int = 300
    rbac_check_interval: int = 60
    audit_log_poll_interval: int = 60

    # Log streaming settings
    log_lines_per_request: int = 1000
    log_follow_timeout: int = 60
    log_since_seconds: int = 300

    # Connection pooling
    max_connections: int = 20
    connection_pool_size: int = 10

    # Rate limiting
    api_rate_limit: int = 1000  # requests per minute
    backoff_multiplier: float = 1.5
    max_backoff_delay: int = 60


@dataclass
class LXDEndpoint:
    """LXD API endpoint configuration"""

    url: str = "https://localhost:8443"
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    server_cert_file: Optional[str] = None
    verify_ssl: bool = True
    timeout: int = 30


@dataclass
class LXCCollectorConfig:
    """LXC/LXD collector configuration - fully clientless via REST API"""

    enabled: bool = True

    # LXD REST API endpoints - support multiple LXD hosts
    lxd_endpoints: List[LXDEndpoint] = field(default_factory=lambda: [LXDEndpoint()])
    unix_socket_path: Optional[str] = "/var/snap/lxd/common/lxd/unix.socket"

    # Collection settings
    collect_container_logs: bool = True
    collect_system_logs: bool = True
    monitor_events: bool = True
    monitor_resource_usage: bool = True

    # API polling settings
    discovery_interval: int = 60
    log_poll_interval: int = 30
    system_log_interval: int = 60
    event_monitor_interval: int = 30
    metrics_interval: int = 60

    # WebSocket settings for real-time events
    websocket_timeout: int = 300
    websocket_ping_interval: int = 30

    # Connection settings
    max_connections: int = 10
    connection_timeout: int = 30

    # Rate limiting
    api_rate_limit: int = 500  # requests per minute
    backoff_multiplier: float = 1.5
    max_backoff_delay: int = 60


@dataclass
class SyslogServer:
    """Syslog server configuration for centralized logs"""

    host: str
    port: int = 514
    protocol: str = "tcp"  # tcp, udp, tls
    tls_cert: Optional[str] = None
    tls_key: Optional[str] = None
    tls_ca: Optional[str] = None


@dataclass
class SSHConnection:
    """SSH connection for direct log access"""

    host: str
    port: int = 22
    username: str
    password: Optional[str] = None
    key_file: Optional[str] = None
    key_passphrase: Optional[str] = None


@dataclass
class JournaldAPI:
    """Systemd journald API configuration"""

    host: str = "localhost"
    port: int = 19531  # systemd-journal-remote default port
    ssl: bool = False
    cert_file: Optional[str] = None
    key_file: Optional[str] = None


@dataclass
class AuditdCollectorConfig:
    """Auditd collector configuration - completely clientless"""

    enabled: bool = True

    # Centralized syslog servers
    syslog_servers: List[SyslogServer] = field(default_factory=list)

    # SSH connections to hypervisors
    ssh_connections: List[SSHConnection] = field(default_factory=list)

    # Journald API endpoints
    journald_endpoints: List[JournaldAPI] = field(default_factory=list)

    # ELK Stack integration
    elasticsearch_url: Optional[str] = None
    elasticsearch_username: Optional[str] = None
    elasticsearch_password: Optional[str] = None
    elasticsearch_index_pattern: str = "auditd-*"

    # Splunk integration
    splunk_url: Optional[str] = None
    splunk_token: Optional[str] = None
    splunk_index: str = "audit"

    # Collection settings
    collect_audit_logs: bool = True
    collect_auth_logs: bool = True
    analyze_syscalls: bool = True

    # Polling intervals
    audit_poll_interval: int = 5
    auth_poll_interval: int = 10
    syslog_poll_interval: int = 15
    ssh_poll_interval: int = 30

    # Connection settings
    connection_timeout: int = 30
    max_connections_per_host: int = 5
    ssh_keepalive_interval: int = 30

    # Rate limiting
    api_rate_limit: int = 200  # requests per minute per endpoint
    backoff_multiplier: float = 1.5
    max_backoff_delay: int = 60


@dataclass
class SyslogCollectorConfig:
    """Syslog collector for RFC3164/RFC5424 messages"""

    enabled: bool = True
    servers: List[SyslogServer] = field(default_factory=list)
    listen_port: int = 514
    listen_address: str = "0.0.0.0"
    protocol: str = "both"  # tcp, udp, both
    max_message_size: int = 65536


@dataclass
class JournaldCollectorConfig:
    """Journald collector using systemd APIs"""

    enabled: bool = True
    endpoints: List[JournaldAPI] = field(default_factory=list)
    units: List[str] = field(default_factory=list)  # specific systemd units to monitor
    poll_interval: int = 30


@dataclass
class FileCollectorConfig:
    """File-based collector for network-mounted logs"""

    enabled: bool = True
    mount_points: List[str] = field(default_factory=list)
    file_patterns: List[str] = field(default_factory=lambda: ["*.log", "*.txt"])
    poll_interval: int = 60
    use_inotify: bool = True


@dataclass
class DatabaseCollectorConfig:
    """Database collector for logs stored in databases"""

    enabled: bool = True
    connections: List[Dict[str, Any]] = field(default_factory=list)  # DB connections
    queries: List[Dict[str, Any]] = field(
        default_factory=list
    )  # SQL queries to execute
    poll_interval: int = 300


@dataclass
class CollectorsConfig:
    """Log collectors configuration - all clientless"""

    kubernetes: KubernetesCollectorConfig = field(
        default_factory=KubernetesCollectorConfig
    )
    lxc_lxd: LXCCollectorConfig = field(default_factory=LXCCollectorConfig)
    auditd: AuditdCollectorConfig = field(default_factory=AuditdCollectorConfig)
    syslog: SyslogCollectorConfig = field(default_factory=SyslogCollectorConfig)
    journald: JournaldCollectorConfig = field(default_factory=JournaldCollectorConfig)
    file: FileCollectorConfig = field(default_factory=FileCollectorConfig)
    database: DatabaseCollectorConfig = field(default_factory=DatabaseCollectorConfig)


@dataclass
class LogProcessingConfig:
    """Log processing configuration"""

    worker_count: int = 4
    queue_max_size: int = 10000
    hp_queue_max_size: int = 1000
    rate_limit_events: int = 1000
    rate_limit_window: int = 60
    dedup_window_minutes: int = 5
    geolocation: Dict[str, Any] = field(default_factory=dict)
    elasticsearch: Dict[str, Any] = field(default_factory=dict)
    mongodb: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ClassificationConfig:
    """Event classification configuration"""

    model_dir: str = "/app/models"
    max_training_samples: int = 10000
    retrain_interval: int = 1000
    max_features: int = 1000


@dataclass
class BufferConfig:
    """Buffer management configuration"""

    max_buffer_size: int = 1000
    flush_interval_seconds: int = 60
    batch_size: int = 100
    compression_enabled: bool = True
    backpressure_threshold: float = 0.8
    drop_threshold: float = 0.95
    persistent_storage: bool = True


@dataclass
class TAXIIConfig:
    """TAXII client configuration"""

    enabled: bool = True
    feeds: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ThreatIntelConfig:
    """Threat intelligence configuration"""

    database_path: str = "/app/data/threat.db"
    minimum_confidence: float = 0.3
    enable_fuzzy_matching: bool = True
    fuzzy_threshold: float = 0.8
    match_cache_ttl: int = 3600
    taxii: TAXIIConfig = field(default_factory=TAXIIConfig)


@dataclass
class OpenAIConfig:
    """OpenAI configuration"""

    enabled: bool = False
    api_key: str = ""
    model: str = "gpt-3.5-turbo"
    max_tokens: int = 1000
    temperature: float = 0.1
    timeout: int = 30


@dataclass
class AnthropicConfig:
    """Anthropic Claude configuration"""

    enabled: bool = False
    api_key: str = ""
    model: str = "claude-3-sonnet-20240229"
    max_tokens: int = 1000
    timeout: int = 30


@dataclass
class OllamaConfig:
    """Ollama configuration"""

    enabled: bool = False
    base_url: str = "http://localhost:11434"
    model: str = "llama2"
    timeout: int = 60


@dataclass
class AIConfig:
    """AI integration configuration"""

    enabled: bool = True
    default_provider: str = "openai"
    fallback_providers: List[str] = field(default_factory=lambda: ["ollama"])
    cache_ttl: int = 3600
    max_concurrent_requests: int = 5
    openai: OpenAIConfig = field(default_factory=OpenAIConfig)
    anthropic: AnthropicConfig = field(default_factory=AnthropicConfig)
    ollama: OllamaConfig = field(default_factory=OllamaConfig)


@dataclass
class PatternDetectionConfig:
    """Pattern detection configuration"""

    enabled: bool = True
    time_window: int = 300  # 5 minutes
    min_events: int = 5
    confidence_threshold: float = 0.7


@dataclass
class AnomalyDetectionConfig:
    """Anomaly detection configuration"""

    enabled: bool = True
    algorithm: str = (
        "isolation_forest"  # isolation_forest, one_class_svm, local_outlier_factor
    )
    contamination: float = 0.1
    window_size: int = 1000
    threshold: float = 0.8


@dataclass
class AlertingConfig:
    """Alerting configuration"""

    enabled: bool = True
    webhooks: List[str] = field(default_factory=list)
    email_smtp: Dict[str, Any] = field(default_factory=dict)
    slack_webhook: Optional[str] = None
    pagerduty_key: Optional[str] = None
    severity_thresholds: Dict[str, str] = field(
        default_factory=lambda: {
            "critical": "immediate",
            "high": "5m",
            "medium": "15m",
            "low": "1h",
        }
    )


@dataclass
class EscalationConfig:
    """Alert escalation configuration"""

    enabled: bool = True
    escalation_rules: List[Dict[str, Any]] = field(default_factory=list)
    max_escalation_level: int = 3
    escalation_timeout: int = 1800  # 30 minutes


@dataclass
class AnalysisConfig:
    """Analysis engine configuration"""

    enabled: bool = True
    batch_size: int = 100
    processing_interval: int = 30
    correlation_window: int = 600  # 10 minutes
    ai_analysis_threshold: int = 10  # events before triggering AI


@dataclass
class HealthCheckConfig:
    """Health check configuration"""

    enabled: bool = True
    check_interval: int = 30
    timeout: int = 10
    checks: List[str] = field(
        default_factory=lambda: [
            "database",
            "redis",
            "collectors",
            "threat_intel",
            "ai_providers",
        ]
    )


class AAAMonitorConfig:
    """Main configuration class for AAA Monitor service"""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration

        Args:
            config_path: Optional path to configuration file
        """
        self.config_path = config_path
        self._load_configuration()

    def _load_configuration(self):
        """Load configuration from file and environment variables"""
        try:
            # Default configuration
            config_dict = {}

            # Load from file if provided
            if self.config_path and Path(self.config_path).exists():
                config_dict = self._load_config_file(self.config_path)

            # Override with environment variables
            config_dict = self._apply_env_overrides(config_dict)

            # Create configuration objects
            self.redis = RedisConfig(**config_dict.get("redis", {}))
            self.database = DatabaseConfig(**config_dict.get("database", {}))
            self.logging = LoggingConfig(**config_dict.get("logging", {}))
            self.api = APIConfig(**config_dict.get("api", {}))
            self.security = SecurityConfig(**config_dict.get("security", {}))

            # Collectors
            collectors_config = config_dict.get("collectors", {})

            # Build Kubernetes API servers list
            k8s_config = collectors_config.get("kubernetes", {})
            k8s_apis = []
            if k8s_config.get("api_servers"):
                for api_config in k8s_config["api_servers"]:
                    k8s_apis.append(KubernetesAPI(**api_config))
            elif not k8s_apis:
                k8s_apis = [KubernetesAPI()]
            k8s_config["api_servers"] = k8s_apis

            # Build LXD endpoints list
            lxd_config = collectors_config.get("lxc_lxd", {})
            lxd_endpoints = []
            if lxd_config.get("lxd_endpoints"):
                for endpoint_config in lxd_config["lxd_endpoints"]:
                    lxd_endpoints.append(LXDEndpoint(**endpoint_config))
            elif not lxd_endpoints:
                lxd_endpoints = [LXDEndpoint()]
            lxd_config["lxd_endpoints"] = lxd_endpoints

            # Build auditd sources
            auditd_config = collectors_config.get("auditd", {})
            # Build syslog servers
            if auditd_config.get("syslog_servers"):
                servers = []
                for server_config in auditd_config["syslog_servers"]:
                    servers.append(SyslogServer(**server_config))
                auditd_config["syslog_servers"] = servers

            # Build SSH connections
            if auditd_config.get("ssh_connections"):
                connections = []
                for conn_config in auditd_config["ssh_connections"]:
                    connections.append(SSHConnection(**conn_config))
                auditd_config["ssh_connections"] = connections

            # Build journald endpoints
            if auditd_config.get("journald_endpoints"):
                endpoints = []
                for endpoint_config in auditd_config["journald_endpoints"]:
                    endpoints.append(JournaldAPI(**endpoint_config))
                auditd_config["journald_endpoints"] = endpoints

            # Build other collector configs
            syslog_config = collectors_config.get("syslog", {})
            if syslog_config.get("servers"):
                servers = []
                for server_config in syslog_config["servers"]:
                    servers.append(SyslogServer(**server_config))
                syslog_config["servers"] = servers

            journald_config = collectors_config.get("journald", {})
            if journald_config.get("endpoints"):
                endpoints = []
                for endpoint_config in journald_config["endpoints"]:
                    endpoints.append(JournaldAPI(**endpoint_config))
                journald_config["endpoints"] = endpoints

            self.collectors = CollectorsConfig(
                kubernetes=KubernetesCollectorConfig(**k8s_config),
                lxc_lxd=LXCCollectorConfig(**lxd_config),
                auditd=AuditdCollectorConfig(**auditd_config),
                syslog=SyslogCollectorConfig(**syslog_config),
                journald=JournaldCollectorConfig(**journald_config),
                file=FileCollectorConfig(**collectors_config.get("file", {})),
                database=DatabaseCollectorConfig(
                    **collectors_config.get("database", {})
                ),
            )

            # Processing
            self.log_processing = LogProcessingConfig(
                **config_dict.get("log_processing", {})
            )
            self.classification = ClassificationConfig(
                **config_dict.get("classification", {})
            )
            self.buffer = BufferConfig(**config_dict.get("buffer", {}))

            # Threat Intelligence
            threat_intel_config = config_dict.get("threat_intel", {})
            taxii_config = threat_intel_config.get("taxii", {})
            self.threat_intel = ThreatIntelConfig(
                **{k: v for k, v in threat_intel_config.items() if k != "taxii"},
                taxii=TAXIIConfig(**taxii_config),
            )

            # AI Integration
            ai_config = config_dict.get("ai", {})
            self.ai = AIConfig(
                **{
                    k: v
                    for k, v in ai_config.items()
                    if k not in ["openai", "anthropic", "ollama"]
                },
                openai=OpenAIConfig(**ai_config.get("openai", {})),
                anthropic=AnthropicConfig(**ai_config.get("anthropic", {})),
                ollama=OllamaConfig(**ai_config.get("ollama", {})),
            )

            # Analysis and Alerting
            self.pattern_detection = PatternDetectionConfig(
                **config_dict.get("pattern_detection", {})
            )
            self.anomaly_detection = AnomalyDetectionConfig(
                **config_dict.get("anomaly_detection", {})
            )
            self.analysis = AnalysisConfig(**config_dict.get("analysis", {}))
            self.alerting = AlertingConfig(**config_dict.get("alerting", {}))
            self.escalation = EscalationConfig(**config_dict.get("escalation", {}))

            # Health Check
            self.health_check = HealthCheckConfig(**config_dict.get("health_check", {}))

            # Generate secret key if not provided
            if not self.security.secret_key:
                import secrets

                self.security.secret_key = secrets.token_urlsafe(32)

            logger.info(
                "Configuration loaded successfully", config_path=self.config_path
            )

        except Exception as e:
            logger.error("Failed to load configuration", error=str(e))
            raise

    def _load_config_file(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            config_file = Path(config_path)

            with open(config_file, "r") as f:
                if (
                    config_file.suffix.lower() == ".yaml"
                    or config_file.suffix.lower() == ".yml"
                ):
                    return yaml.safe_load(f)
                elif config_file.suffix.lower() == ".json":
                    return json.load(f)
                else:
                    raise ValueError(
                        f"Unsupported configuration file format: {config_file.suffix}"
                    )

        except Exception as e:
            logger.error(
                "Failed to load configuration file", path=config_path, error=str(e)
            )
            raise

    def _apply_env_overrides(self, config_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Apply environment variable overrides"""
        try:
            # Environment variable mappings
            env_mappings = {
                "AAA_REDIS_URL": ("redis", "url"),
                "AAA_REDIS_PASSWORD": ("redis", "password"),
                "AAA_DATABASE_HOST": ("database", "host"),
                "AAA_DATABASE_PORT": ("database", "port"),
                "AAA_DATABASE_NAME": ("database", "database"),
                "AAA_DATABASE_USER": ("database", "username"),
                "AAA_DATABASE_PASSWORD": ("database", "password"),
                "AAA_LOG_LEVEL": ("logging", "level"),
                "AAA_API_HOST": ("api", "host"),
                "AAA_API_PORT": ("api", "port"),
                "AAA_SECRET_KEY": ("security", "secret_key"),
                "AAA_OPENAI_API_KEY": ("ai", "openai", "api_key"),
                "AAA_ANTHROPIC_API_KEY": ("ai", "anthropic", "api_key"),
                "AAA_OLLAMA_URL": ("ai", "ollama", "base_url"),
            }

            for env_var, config_path in env_mappings.items():
                value = os.environ.get(env_var)
                if value:
                    self._set_nested_value(config_dict, config_path, value)

            # Boolean environment variables
            bool_mappings = {
                "AAA_KUBERNETES_ENABLED": ("collectors", "kubernetes", "enabled"),
                "AAA_LXC_ENABLED": ("collectors", "lxc_lxd", "enabled"),
                "AAA_AUDITD_ENABLED": ("collectors", "auditd", "enabled"),
                "AAA_AI_ENABLED": ("ai", "enabled"),
                "AAA_OPENAI_ENABLED": ("ai", "openai", "enabled"),
                "AAA_ANTHROPIC_ENABLED": ("ai", "anthropic", "enabled"),
                "AAA_OLLAMA_ENABLED": ("ai", "ollama", "enabled"),
            }

            for env_var, config_path in bool_mappings.items():
                value = os.environ.get(env_var)
                if value:
                    bool_value = value.lower() in ("true", "1", "yes", "on")
                    self._set_nested_value(config_dict, config_path, bool_value)

            # Integer environment variables
            int_mappings = {
                "AAA_DATABASE_PORT": ("database", "port"),
                "AAA_API_PORT": ("api", "port"),
                "AAA_WORKER_COUNT": ("log_processing", "worker_count"),
                "AAA_BATCH_SIZE": ("buffer", "batch_size"),
            }

            for env_var, config_path in int_mappings.items():
                value = os.environ.get(env_var)
                if value:
                    try:
                        int_value = int(value)
                        self._set_nested_value(config_dict, config_path, int_value)
                    except ValueError:
                        logger.warning(
                            "Invalid integer value for environment variable",
                            var=env_var,
                            value=value,
                        )

            return config_dict

        except Exception as e:
            logger.error("Failed to apply environment overrides", error=str(e))
            return config_dict

    def _set_nested_value(self, config_dict: Dict[str, Any], path: tuple, value: Any):
        """Set nested configuration value"""
        current = config_dict

        # Navigate to the parent dictionary
        for key in path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]

        # Set the final value
        current[path[-1]] = value

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            "redis": self.redis.__dict__,
            "database": self.database.__dict__,
            "logging": self.logging.__dict__,
            "api": self.api.__dict__,
            "security": {
                k: v for k, v in self.security.__dict__.items() if k != "secret_key"
            },
            "collectors": {
                "kubernetes": self.collectors.kubernetes.__dict__,
                "lxc_lxd": self.collectors.lxc_lxd.__dict__,
                "auditd": self.collectors.auditd.__dict__,
                "syslog": self.collectors.syslog.__dict__,
                "journald": self.collectors.journald.__dict__,
                "file": self.collectors.file.__dict__,
                "database": self.collectors.database.__dict__,
            },
            "log_processing": self.log_processing.__dict__,
            "classification": self.classification.__dict__,
            "buffer": self.buffer.__dict__,
            "threat_intel": {
                **{k: v for k, v in self.threat_intel.__dict__.items() if k != "taxii"},
                "taxii": self.threat_intel.taxii.__dict__,
            },
            "ai": {
                **{
                    k: v
                    for k, v in self.ai.__dict__.items()
                    if k not in ["openai", "anthropic", "ollama"]
                },
                "openai": {
                    k: v for k, v in self.ai.openai.__dict__.items() if k != "api_key"
                },
                "anthropic": {
                    k: v
                    for k, v in self.ai.anthropic.__dict__.items()
                    if k != "api_key"
                },
                "ollama": self.ai.ollama.__dict__,
            },
            "pattern_detection": self.pattern_detection.__dict__,
            "anomaly_detection": self.anomaly_detection.__dict__,
            "analysis": self.analysis.__dict__,
            "alerting": self.alerting.__dict__,
            "escalation": self.escalation.__dict__,
            "health_check": self.health_check.__dict__,
        }

    def save_to_file(self, file_path: str):
        """Save configuration to file

        Args:
            file_path: Path to save configuration file
        """
        try:
            config_file = Path(file_path)
            config_dict = self.to_dict()

            with open(config_file, "w") as f:
                if config_file.suffix.lower() in [".yaml", ".yml"]:
                    yaml.dump(config_dict, f, default_flow_style=False, indent=2)
                elif config_file.suffix.lower() == ".json":
                    json.dump(config_dict, f, indent=2)
                else:
                    raise ValueError(f"Unsupported file format: {config_file.suffix}")

            logger.info("Configuration saved to file", path=file_path)

        except Exception as e:
            logger.error("Failed to save configuration", path=file_path, error=str(e))
            raise
