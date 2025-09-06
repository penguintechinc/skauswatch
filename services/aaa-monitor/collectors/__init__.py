"""
SkausWatch AAA Monitor Service - Log Collectors

Completely clientless log collection infrastructure for various sources.
All collectors operate without agents or log forwarding infrastructure.
"""

from .kubernetes_collector import KubernetesCollector
from .lxc_collector import LXCCollector
from .auditd_collector import AuditdCollector
from .syslog_collector import SyslogCollector
from .journald_collector import JournaldCollector
from .file_collector import FileCollector
from .database_collector import DatabaseCollector

__all__ = [
    'KubernetesCollector',
    'LXCCollector', 
    'AuditdCollector',
    'SyslogCollector',
    'JournaldCollector',
    'FileCollector',
    'DatabaseCollector'
]