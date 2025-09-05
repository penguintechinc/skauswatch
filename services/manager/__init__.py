"""
SkausWatch Manager Service

The central management plane for SkausWatch providing:
- User authentication and authorization with MFA support
- Role-based access control (RBAC)
- Service configuration management
- Certificate lifecycle management
- Audit logging and monitoring
- Administrative dashboard and APIs
"""

__version__ = "0.1.0"
__author__ = "SkausWatch Team"
__email__ = "support@skauswatch.io"

from .main import create_app

__all__ = ["create_app"]