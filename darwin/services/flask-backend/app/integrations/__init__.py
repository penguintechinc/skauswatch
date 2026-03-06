"""
Integration clients for external platforms (GitHub, GitLab).

This module provides unified access to different code hosting platforms
through consistent client interfaces.
"""

from .github import GitHubClient, GitHubConfig
from .gitlab import GitLabClient, GitLabConfig

__all__ = [
    "GitHubClient",
    "GitHubConfig",
    "GitLabClient",
    "GitLabConfig",
    "get_integration_client",
]


def get_integration_client(platform: str, **kwargs):
    """
    Factory function to get the appropriate integration client.

    Args:
        platform: Platform name ('github' or 'gitlab')
        **kwargs: Platform-specific configuration parameters

    Returns:
        Client instance for the specified platform

    Raises:
        ValueError: If platform is not supported
    """
    if platform == "github":
        return GitHubClient(GitHubConfig(**kwargs))
    elif platform == "gitlab":
        return GitLabClient(GitLabConfig(**kwargs))
    raise ValueError(f"Unknown platform: {platform}")
