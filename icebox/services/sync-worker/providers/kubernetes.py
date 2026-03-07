"""Kubernetes Secrets cloud provider."""
from __future__ import annotations

import base64
import logging
from typing import Any

from kubernetes import client, config as k8s_config
from kubernetes.client.rest import ApiException

from . import CloudProvider, SyncResult

logger = logging.getLogger(__name__)

ICEBOX_LABEL_KEY = "icebox-managed"
ICEBOX_LABEL_VALUE = "true"


class KubernetesProvider(CloudProvider):
    """Sync secrets between IceBox and Kubernetes Secrets."""

    def __init__(
        self,
        credentials: dict[str, Any],
        config: dict[str, Any],
    ) -> None:
        super().__init__(credentials, config)
        self._namespace: str = credentials.get("namespace", "default")
        self._prefix: str = config.get("secret_prefix", "icebox-")

        # Load kubeconfig: in-cluster (pod) or explicit kubeconfig path
        kubeconfig_path = credentials.get("kubeconfig_path")
        in_cluster = credentials.get("in_cluster", False)

        if in_cluster:
            k8s_config.load_incluster_config()
        elif kubeconfig_path:
            k8s_config.load_kube_config(config_file=kubeconfig_path)
        else:
            # Try in-cluster first, fall back to default kubeconfig
            try:
                k8s_config.load_incluster_config()
            except k8s_config.ConfigException:
                k8s_config.load_kube_config()

        # Optional: override API server URL and bearer token
        api_url = credentials.get("api_server_url")
        bearer_token = credentials.get("bearer_token")
        if api_url or bearer_token:
            cfg = client.Configuration.get_default_copy()
            if api_url:
                cfg.host = api_url
            if bearer_token:
                cfg.api_key = {"authorization": f"Bearer {bearer_token}"}
                cfg.api_key_prefix = {"authorization": ""}
            client.Configuration.set_default(cfg)

        self._core_v1 = client.CoreV1Api()

    def _secret_name(self, name: str) -> str:
        """K8s secret names: lowercase alphanumeric and dashes only."""
        safe = (
            name.lower()
            .replace("/", "-")
            .replace("_", "-")
            .replace(".", "-")
        )
        return f"{self._prefix}{safe}"

    async def push_secret(
        self,
        name: str,
        value: str,
        secret_id: str,
        tags: dict[str, str] | None = None,
    ) -> SyncResult:
        """Create or update a Kubernetes Secret."""
        k8s_name = self._secret_name(name)
        encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")

        labels: dict[str, str] = {
            ICEBOX_LABEL_KEY: ICEBOX_LABEL_VALUE,
            "icebox-secret-id": secret_id[:63],  # K8s label value max 63 chars
        }
        if tags:
            for k, v in tags.items():
                labels[k[:63]] = v[:63]

        body = client.V1Secret(
            api_version="v1",
            kind="Secret",
            metadata=client.V1ObjectMeta(
                name=k8s_name,
                namespace=self._namespace,
                labels=labels,
            ),
            type="Opaque",
            data={"value": encoded},
        )

        # Try to update existing, create if missing
        try:
            self._core_v1.patch_namespaced_secret(
                name=k8s_name,
                namespace=self._namespace,
                body=body,
            )
            logger.info(
                "kubernetes: updated secret %s/%s (icebox_id=%s)",
                self._namespace,
                k8s_name,
                secret_id,
            )
            return SyncResult(
                secret_id=secret_id,
                external_ref=k8s_name,
                success=True,
                action="updated",
            )
        except ApiException as exc:
            if exc.status == 404:
                # Secret doesn't exist — create it
                try:
                    self._core_v1.create_namespaced_secret(
                        namespace=self._namespace,
                        body=body,
                    )
                    logger.info(
                        "kubernetes: created secret %s/%s (icebox_id=%s)",
                        self._namespace,
                        k8s_name,
                        secret_id,
                    )
                    return SyncResult(
                        secret_id=secret_id,
                        external_ref=k8s_name,
                        success=True,
                        action="created",
                    )
                except ApiException as create_exc:
                    msg = str(create_exc)
                    logger.error(
                        "kubernetes: create failed for %s/%s: %s",
                        self._namespace,
                        k8s_name,
                        msg,
                    )
                    return SyncResult(
                        secret_id=secret_id,
                        external_ref=k8s_name,
                        success=False,
                        error=msg,
                    )
            msg = str(exc)
            logger.error(
                "kubernetes: push failed for %s/%s: %s",
                self._namespace,
                k8s_name,
                msg,
            )
            return SyncResult(
                secret_id=secret_id,
                external_ref=k8s_name,
                success=False,
                error=msg,
            )

    async def pull_secret(self, external_ref: str) -> str | None:
        """Fetch a secret value from Kubernetes."""
        try:
            secret = self._core_v1.read_namespaced_secret(
                name=external_ref,
                namespace=self._namespace,
            )
            encoded: str | None = (secret.data or {}).get("value")
            if encoded is None:
                return None
            return base64.b64decode(encoded).decode("utf-8")
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise

    async def delete_secret(self, external_ref: str) -> bool:
        """Delete a Kubernetes Secret."""
        try:
            self._core_v1.delete_namespaced_secret(
                name=external_ref,
                namespace=self._namespace,
            )
            logger.info(
                "kubernetes: deleted secret %s/%s",
                self._namespace,
                external_ref,
            )
            return True
        except ApiException as exc:
            if exc.status == 404:
                return False
            raise

    async def list_secrets(self) -> list[str]:
        """List all IceBox-managed secret names in this namespace."""
        label_selector = f"{ICEBOX_LABEL_KEY}={ICEBOX_LABEL_VALUE}"
        secrets = self._core_v1.list_namespaced_secret(
            namespace=self._namespace,
            label_selector=label_selector,
        )
        return [s.metadata.name for s in secrets.items]

    async def close(self) -> None:
        """Kubernetes client has no persistent connection to close."""
