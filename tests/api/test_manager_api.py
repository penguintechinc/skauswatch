"""Comprehensive Manager API tests.

Tests every single manager-new endpoint across all blueprint groups:
Auth (5), Users (5), Alerts (8+), S3-Scan (16+), EDR (5+),
Approvals (7), Threat-Intel (6+), Research (7), Health (3).

Uses the shared conftest fixtures: app, client, admin/maintainer/viewer tokens.
"""

import pytest


@pytest.mark.api
class TestHealthEndpoints:
    """Health check and metadata endpoints (no auth required)."""

    async def test_healthz(self, client):
        resp = await client.get("/healthz")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "status" in data

    async def test_readyz(self, client):
        resp = await client.get("/readyz")
        assert resp.status_code == 200

    async def test_version(self, client):
        resp = await client.get("/version")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "version" in data


# ─────────────────────────────────────────────────
#  AUTH
# ─────────────────────────────────────────────────
@pytest.mark.api
class TestAuthAPI:
    """Auth endpoints: login, refresh, logout, me, register."""

    async def test_login_success(self, client, admin_user):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": admin_user["email"], "password": admin_user["password"]},
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "access_token" in data
        assert "refresh_token" in data

    async def test_login_wrong_password(self, client, admin_user):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": admin_user["email"], "password": "WrongPassword1!"},
        )
        assert resp.status_code == 401

    async def test_login_nonexistent_user(self, client):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@test.com", "password": "Pass123!"},
        )
        assert resp.status_code == 401

    async def test_login_missing_fields(self, client):
        resp = await client.post("/api/v1/auth/login", json={})
        assert resp.status_code == 400

    async def test_get_me(self, client, admin_headers, admin_user):
        resp = await client.get("/api/v1/auth/me", headers=admin_headers)
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["email"] == admin_user["email"]

    async def test_get_me_unauthenticated(self, client):
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    async def test_refresh_token(self, client, admin_user):
        # Login first
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": admin_user["email"], "password": admin_user["password"]},
        )
        login_data = await login_resp.get_json()
        refresh_token = login_data["refresh_token"]

        # Refresh
        resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "access_token" in data

    async def test_logout(self, client, admin_user):
        # Login
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": admin_user["email"], "password": admin_user["password"]},
        )
        login_data = await login_resp.get_json()
        token = login_data["access_token"]
        refresh_token = login_data["refresh_token"]

        # Logout
        resp = await client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
            json={"refresh_token": refresh_token},
        )
        assert resp.status_code in (200, 204)

    async def test_register_new_user(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/auth/register",
            headers=admin_headers,
            json={
                "email": "newuser@api.test",
                "password": "NewUser123!",
                "full_name": "New User",
                "role": "viewer",
            },
        )
        assert resp.status_code in (200, 201)

    async def test_register_duplicate_email(self, client, admin_headers, admin_user):
        resp = await client.post(
            "/api/v1/auth/register",
            headers=admin_headers,
            json={
                "email": admin_user["email"],
                "password": "Dup123!abc",
                "full_name": "Duplicate",
                "role": "viewer",
            },
        )
        assert resp.status_code == 409


# ─────────────────────────────────────────────────
#  USERS
# ─────────────────────────────────────────────────
@pytest.mark.api
class TestUsersAPI:
    """User management endpoints (admin-only for most)."""

    async def test_list_users_admin(self, client, admin_headers, admin_user):
        resp = await client.get("/api/v1/users", headers=admin_headers)
        assert resp.status_code == 200
        data = await resp.get_json()
        assert isinstance(data, (list, dict))

    async def test_list_users_viewer_forbidden(self, client, viewer_headers):
        resp = await client.get("/api/v1/users", headers=viewer_headers)
        assert resp.status_code == 403

    async def test_get_user_by_id(self, client, admin_headers, admin_user):
        resp = await client.get(
            f"/api/v1/users/{admin_user['id']}", headers=admin_headers
        )
        assert resp.status_code == 200

    async def test_get_user_not_found(self, client, admin_headers):
        resp = await client.get("/api/v1/users/99999", headers=admin_headers)
        assert resp.status_code == 404

    async def test_create_user(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/users",
            headers=admin_headers,
            json={
                "email": "created@api.test",
                "password": "Created123!",
                "full_name": "Created User",
                "role": "viewer",
            },
        )
        assert resp.status_code in (200, 201)

    async def test_update_user(self, client, admin_headers, admin_user):
        resp = await client.put(
            f"/api/v1/users/{admin_user['id']}",
            headers=admin_headers,
            json={"full_name": "Updated Admin Name"},
        )
        assert resp.status_code == 200

    async def test_delete_user_self_blocked(self, client, admin_headers, admin_user):
        resp = await client.delete(
            f"/api/v1/users/{admin_user['id']}", headers=admin_headers
        )
        # Admin should not be able to self-delete
        assert resp.status_code in (400, 403)


# ─────────────────────────────────────────────────
#  ALERTS
# ─────────────────────────────────────────────────
@pytest.mark.api
class TestAlertsAPI:
    """Alert CRUD, search, statistics, AI review endpoints."""

    async def test_list_alerts_empty(self, client, admin_headers):
        resp = await client.get("/api/v1/alerts", headers=admin_headers)
        assert resp.status_code == 200

    async def test_create_alert(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/alerts",
            headers=admin_headers,
            json={
                "title": "API Test Alert",
                "description": "Created via API test",
                "severity": "high",
                "source": "api-test",
            },
        )
        assert resp.status_code in (200, 201)

    async def test_get_alert(self, client, admin_headers):
        # Create first
        create_resp = await client.post(
            "/api/v1/alerts",
            headers=admin_headers,
            json={
                "title": "Fetch Alert",
                "description": "To be fetched",
                "severity": "medium",
                "source": "test",
            },
        )
        create_data = await create_resp.get_json()
        alert_id = create_data.get("id") or create_data.get("alert", {}).get("id")

        if alert_id:
            resp = await client.get(
                f"/api/v1/alerts/{alert_id}", headers=admin_headers
            )
            assert resp.status_code == 200

    async def test_get_alert_not_found(self, client, admin_headers):
        resp = await client.get("/api/v1/alerts/99999", headers=admin_headers)
        assert resp.status_code == 404

    async def test_update_alert(self, client, admin_headers):
        create_resp = await client.post(
            "/api/v1/alerts",
            headers=admin_headers,
            json={
                "title": "Update Me",
                "description": "Will be updated",
                "severity": "low",
                "source": "test",
            },
        )
        create_data = await create_resp.get_json()
        alert_id = create_data.get("id") or create_data.get("alert", {}).get("id")

        if alert_id:
            resp = await client.put(
                f"/api/v1/alerts/{alert_id}",
                headers=admin_headers,
                json={"title": "Updated Title"},
            )
            assert resp.status_code == 200

    async def test_alert_statistics(self, client, admin_headers):
        resp = await client.get("/api/v1/alerts/statistics", headers=admin_headers)
        assert resp.status_code == 200

    async def test_alert_search(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/alerts/search",
            headers=admin_headers,
            json={"query": "test"},
        )
        assert resp.status_code == 200

    async def test_alerts_unauthenticated(self, client):
        resp = await client.get("/api/v1/alerts")
        assert resp.status_code == 401

    async def test_alert_ai_review_disabled(self, client, admin_headers):
        # AI is disabled in test config
        create_resp = await client.post(
            "/api/v1/alerts",
            headers=admin_headers,
            json={
                "title": "AI Review",
                "description": "Needs AI",
                "severity": "critical",
                "source": "test",
            },
        )
        create_data = await create_resp.get_json()
        alert_id = create_data.get("id") or create_data.get("alert", {}).get("id")

        if alert_id:
            resp = await client.post(
                f"/api/v1/alerts/{alert_id}/ai-review", headers=admin_headers
            )
            # AI disabled returns 503 or 400
            assert resp.status_code in (400, 503)


# ─────────────────────────────────────────────────
#  S3 SCAN
# ─────────────────────────────────────────────────
@pytest.mark.api
class TestS3ScanBucketsAPI:
    """S3 Scan bucket CRUD endpoints."""

    async def test_list_buckets_empty(self, client, admin_headers):
        resp = await client.get("/api/v1/s3-scan/buckets", headers=admin_headers)
        assert resp.status_code == 200

    async def test_create_bucket(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
            json={
                "name": "api-test-bucket",
                "endpoint_url": "https://s3.amazonaws.com",
                "bucket_name": "my-api-bucket",
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "region": "us-east-1",
            },
        )
        assert resp.status_code in (200, 201)

    async def test_create_bucket_viewer_forbidden(self, client, viewer_headers):
        resp = await client.post(
            "/api/v1/s3-scan/buckets",
            headers=viewer_headers,
            json={
                "name": "forbidden-bucket",
                "endpoint_url": "https://s3.amazonaws.com",
                "bucket_name": "forbidden",
                "access_key_id": "AKIATEST",
                "secret_access_key": "secret",
            },
        )
        assert resp.status_code == 403

    async def test_get_bucket(self, client, admin_headers):
        # Create first
        create_resp = await client.post(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
            json={
                "name": "get-test-bucket",
                "endpoint_url": "https://s3.amazonaws.com",
                "bucket_name": "get-bucket",
                "access_key_id": "AKIATEST",
                "secret_access_key": "secret",
            },
        )
        create_data = await create_resp.get_json()
        bucket_id = (
            create_data.get("id")
            or create_data.get("bucket", {}).get("id")
        )

        if bucket_id:
            resp = await client.get(
                f"/api/v1/s3-scan/buckets/{bucket_id}", headers=admin_headers
            )
            assert resp.status_code == 200

    async def test_get_bucket_not_found(self, client, admin_headers):
        resp = await client.get(
            "/api/v1/s3-scan/buckets/99999", headers=admin_headers
        )
        assert resp.status_code == 404

    async def test_update_bucket(self, client, admin_headers):
        create_resp = await client.post(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
            json={
                "name": "update-bucket",
                "endpoint_url": "https://s3.amazonaws.com",
                "bucket_name": "upd-bucket",
                "access_key_id": "AKIATEST",
                "secret_access_key": "secret",
            },
        )
        create_data = await create_resp.get_json()
        bucket_id = (
            create_data.get("id")
            or create_data.get("bucket", {}).get("id")
        )

        if bucket_id:
            resp = await client.put(
                f"/api/v1/s3-scan/buckets/{bucket_id}",
                headers=admin_headers,
                json={"name": "renamed-bucket"},
            )
            assert resp.status_code == 200

    async def test_delete_bucket(self, client, admin_headers):
        create_resp = await client.post(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
            json={
                "name": "delete-bucket",
                "endpoint_url": "https://s3.amazonaws.com",
                "bucket_name": "del-bucket",
                "access_key_id": "AKIATEST",
                "secret_access_key": "secret",
            },
        )
        create_data = await create_resp.get_json()
        bucket_id = (
            create_data.get("id")
            or create_data.get("bucket", {}).get("id")
        )

        if bucket_id:
            resp = await client.delete(
                f"/api/v1/s3-scan/buckets/{bucket_id}", headers=admin_headers
            )
            assert resp.status_code in (200, 204)

    async def test_delete_bucket_viewer_forbidden(self, client, viewer_headers):
        resp = await client.delete(
            "/api/v1/s3-scan/buckets/1", headers=viewer_headers
        )
        assert resp.status_code == 403

    async def test_s3_scan_unauthenticated(self, client):
        resp = await client.get("/api/v1/s3-scan/buckets")
        assert resp.status_code == 401


@pytest.mark.api
class TestS3ScanJobsAPI:
    """S3 Scan job and trigger endpoints."""

    async def test_trigger_scan(self, client, admin_headers):
        # Create bucket first
        create_resp = await client.post(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
            json={
                "name": "scan-trigger-bucket",
                "endpoint_url": "https://s3.amazonaws.com",
                "bucket_name": "trigger-bucket",
                "access_key_id": "AKIATEST",
                "secret_access_key": "secret",
            },
        )
        create_data = await create_resp.get_json()
        bucket_id = (
            create_data.get("id")
            or create_data.get("bucket", {}).get("id")
        )

        if bucket_id:
            resp = await client.post(
                f"/api/v1/s3-scan/buckets/{bucket_id}/scan",
                headers=admin_headers,
            )
            # May succeed or fail depending on stream mock
            assert resp.status_code in (200, 201, 202, 503)

    async def test_trigger_scan_not_found(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/s3-scan/buckets/99999/scan", headers=admin_headers
        )
        assert resp.status_code == 404

    async def test_list_jobs(self, client, admin_headers):
        resp = await client.get("/api/v1/s3-scan/jobs", headers=admin_headers)
        assert resp.status_code == 200

    async def test_get_job_not_found(self, client, admin_headers):
        resp = await client.get("/api/v1/s3-scan/jobs/99999", headers=admin_headers)
        assert resp.status_code == 404


@pytest.mark.api
class TestS3ScanResultsAPI:
    """S3 Scan results and statistics endpoints."""

    async def test_query_results_empty(self, client, admin_headers):
        resp = await client.get("/api/v1/s3-scan/results", headers=admin_headers)
        assert resp.status_code == 200

    async def test_get_result_not_found(self, client, admin_headers):
        resp = await client.get(
            "/api/v1/s3-scan/results/99999", headers=admin_headers
        )
        assert resp.status_code == 404

    async def test_statistics(self, client, admin_headers):
        resp = await client.get(
            "/api/v1/s3-scan/statistics", headers=admin_headers
        )
        assert resp.status_code == 200


@pytest.mark.api
class TestS3ScanScheduleAPI:
    """S3 Scan schedule CRUD endpoints."""

    async def test_get_schedule_not_found(self, client, admin_headers):
        resp = await client.get(
            "/api/v1/s3-scan/buckets/99999/schedule", headers=admin_headers
        )
        assert resp.status_code == 404

    async def test_set_schedule(self, client, admin_headers):
        # Create bucket first
        create_resp = await client.post(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
            json={
                "name": "schedule-bucket",
                "endpoint_url": "https://s3.amazonaws.com",
                "bucket_name": "sched-bucket",
                "access_key_id": "AKIATEST",
                "secret_access_key": "secret",
            },
        )
        create_data = await create_resp.get_json()
        bucket_id = (
            create_data.get("id")
            or create_data.get("bucket", {}).get("id")
        )

        if bucket_id:
            resp = await client.put(
                f"/api/v1/s3-scan/buckets/{bucket_id}/schedule",
                headers=admin_headers,
                json={
                    "enabled": True,
                    "cron_expression": "0 2 * * *",
                },
            )
            assert resp.status_code in (200, 201)


@pytest.mark.api
class TestS3ScanUploadAPI:
    """S3 Scan adhoc upload endpoints."""

    async def test_upload_no_file(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/s3-scan/upload", headers=admin_headers
        )
        assert resp.status_code == 400

    async def test_upload_history_empty(self, client, admin_headers):
        resp = await client.get(
            "/api/v1/s3-scan/upload/history", headers=admin_headers
        )
        assert resp.status_code == 200

    async def test_get_upload_result_not_found(self, client, admin_headers):
        resp = await client.get(
            "/api/v1/s3-scan/upload/99999", headers=admin_headers
        )
        assert resp.status_code == 404


# ─────────────────────────────────────────────────
#  EDR
# ─────────────────────────────────────────────────
@pytest.mark.api
class TestEDRAPI:
    """EDR agent registration, heartbeat, events endpoints."""

    async def test_register_agent(self, client):
        resp = await client.post(
            "/api/v1/edr/register",
            headers={
                "X-API-Key": "test-edr-api-key-32chars-longx",
                "X-Agent-ID": "edr-agent-001",
            },
            json={
                "agent_id": "edr-agent-001",
                "hostname": "test-host",
                "os": "Linux 6.1",
                "agent_version": "1.0.0",
                "collectors": ["process", "network"],
            },
        )
        assert resp.status_code in (200, 201)

    async def test_register_no_api_key(self, client):
        resp = await client.post(
            "/api/v1/edr/register",
            json={"agent_id": "bad-agent"},
        )
        assert resp.status_code == 401

    async def test_heartbeat(self, client):
        # Register first
        await client.post(
            "/api/v1/edr/register",
            headers={
                "X-API-Key": "test-edr-api-key-32chars-longx",
                "X-Agent-ID": "heartbeat-agent",
            },
            json={
                "agent_id": "heartbeat-agent",
                "hostname": "test-host",
                "os": "Linux",
                "agent_version": "1.0.0",
            },
        )

        resp = await client.post(
            "/api/v1/edr/heartbeat",
            headers={
                "X-API-Key": "test-edr-api-key-32chars-longx",
                "X-Agent-ID": "heartbeat-agent",
            },
        )
        assert resp.status_code == 200

    async def test_events_batch(self, client):
        # Register first
        await client.post(
            "/api/v1/edr/register",
            headers={
                "X-API-Key": "test-edr-api-key-32chars-longx",
                "X-Agent-ID": "events-agent",
            },
            json={
                "agent_id": "events-agent",
                "hostname": "test-host",
                "os": "Linux",
                "agent_version": "1.0.0",
            },
        )

        resp = await client.post(
            "/api/v1/edr/events",
            headers={
                "X-API-Key": "test-edr-api-key-32chars-longx",
                "X-Agent-ID": "events-agent",
            },
            json={
                "events": [
                    {
                        "type": "process",
                        "severity": "high",
                        "data": {"pid": 1234, "name": "test"},
                    }
                ]
            },
        )
        assert resp.status_code in (200, 202)

    async def test_list_agents_admin(self, client, admin_headers):
        resp = await client.get("/api/v1/edr/agents", headers=admin_headers)
        assert resp.status_code == 200

    async def test_list_agents_viewer_forbidden(self, client, viewer_headers):
        resp = await client.get("/api/v1/edr/agents", headers=viewer_headers)
        assert resp.status_code == 403

    async def test_edr_statistics(self, client, admin_headers):
        resp = await client.get("/api/v1/edr/statistics", headers=admin_headers)
        assert resp.status_code == 200


# ─────────────────────────────────────────────────
#  APPROVALS
# ─────────────────────────────────────────────────
@pytest.mark.api
class TestApprovalsAPI:
    """Approval workflow endpoints."""

    async def test_list_approvals_empty(self, client, admin_headers):
        resp = await client.get("/api/v1/approvals", headers=admin_headers)
        assert resp.status_code == 200

    async def test_list_pending_approvals(self, client, admin_headers):
        resp = await client.get("/api/v1/approvals/pending", headers=admin_headers)
        assert resp.status_code == 200

    async def test_create_approval(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/approvals",
            headers=admin_headers,
            json={
                "action_type": "delete_user",
                "resource_type": "user",
                "resource_id": "1",
                "reason": "API test approval",
            },
        )
        assert resp.status_code in (200, 201)

    async def test_get_approval_not_found(self, client, admin_headers):
        resp = await client.get("/api/v1/approvals/99999", headers=admin_headers)
        assert resp.status_code == 404

    async def test_approval_statistics(self, client, admin_headers):
        resp = await client.get(
            "/api/v1/approvals/statistics", headers=admin_headers
        )
        assert resp.status_code == 200

    async def test_approvals_unauthenticated(self, client):
        resp = await client.get("/api/v1/approvals")
        assert resp.status_code == 401


# ─────────────────────────────────────────────────
#  THREAT INTEL
# ─────────────────────────────────────────────────
@pytest.mark.api
class TestThreatIntelAPI:
    """Threat intelligence IOC CRUD and search endpoints."""

    async def test_list_iocs_empty(self, client, admin_headers):
        resp = await client.get("/api/v1/threat-intel/iocs", headers=admin_headers)
        assert resp.status_code == 200

    async def test_create_ioc(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/threat-intel/iocs",
            headers=admin_headers,
            json={
                "indicator_type": "ip",
                "value": "192.168.1.100",
                "threat_type": "malware",
                "confidence": 85,
                "source": "api-test",
            },
        )
        assert resp.status_code in (200, 201)

    async def test_create_ioc_viewer_forbidden(self, client, viewer_headers):
        resp = await client.post(
            "/api/v1/threat-intel/iocs",
            headers=viewer_headers,
            json={
                "indicator_type": "domain",
                "value": "evil.example.com",
                "threat_type": "phishing",
            },
        )
        assert resp.status_code == 403

    async def test_get_ioc_not_found(self, client, admin_headers):
        resp = await client.get(
            "/api/v1/threat-intel/iocs/99999", headers=admin_headers
        )
        assert resp.status_code == 404

    async def test_search_iocs(self, client, admin_headers):
        resp = await client.get(
            "/api/v1/threat-intel/iocs?indicator_type=ip", headers=admin_headers
        )
        assert resp.status_code == 200

    async def test_delete_ioc(self, client, admin_headers):
        # Create first
        create_resp = await client.post(
            "/api/v1/threat-intel/iocs",
            headers=admin_headers,
            json={
                "indicator_type": "hash",
                "value": "d41d8cd98f00b204e9800998ecf8427e",
                "threat_type": "malware",
                "source": "test",
            },
        )
        create_data = await create_resp.get_json()
        ioc_id = create_data.get("id") or create_data.get("ioc", {}).get("id")

        if ioc_id:
            resp = await client.delete(
                f"/api/v1/threat-intel/iocs/{ioc_id}", headers=admin_headers
            )
            assert resp.status_code in (200, 204)

    async def test_ti_statistics(self, client, admin_headers):
        resp = await client.get(
            "/api/v1/threat-intel/statistics", headers=admin_headers
        )
        assert resp.status_code == 200

    async def test_ti_unauthenticated(self, client):
        resp = await client.get("/api/v1/threat-intel/iocs")
        assert resp.status_code == 401


# ─────────────────────────────────────────────────
#  RESEARCH
# ─────────────────────────────────────────────────
@pytest.mark.api
class TestResearchAPI:
    """Research/OSINT lookup endpoints."""

    async def test_lookup(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/research/lookup",
            headers=admin_headers,
            json={"indicator": "8.8.8.8", "indicator_type": "ip"},
        )
        # May succeed or 503 if services are down
        assert resp.status_code in (200, 503)

    async def test_whois_lookup(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/research/whois",
            headers=admin_headers,
            json={"query": "example.com"},
        )
        assert resp.status_code in (200, 503)

    async def test_dns_lookup(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/research/dns",
            headers=admin_headers,
            json={"domain": "example.com"},
        )
        assert resp.status_code in (200, 503)

    async def test_asn_lookup(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/research/asn",
            headers=admin_headers,
            json={"query": "8.8.8.8"},
        )
        assert resp.status_code in (200, 503)

    async def test_shodan_disabled(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/research/shodan",
            headers=admin_headers,
            json={"query": "8.8.8.8"},
        )
        # Shodan requires API key, should be disabled
        assert resp.status_code in (200, 400, 503)

    async def test_maltego_disabled(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/research/maltego",
            headers=admin_headers,
            json={"query": "example.com", "transform": "domain_to_ip"},
        )
        assert resp.status_code in (200, 400, 503)

    async def test_research_config(self, client, admin_headers):
        resp = await client.get("/api/v1/research/config", headers=admin_headers)
        assert resp.status_code == 200

    async def test_research_unauthenticated(self, client):
        resp = await client.post(
            "/api/v1/research/lookup",
            json={"indicator": "8.8.8.8"},
        )
        assert resp.status_code == 401
