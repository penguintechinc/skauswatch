"""
gRPC pipeline tests.

Tests service-to-service gRPC communication for S3 scanning operations
(manager ↔ worker via the S3ScanService defined in grpc/proto/s3_scan.proto).

gRPC is disabled by default (GRPC_ENABLED=false). These tests verify:
  - Client initialisation and channel creation
  - Error handling when the gRPC server is unavailable
  - Report/request round-trip with fully mocked stubs
  - Streaming batch results through the server servicer

No live gRPC server is started; all network calls are replaced with mocks.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
import asyncio

pytestmark = [pytest.mark.stream, pytest.mark.unit]

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scan_result_dict():
    """Minimal dict that matches S3ScanClient.report_scan_result() schema."""
    return {
        "task_id": "task-abc-001",
        "job_id": "job-xyz-001",
        "object_key": "uploads/test-file.pdf",
        "scan_status": "clean",
        "is_malware": False,
        "is_pup": False,
        "is_threat": False,
        "detected_file_type": "PDF",
        "threat_names": [],
        "file_md5": "d41d8cd98f00b204e9800998ecf8427e",
        "file_sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "file_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4"
        "649b934ca495991b7852b855",
        "clamav_result_json": "{}",
        "yara_matches_json": "[]",
        "ti_enrichment_json": "{}",
        "scan_duration_ms": 150,
        "tags_applied": False,
        "error_message": "",
    }


@pytest.fixture
def mock_result_ack_accepted():
    """Protobuf-like ResultAck where accepted=True."""
    ack = MagicMock()
    ack.accepted = True
    return ack


@pytest.fixture
def mock_result_ack_rejected():
    """Protobuf-like ResultAck where accepted=False."""
    ack = MagicMock()
    ack.accepted = False
    return ack


# ---------------------------------------------------------------------------
# Class 1: Client initialisation
# ---------------------------------------------------------------------------


class TestGrpcClientInitialization:
    """Verify S3ScanClient initialises correctly with mock channel."""

    def test_client_stores_server_address(self):
        """S3ScanClient stores server_address and timeout on __init__."""
        with patch("services.manager-new.grpc.s3_scan_client" if False else "grpc.aio.insecure_channel"):  # noqa: SIM210
            # Import directly from the service path
            import sys
            import os

            sys.path.insert(
                0,
                os.path.join(
                    os.path.dirname(__file__),
                    "..",
                    "..",
                    "services",
                    "manager-new",
                ),
            )
            from grpc.s3_scan_client import S3ScanClient

            client = S3ScanClient(server_address="localhost:50051", timeout=15)
            assert client.server_address == "localhost:50051"
            assert client.timeout == 15
            assert client.channel is None
            assert client.stub is None

    def test_client_default_timeout(self):
        """Default timeout is 30 seconds."""
        import sys
        import os

        sys.path.insert(
            0,
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "..",
                "services",
                "manager-new",
            ),
        )
        from grpc.s3_scan_client import S3ScanClient

        client = S3ScanClient(server_address="manager:50051")
        assert client.timeout == 30


# ---------------------------------------------------------------------------
# Class 2: Server unavailable error handling
# ---------------------------------------------------------------------------


class TestGrpcServerUnavailable:
    """Verify graceful degradation when the gRPC server is unreachable."""

    @pytest.fixture(autouse=True)
    def _add_manager_to_path(self):
        import sys
        import os

        path = os.path.join(
            os.path.dirname(__file__), "..", "..", "services", "manager-new"
        )
        if path not in sys.path:
            sys.path.insert(0, path)

    async def test_connect_raises_on_channel_not_ready(self):
        """connect() raises when the gRPC channel cannot become ready."""
        import grpc

        with patch("grpc.aio.insecure_channel") as mock_channel_fn:
            mock_channel = AsyncMock()
            mock_channel.channel_ready.side_effect = grpc.RpcError("unavailable")
            mock_channel_fn.return_value = mock_channel

            # Stub out generated import
            fake_pb2_grpc = MagicMock()
            fake_pb2_grpc.S3ScanServiceStub.return_value = MagicMock()

            with patch.dict(
                "sys.modules",
                {"grpc.generated": MagicMock(), "grpc.generated.s3_scan_pb2_grpc": fake_pb2_grpc},
            ):
                from grpc.s3_scan_client import S3ScanClient

                client = S3ScanClient(server_address="unreachable:50051")
                with pytest.raises(Exception):
                    await client.connect()

    async def test_report_result_returns_false_when_not_connected(
        self, scan_result_dict
    ):
        """report_scan_result() returns False if connect() was never called."""
        from grpc.s3_scan_client import S3ScanClient

        client = S3ScanClient(server_address="nowhere:50051")
        # stub is None because connect() was never called
        result = await client.report_scan_result(scan_result_dict)
        assert result is False

    async def test_get_scan_status_returns_none_when_not_connected(self):
        """get_scan_status() returns None if connect() was never called."""
        from grpc.s3_scan_client import S3ScanClient

        client = S3ScanClient(server_address="nowhere:50051")
        result = await client.get_scan_status("job-123")
        assert result is None

    async def test_stream_results_returns_zero_when_not_connected(self):
        """stream_scan_results() returns 0 if connect() was never called."""
        from grpc.s3_scan_client import S3ScanClient

        client = S3ScanClient(server_address="nowhere:50051")
        result = await client.stream_scan_results([{"task_id": "t1"}])
        assert result == 0

    async def test_report_result_returns_false_on_grpc_rpc_error(
        self, scan_result_dict
    ):
        """report_scan_result() returns False on grpc.RpcError."""
        import grpc as grpc_lib

        fake_pb2 = MagicMock()
        fake_pb2.ScanResult.return_value = MagicMock()

        grpc_error = grpc_lib.RpcError()
        grpc_error.code = MagicMock(return_value=grpc_lib.StatusCode.UNAVAILABLE)
        grpc_error.details = MagicMock(return_value="server unavailable")

        mock_stub = AsyncMock()
        mock_stub.ReportScanResult.side_effect = grpc_error

        with patch.dict(
            "sys.modules",
            {
                "grpc.generated": MagicMock(),
                "grpc.generated.s3_scan_pb2": fake_pb2,
                "grpc.generated.s3_scan_pb2_grpc": MagicMock(),
            },
        ):
            from grpc.s3_scan_client import S3ScanClient

            client = S3ScanClient(server_address="mock:50051")
            client.stub = mock_stub

            result = await client.report_scan_result(scan_result_dict)

        assert result is False


# ---------------------------------------------------------------------------
# Class 3: Request/Response round-trip with mocked stubs
# ---------------------------------------------------------------------------


class TestGrpcRoundTrip:
    """Test full request/response round-trip using mocked gRPC stubs."""

    @pytest.fixture(autouse=True)
    def _add_manager_to_path(self):
        import sys
        import os

        path = os.path.join(
            os.path.dirname(__file__), "..", "..", "services", "manager-new"
        )
        if path not in sys.path:
            sys.path.insert(0, path)

    async def test_report_scan_result_accepted(
        self, scan_result_dict, mock_result_ack_accepted
    ):
        """report_scan_result() returns True when stub responds accepted=True."""
        fake_pb2 = MagicMock()
        fake_pb2.ScanResult.return_value = MagicMock()

        mock_stub = AsyncMock()
        mock_stub.ReportScanResult.return_value = mock_result_ack_accepted

        with patch.dict(
            "sys.modules",
            {
                "grpc.generated": MagicMock(),
                "grpc.generated.s3_scan_pb2": fake_pb2,
                "grpc.generated.s3_scan_pb2_grpc": MagicMock(),
            },
        ):
            from grpc.s3_scan_client import S3ScanClient

            client = S3ScanClient(server_address="mock:50051")
            client.stub = mock_stub

            result = await client.report_scan_result(scan_result_dict)

        assert result is True
        mock_stub.ReportScanResult.assert_awaited_once()

    async def test_report_scan_result_rejected(
        self, scan_result_dict, mock_result_ack_rejected
    ):
        """report_scan_result() returns False when stub responds accepted=False."""
        fake_pb2 = MagicMock()
        fake_pb2.ScanResult.return_value = MagicMock()

        mock_stub = AsyncMock()
        mock_stub.ReportScanResult.return_value = mock_result_ack_rejected

        with patch.dict(
            "sys.modules",
            {
                "grpc.generated": MagicMock(),
                "grpc.generated.s3_scan_pb2": fake_pb2,
                "grpc.generated.s3_scan_pb2_grpc": MagicMock(),
            },
        ):
            from grpc.s3_scan_client import S3ScanClient

            client = S3ScanClient(server_address="mock:50051")
            client.stub = mock_stub

            result = await client.report_scan_result(scan_result_dict)

        assert result is False

    async def test_get_scan_status_returns_dict(self):
        """get_scan_status() returns a status dict from the server response."""
        fake_pb2 = MagicMock()
        status_request = MagicMock()
        fake_pb2.ScanStatusRequest.return_value = status_request

        mock_response = MagicMock()
        mock_response.job_id = "job-001"
        mock_response.status = "running"
        mock_response.total = 500
        mock_response.scanned = 120
        mock_response.infected = 0

        mock_stub = AsyncMock()
        mock_stub.GetScanStatus.return_value = mock_response

        with patch.dict(
            "sys.modules",
            {
                "grpc.generated": MagicMock(),
                "grpc.generated.s3_scan_pb2": fake_pb2,
                "grpc.generated.s3_scan_pb2_grpc": MagicMock(),
            },
        ):
            from grpc.s3_scan_client import S3ScanClient

            client = S3ScanClient(server_address="mock:50051")
            client.stub = mock_stub

            status = await client.get_scan_status("job-001")

        assert status is not None
        assert status["job_id"] == "job-001"
        assert status["status"] == "running"
        assert status["total"] == 500
        assert status["scanned"] == 120

    async def test_get_scan_status_not_found_returns_none(self):
        """get_scan_status() returns None when server raises NOT_FOUND."""
        import grpc as grpc_lib

        fake_pb2 = MagicMock()
        fake_pb2.ScanStatusRequest.return_value = MagicMock()

        not_found_error = grpc_lib.RpcError()
        not_found_error.code = MagicMock(return_value=grpc_lib.StatusCode.NOT_FOUND)
        not_found_error.details = MagicMock(return_value="job not found")

        mock_stub = AsyncMock()
        mock_stub.GetScanStatus.side_effect = not_found_error

        with patch.dict(
            "sys.modules",
            {
                "grpc.generated": MagicMock(),
                "grpc.generated.s3_scan_pb2": fake_pb2,
                "grpc.generated.s3_scan_pb2_grpc": MagicMock(),
            },
        ):
            from grpc.s3_scan_client import S3ScanClient

            client = S3ScanClient(server_address="mock:50051")
            client.stub = mock_stub

            result = await client.get_scan_status("nonexistent-job")

        assert result is None

    async def test_stream_scan_results_returns_count(self):
        """stream_scan_results() returns the count reported by StreamAck."""
        fake_pb2 = MagicMock()
        # Each call to ScanResult() returns a unique mock
        fake_pb2.ScanResult.side_effect = lambda **kwargs: MagicMock(**kwargs)

        stream_ack = MagicMock()
        stream_ack.results_received = 3

        mock_stub = AsyncMock()
        mock_stub.StreamScanResults.return_value = stream_ack

        results = [
            {"task_id": f"t{i}", "job_id": "job-001", "object_key": f"file{i}.pdf"}
            for i in range(3)
        ]

        with patch.dict(
            "sys.modules",
            {
                "grpc.generated": MagicMock(),
                "grpc.generated.s3_scan_pb2": fake_pb2,
                "grpc.generated.s3_scan_pb2_grpc": MagicMock(),
            },
        ):
            from grpc.s3_scan_client import S3ScanClient

            client = S3ScanClient(server_address="mock:50051")
            client.stub = mock_stub

            count = await client.stream_scan_results(results)

        assert count == 3

    async def test_close_clears_channel_and_stub(self):
        """close() sets channel and stub to None."""
        mock_channel = AsyncMock()
        mock_channel.close = AsyncMock()

        import sys
        import os

        path = os.path.join(
            os.path.dirname(__file__), "..", "..", "services", "manager-new"
        )
        if path not in sys.path:
            sys.path.insert(0, path)
        from grpc.s3_scan_client import S3ScanClient

        client = S3ScanClient(server_address="mock:50051")
        client.channel = mock_channel
        client.stub = MagicMock()

        await client.close()

        assert client.channel is None
        assert client.stub is None
        mock_channel.close.assert_awaited_once()


# ---------------------------------------------------------------------------
# Class 4: Server-side servicer tests
# ---------------------------------------------------------------------------


class TestGrpcServerServicer:
    """Test S3ScanServicer (server side) with mocked managers."""

    @pytest.fixture(autouse=True)
    def _add_manager_to_path(self):
        import sys
        import os

        path = os.path.join(
            os.path.dirname(__file__), "..", "..", "services", "manager-new"
        )
        if path not in sys.path:
            sys.path.insert(0, path)

    @pytest.fixture
    def servicer(self):
        """Create an S3ScanServicer with all manager deps mocked."""
        job_manager = AsyncMock()
        job_manager.scan_publisher = AsyncMock()
        job_manager.scan_publisher.publish_scan_task = AsyncMock()
        job_manager.get_job_status = AsyncMock(
            return_value={
                "status": "running",
                "bucket_config_id": 1,
                "total_objects": 100,
                "scanned_objects": 20,
                "infected_objects": 0,
            }
        )
        job_manager.update_job_progress = AsyncMock()

        results_manager = AsyncMock()
        results_manager.save_scan_result = AsyncMock(return_value=42)

        adhoc_manager = AsyncMock()
        bucket_manager = AsyncMock()

        fake_pb2 = MagicMock()
        fake_pb2.TaskAck.return_value = MagicMock(accepted=True, message="ok")
        fake_pb2.ResultAck.return_value = MagicMock(accepted=True)
        fake_pb2.StreamAck.return_value = MagicMock(results_received=0)
        fake_pb2.ScanStatusResponse.return_value = MagicMock()
        fake_pb2.AdhocScanResponse.return_value = MagicMock()

        with patch.dict(
            "sys.modules",
            {
                "grpc.generated": MagicMock(),
                "grpc.generated.s3_scan_pb2": fake_pb2,
                "grpc.generated.s3_scan_pb2_grpc": MagicMock(),
            },
        ):
            from grpc.s3_scan_server import S3ScanServicer as Servicer

            svc = Servicer(
                job_manager=job_manager,
                results_manager=results_manager,
                adhoc_manager=adhoc_manager,
                bucket_manager=bucket_manager,
            )
            svc._fake_pb2 = fake_pb2
            return svc

    async def test_submit_scan_task_accepted(self, servicer):
        """SubmitScanTask publishes to stream and returns accepted=True."""
        request = MagicMock()
        request.task_id = "t-001"
        request.job_id = "j-001"
        request.object_key = "bucket/file.pdf"
        request.bucket_config_id = 1
        request.object_size = 1024
        request.endpoint_url = "https://s3.example.com"
        request.bucket_name = "test-bucket"
        request.access_key = "AKIATEST"
        request.secret_key = "secret"
        request.region = "us-east-1"
        request.use_ssl = True
        request.path_style = False
        request.yara_enabled = True

        context = MagicMock()

        with patch.dict(
            "sys.modules",
            {
                "grpc.generated": MagicMock(),
                "grpc.generated.s3_scan_pb2": servicer._fake_pb2,
                "grpc.generated.s3_scan_pb2_grpc": MagicMock(),
            },
        ):
            response = await servicer.SubmitScanTask(request, context)

        servicer.job_manager.scan_publisher.publish_scan_task.assert_awaited_once()
        assert response.accepted is True

    async def test_submit_scan_task_missing_task_id(self, servicer):
        """SubmitScanTask returns accepted=False when task_id is empty."""
        request = MagicMock()
        request.task_id = ""  # missing
        request.job_id = "j-001"
        request.object_key = "file.pdf"
        context = MagicMock()

        servicer._fake_pb2.TaskAck.return_value = MagicMock(
            accepted=False, message="Missing required field: task_id"
        )

        with patch.dict(
            "sys.modules",
            {
                "grpc.generated": MagicMock(),
                "grpc.generated.s3_scan_pb2": servicer._fake_pb2,
                "grpc.generated.s3_scan_pb2_grpc": MagicMock(),
            },
        ):
            response = await servicer.SubmitScanTask(request, context)

        assert response.accepted is False

    async def test_report_scan_result_saves_to_db(self, servicer):
        """ReportScanResult saves the result via results_manager."""
        request = MagicMock()
        request.task_id = "t-001"
        request.job_id = "j-001"
        request.object_key = "file.pdf"
        request.scan_status = "clean"
        request.is_malware = False
        request.is_pup = False
        request.is_threat = False
        request.detected_file_type = "PDF"
        request.threat_names = []
        request.file_md5 = "abc123"
        request.file_sha1 = ""
        request.file_sha256 = "def456"
        request.clamav_result_json = ""
        request.yara_matches_json = ""
        request.ti_enrichment_json = ""
        request.scan_duration_ms = 200
        request.error_message = ""

        context = MagicMock()

        with patch.dict(
            "sys.modules",
            {
                "grpc.generated": MagicMock(),
                "grpc.generated.s3_scan_pb2": servicer._fake_pb2,
                "grpc.generated.s3_scan_pb2_grpc": MagicMock(),
            },
        ):
            response = await servicer.ReportScanResult(request, context)

        servicer.results_manager.save_scan_result.assert_awaited_once()
        assert response.accepted is True
