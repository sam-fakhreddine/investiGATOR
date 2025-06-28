"""
Web interface tests for VPC Flow Log Investigator.
"""

import json
from unittest.mock import Mock, patch

import pytest
from fastapi.testclient import TestClient

from vpc_flow_investigator.web import WebApplicationFactory


@pytest.fixture
def client():
    """Create test client for FastAPI app."""
    app = WebApplicationFactory.create_app()
    return TestClient(app)


@pytest.fixture
def mock_instance_info():
    """Mock instance information."""
    return {
        "private_ips": ["10.0.1.100"],
        "primary_ip": "10.0.1.100",
        "vpc_cidr_prefix": "10.0.",
        "vpc_id": "vpc-12345",
        "region": "us-east-1",
    }


@pytest.fixture
def sample_logs():
    """Sample log data for testing."""
    return [
        {
            "srcaddr": "10.0.1.100",
            "dstaddr": "203.0.113.12",
            "srcport": "443",
            "dstport": "49152",
            "protocol": "6",
            "action": "ACCEPT",
            "start": "1418530010",
        },
        {
            "srcaddr": "203.0.113.12",
            "dstaddr": "10.0.1.100",
            "srcport": "49152",
            "dstport": "22",
            "protocol": "6",
            "action": "ACCEPT",
            "start": "1418530015",
        },
    ]


class TestWebEndpoints:
    """Test web interface endpoints."""

    def test_home_page(self, client):
        """Test home page loads successfully."""
        with patch(
            "vpc_flow_investigator.web.AWSProfileService.get_profiles"
        ) as mock_profiles:
            mock_profiles.return_value = ["default", "test"]
            response = client.get("/")
            assert response.status_code == 200
            assert "text/html" in response.headers["content-type"]

    def test_api_test_endpoint(self, client):
        """Test API test endpoint."""
        response = client.get("/api/test")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["message"] == "API is working"

    def test_get_profiles_endpoint(self, client):
        """Test get profiles endpoint."""
        with patch(
            "vpc_flow_investigator.web.AWSProfileService.get_profiles"
        ) as mock_profiles:
            mock_profiles.return_value = ["default", "production"]
            response = client.get("/api/profiles")
            assert response.status_code == 200
            data = response.json()
            assert "profiles" in data
            assert data["profiles"] == ["default", "production"]

    def test_query_result_endpoint_not_found(self, client):
        """Test query result endpoint with non-existent query ID."""
        with patch("vpc_flow_investigator.web.get_query_result") as mock_get_result:
            mock_get_result.return_value = None
            response = client.get("/api/query/nonexistent")
            assert response.status_code == 404

    def test_query_result_endpoint_found(self, client):
        """Test query result endpoint with existing query ID."""
        mock_result = {"status": "success", "data": []}
        with patch("vpc_flow_investigator.web.get_query_result") as mock_get_result:
            mock_get_result.return_value = mock_result
            response = client.get("/api/query/test-query-id")
            assert response.status_code == 200
            assert response.json() == mock_result


class TestAnalysisEndpoint:
    """Test analysis endpoint functionality."""

    @patch("vpc_flow_investigator.web.FileCleanupService.cleanup_file")
    @patch("vpc_flow_investigator.web.filter_logs")
    @patch("vpc_flow_investigator.web.read_log_file")
    @patch("vpc_flow_investigator.web.download_vpc_flow_logs")
    @patch("vpc_flow_investigator.web.find_vpc_flow_log_group")
    @patch("vpc_flow_investigator.web.get_instance_info")
    def test_analyze_logs_success(
        self,
        mock_get_instance,
        mock_find_log_group,
        mock_download_logs,
        mock_read_logs,
        mock_filter_logs,
        mock_cleanup,
        client,
        mock_instance_info,
        sample_logs,
    ):
        """Test successful log analysis."""
        # Setup mocks
        mock_get_instance.return_value = mock_instance_info
        mock_find_log_group.return_value = "test-log-group"
        mock_download_logs.return_value = "/tmp/test.log"
        mock_read_logs.return_value = iter(sample_logs)
        mock_filter_logs.return_value = iter(sample_logs)

        response = client.post(
            "/api/analyze",
            data={
                "profile": "default",
                "instance_id": "i-1234567890abcdef0",
                "region": "us-east-1",
                "start_time": "1418530000",
                "end_time": "1418530100",
                "analysis": "traffic-summary",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "total_logs" in data
        assert "analyses" in data
        assert data["total_logs"] == 2

    def test_analyze_logs_invalid_instance(self, client):
        """Test analysis with invalid instance ID."""
        with patch("vpc_flow_investigator.web.get_instance_info") as mock_get_instance:
            mock_get_instance.return_value = None

            response = client.post(
                "/api/analyze",
                data={
                    "profile": "default",
                    "instance_id": "invalid-instance",
                    "analysis": "all",
                },
            )

            assert response.status_code == 400

    def test_analyze_logs_missing_log_group(self, client, mock_instance_info):
        """Test analysis when log group cannot be found."""
        with patch("vpc_flow_investigator.web.get_instance_info") as mock_get_instance:
            with patch(
                "vpc_flow_investigator.web.find_vpc_flow_log_group"
            ) as mock_find_log_group:
                mock_get_instance.return_value = mock_instance_info
                mock_find_log_group.return_value = None

                response = client.post(
                    "/api/analyze",
                    data={
                        "profile": "default",
                        "instance_id": "i-1234567890abcdef0",
                        "analysis": "all",
                    },
                )

                assert response.status_code == 400


class TestCIDRScanEndpoint:
    """Test CIDR scanning endpoint."""

    def test_scan_cidrs_success(self, client, sample_logs):
        """Test successful CIDR scanning."""
        with patch(
            "vpc_flow_investigator.aws_utils.download_vpc_flow_logs"
        ) as mock_download:
            with patch("vpc_flow_investigator.parser.read_log_file") as mock_read:
                with patch(
                    "vpc_flow_investigator.cidr_analyzer.CIDRAnalyzer"
                ) as mock_analyzer_class:
                    mock_download.return_value = "/tmp/test.log"
                    mock_read.return_value = iter(sample_logs)
                    mock_analyzer = Mock()
                    mock_analyzer_class.return_value = mock_analyzer

                    response = client.post(
                        "/api/scan-cidrs",
                        data={
                            "profile": "default",
                            "log_group": "test-log-group",
                            "region": "us-east-1",
                            "start_time": "24h",
                            "end_time": "now",
                        },
                    )

                    assert response.status_code == 200
                    data = response.json()
                    assert data["status"] == "success"

    def test_scan_cidrs_with_invalid_json_file(self, client):
        """Test CIDR scanning with invalid JSON file."""
        from io import BytesIO

        invalid_json = BytesIO(b"invalid json content")

        response = client.post(
            "/api/scan-cidrs",
            data={
                "profile": "default",
                "log_group": "test-log-group",
            },
            files={"cidr_file": ("test.json", invalid_json, "application/json")},
        )

        assert response.status_code == 400
        data = response.json()
        assert data["status"] == "error"
        assert "Invalid JSON file" in data["message"]

    def test_scan_cidrs_download_failure(self, client):
        """Test CIDR scanning when log download fails."""
        with patch(
            "vpc_flow_investigator.aws_utils.download_vpc_flow_logs"
        ) as mock_download:
            mock_download.return_value = None

            response = client.post(
                "/api/scan-cidrs",
                data={
                    "profile": "default",
                    "log_group": "test-log-group",
                },
            )

            assert response.status_code == 500
            data = response.json()
            assert data["status"] == "error"


class TestAnalyzers:
    """Test individual analyzer classes."""

    def test_traffic_summary_analyzer(self, sample_logs):
        """Test traffic summary analyzer."""
        from vpc_flow_investigator.web import TrafficSummaryAnalyzer

        result = TrafficSummaryAnalyzer.analyze(sample_logs)
        assert isinstance(result, list)
        assert len(result) > 0
        assert all(
            "protocol" in item and "action" in item and "count" in item for item in result
        )

    def test_ssh_inbound_analyzer(self, sample_logs):
        """Test SSH inbound analyzer."""
        from vpc_flow_investigator.web import SSHInboundAnalyzer

        config = {
            "instance_ips": ["10.0.1.100"],
            "vpc_cidr_prefix": "10.0.",
        }

        with patch("vpc_flow_investigator.whois_utils.get_whois_info") as mock_whois:
            with patch(
                "vpc_flow_investigator.whois_utils.is_external_ip"
            ) as mock_is_external:
                mock_whois.return_value = {"org": "Test Organization"}
                mock_is_external.return_value = True
                result = SSHInboundAnalyzer.analyze(sample_logs, config)
                assert isinstance(result, list)

    def test_external_inbound_analyzer(self, sample_logs):
        """Test external inbound analyzer."""
        from vpc_flow_investigator.web import ExternalInboundAnalyzer

        config = {
            "instance_ips": ["10.0.1.100"],
            "vpc_cidr_prefix": "10.0.",
        }

        with patch("vpc_flow_investigator.whois_utils.get_whois_info") as mock_whois:
            mock_whois.return_value = {"org": "External Organization"}
            result = ExternalInboundAnalyzer.analyze(sample_logs, config)
            assert isinstance(result, list)

    def test_analysis_result_processor_empty_logs(self):
        """Test analysis result processor with empty logs."""
        from vpc_flow_investigator.web import AnalysisResultProcessor

        config = {"analysis": "all"}
        result = AnalysisResultProcessor.process_logs([], config)
        assert result["total_logs"] == 0
        assert result["analyses"] == {}

    def test_port_specific_analyzer_no_port(self, sample_logs):
        """Test port specific analyzer with no port specified."""
        from vpc_flow_investigator.web import PortSpecificAnalyzer

        config = {"port": None}
        result = PortSpecificAnalyzer.analyze(sample_logs, config)
        assert result == []


class TestServices:
    """Test service classes."""

    def test_aws_profile_service(self):
        """Test AWS profile service."""
        from vpc_flow_investigator.web import AWSProfileService

        with patch("boto3.Session") as mock_session:
            mock_session_instance = Mock()
            mock_session_instance.available_profiles = ["default", "test"]
            mock_session.return_value = mock_session_instance

            profiles = AWSProfileService.get_profiles()
            assert profiles == ["default", "test"]

    def test_aws_profile_service_fallback(self):
        """Test AWS profile service fallback to default."""
        from vpc_flow_investigator.web import AWSProfileService

        with patch("boto3.Session", side_effect=Exception("AWS error")):
            profiles = AWSProfileService.get_profiles()
            assert profiles == ["default"]

    def test_file_cleanup_service(self):
        """Test file cleanup service."""
        from vpc_flow_investigator.web import FileCleanupService

        with patch("os.path.exists") as mock_exists:
            with patch("os.remove") as mock_remove:
                mock_exists.return_value = True

                FileCleanupService.cleanup_file("/tmp/test.log")
                mock_remove.assert_called_once_with("/tmp/test.log")

    def test_file_cleanup_service_nonexistent(self):
        """Test file cleanup service with non-existent file."""
        from vpc_flow_investigator.web import FileCleanupService

        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = False

            # Should not raise exception
            FileCleanupService.cleanup_file("/tmp/nonexistent.log")

    def test_file_cleanup_service_exception(self):
        """Test file cleanup service handles exceptions."""
        from vpc_flow_investigator.web import FileCleanupService

        with patch("os.path.exists") as mock_exists:
            with patch("os.remove") as mock_remove:
                mock_exists.return_value = True
                mock_remove.side_effect = Exception("Permission denied")

                # Should not raise exception
                FileCleanupService.cleanup_file("/tmp/test.log")

    def test_file_cleanup_service_none_path(self):
        """Test file cleanup service with None path."""
        from vpc_flow_investigator.web import FileCleanupService

        # Should not raise exception
        FileCleanupService.cleanup_file(None)

    def test_run_server(self):
        """Test run_server function."""
        from vpc_flow_investigator.web import run_server

        with patch("vpc_flow_investigator.web.uvicorn.run") as mock_run:
            with patch("builtins.print") as mock_print:
                run_server()
                mock_print.assert_any_call(
                    "Starting VPC Flow Log Investigator Web Interface..."
                )
                mock_print.assert_any_call("Open your browser to: http://localhost:8000")
                mock_run.assert_called_once()

    def test_configuration_builder(self):
        """Test configuration builder."""
        from vpc_flow_investigator.web import AnalysisRequest, ConfigurationBuilder

        request = AnalysisRequest(
            profile="test",
            instance_id="i-1234567890abcdef0",
            region="us-east-1",
            start_time="1418530000",
            end_time="1418530100",
            analysis="all",
            port=22,
        )

        config = ConfigurationBuilder.build_config(request)
        assert config["instance_id"] == "i-1234567890abcdef0"
        assert config["profile"] == "test"
        assert config["region"] == "us-east-1"
        assert config["analysis"] == "all"
        assert config["port"] == 22
        assert config["start_time"] == 1418530000
        assert config["end_time"] == 1418530100

    def test_configuration_builder_time_parsing(self):
        """Test configuration builder time parsing edge cases."""
        from vpc_flow_investigator.web import AnalysisRequest, ConfigurationBuilder

        # Test with "now" end time
        request = AnalysisRequest(
            profile="test",
            instance_id="i-1234567890abcdef0",
            region="us-east-1",
            start_time="24h",
            end_time="now",
            analysis="all",
            port=None,
        )

        with patch("time.time", return_value=1418530100):
            config = ConfigurationBuilder.build_config(request)
            assert config["end_time"] == 1418530100

        # Test with relative time parsing fallback
        request2 = AnalysisRequest(
            profile="test",
            instance_id="i-1234567890abcdef0",
            region="us-east-1",
            start_time="invalid_time",
            end_time="invalid_time",
            analysis="all",
            port=None,
        )

        with patch("vpc_flow_investigator.web.parse_time_input") as mock_parse:
            mock_parse.return_value = 1418530000
            config = ConfigurationBuilder.build_config(request2)
            assert config["start_time"] == 1418530000
            assert config["end_time"] == 1418530000


if __name__ == "__main__":
    pytest.main([__file__])
