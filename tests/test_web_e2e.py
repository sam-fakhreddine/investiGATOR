"""
End-to-end tests for the web interface.
"""

import asyncio
import json
import time
from unittest.mock import Mock, patch

import pytest
from fastapi.testclient import TestClient

from vpc_flow_investigator.web import WebApplicationFactory


@pytest.fixture
def client():
    """Create test client for FastAPI app."""
    app = WebApplicationFactory.create_app()
    return TestClient(app)


class TestWebE2E:
    """End-to-end web interface tests."""

    def test_complete_analysis_workflow(self, client):
        """Test complete analysis workflow from web interface."""
        # Mock all external dependencies
        mock_instance_info = {
            "private_ips": ["10.0.1.100"],
            "primary_ip": "10.0.1.100",
            "vpc_cidr_prefix": "10.0.",
            "vpc_id": "vpc-12345",
            "region": "us-east-1",
        }

        sample_logs = [
            {
                "srcaddr": "203.0.113.12",
                "dstaddr": "10.0.1.100",
                "srcport": "49152",
                "dstport": "22",
                "protocol": "6",
                "action": "ACCEPT",
                "start": "1418530010",
            },
            {
                "srcaddr": "10.0.1.100",
                "dstaddr": "8.8.8.8",
                "srcport": "49153",
                "dstport": "53",
                "protocol": "17",
                "action": "ACCEPT",
                "start": "1418530015",
            },
        ]

        with patch("vpc_flow_investigator.web.get_instance_info") as mock_get_instance:
            with patch(
                "vpc_flow_investigator.web.find_vpc_flow_log_group"
            ) as mock_find_log_group:
                with patch(
                    "vpc_flow_investigator.web.download_vpc_flow_logs"
                ) as mock_download:
                    with patch("vpc_flow_investigator.web.read_log_file") as mock_read:
                        with patch(
                            "vpc_flow_investigator.web.filter_logs"
                        ) as mock_filter:
                            with patch(
                                "vpc_flow_investigator.web.FileCleanupService.cleanup_file"
                            ):
                                # Setup mocks
                                mock_get_instance.return_value = mock_instance_info
                                mock_find_log_group.return_value = "test-log-group"
                                mock_download.return_value = "/tmp/test.log"
                                mock_read.return_value = iter(sample_logs)
                                mock_filter.return_value = iter(sample_logs)

                                # Test the complete workflow
                                response = client.post(
                                    "/api/analyze",
                                    data={
                                        "profile": "default",
                                        "instance_id": "i-1234567890abcdef0",
                                        "region": "us-east-1",
                                        "start_time": "1418530000",
                                        "end_time": "1418530100",
                                        "analysis": "all",
                                    },
                                )

                                assert response.status_code == 200
                                data = response.json()

                                # Verify response structure
                                assert "total_logs" in data
                                assert "analyses" in data
                                assert "query_id" in data
                                assert data["total_logs"] == 2

                                # Verify analyses were performed
                                analyses = data["analyses"]
                                assert "traffic_summary" in analyses
                                assert isinstance(analyses["traffic_summary"], list)

    def test_error_handling_workflow(self, client):
        """Test error handling in the analysis workflow."""
        # Test with invalid instance ID
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

    def test_cidr_scan_workflow(self, client):
        """Test CIDR scanning workflow."""
        sample_logs = [
            {
                "srcaddr": "52.95.110.1",  # AWS IP
                "dstaddr": "10.0.1.100",
                "srcport": "443",
                "dstport": "49152",
                "protocol": "6",
                "action": "ACCEPT",
                "start": "1418530010",
            }
        ]

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

    def test_api_endpoints_health(self, client):
        """Test all API endpoints for basic health."""
        # Test API test endpoint
        response = client.get("/api/test")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

        # Test profiles endpoint
        with patch(
            "vpc_flow_investigator.web.AWSProfileService.get_profiles"
        ) as mock_profiles:
            mock_profiles.return_value = ["default", "test"]
            response = client.get("/api/profiles")
            assert response.status_code == 200
            data = response.json()
            assert "profiles" in data

        # Test query result endpoint (not found)
        response = client.get("/api/query/nonexistent")
        assert response.status_code == 404

    def test_home_page_rendering(self, client):
        """Test home page renders correctly."""
        with patch(
            "vpc_flow_investigator.web.AWSProfileService.get_profiles"
        ) as mock_profiles:
            mock_profiles.return_value = ["default", "production"]
            response = client.get("/")
            assert response.status_code == 200
            assert "text/html" in response.headers["content-type"]

    def test_concurrent_requests(self, client):
        """Test handling of concurrent requests."""
        import concurrent.futures

        def make_request():
            response = client.get("/api/test")
            return response.status_code == 200

        # Test 10 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]
            results = [
                future.result() for future in concurrent.futures.as_completed(futures)
            ]

        assert all(results), "Some concurrent requests failed"

    def test_large_payload_handling(self, client):
        """Test handling of large payloads."""
        # Test with large form data
        large_data = {
            "profile": "default",
            "instance_id": "i-1234567890abcdef0",
            "region": "us-east-1",
            "start_time": "1418530000",
            "end_time": "1418530100",
            "analysis": "all",
            "large_field": "x" * 10000,  # 10KB of data
        }

        with patch("vpc_flow_investigator.web.get_instance_info") as mock_get_instance:
            mock_get_instance.return_value = (
                None  # Will cause 400 error, but should handle large payload
            )

            response = client.post("/api/analyze", data=large_data)
            # Should handle the request (even if it fails due to invalid instance)
            assert response.status_code in [
                400,
                500,
            ]  # Should not be a connection error


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
