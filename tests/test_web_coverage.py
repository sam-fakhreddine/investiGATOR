"""
Additional tests to achieve 100% coverage for web interface.
"""

from unittest.mock import Mock, patch
import pytest
from fastapi.testclient import TestClient
from vpc_flow_investigator.web import WebApplicationFactory


@pytest.fixture
def client():
    """Create test client for FastAPI app."""
    app = WebApplicationFactory.create_app()
    return TestClient(app)


class TestMissingCoverage:
    """Tests to cover remaining uncovered lines."""

    def test_scan_cidrs_with_valid_json_file(self, client):
        """Test CIDR scanning with valid JSON file upload."""
        from io import BytesIO
        import json

        valid_json_data = {"test": {"cidrs": ["192.168.1.0/24"]}}
        valid_json = BytesIO(json.dumps(valid_json_data).encode())

        with patch(
            "vpc_flow_investigator.aws_utils.download_vpc_flow_logs"
        ) as mock_download:
            with patch("vpc_flow_investigator.parser.read_log_file") as mock_read:
                with patch(
                    "vpc_flow_investigator.cidr_analyzer.CIDRAnalyzer"
                ) as mock_analyzer_class:
                    mock_download.return_value = "/tmp/test.log"
                    mock_read.return_value = iter([])
                    mock_analyzer = Mock()
                    mock_analyzer_class.return_value = mock_analyzer

                    response = client.post(
                        "/api/scan-cidrs",
                        data={
                            "profile": "default",
                            "log_group": "test-log-group",
                        },
                        files={
                            "cidr_file": ("test.json", valid_json, "application/json")
                        },
                    )

                    assert response.status_code == 200

    def test_scan_cidrs_with_non_now_end_time(self, client):
        """Test CIDR scanning with specific end time."""
        with patch(
            "vpc_flow_investigator.aws_utils.download_vpc_flow_logs"
        ) as mock_download:
            with patch("vpc_flow_investigator.parser.read_log_file") as mock_read:
                with patch(
                    "vpc_flow_investigator.cidr_analyzer.CIDRAnalyzer"
                ) as mock_analyzer_class:
                    with patch(
                        "vpc_flow_investigator.time_utils.parse_time_input"
                    ) as mock_parse:
                        mock_download.return_value = "/tmp/test.log"
                        mock_read.return_value = iter([])
                        mock_analyzer = Mock()
                        mock_analyzer_class.return_value = mock_analyzer
                        mock_parse.return_value = 1418530000

                        response = client.post(
                            "/api/scan-cidrs",
                            data={
                                "profile": "default",
                                "log_group": "test-log-group",
                                "end_time": "1418530100",
                            },
                        )

                        assert response.status_code == 200

    def test_all_analyzer_branches(self):
        """Test all analyzer branches for complete coverage."""
        from vpc_flow_investigator.web import (
            SSHInboundAnalyzer,
            SSHResponseAnalyzer,
            SSHOutboundAnalyzer,
            ExternalOutboundAnalyzer,
            TopExternalAnalyzer,
            SensitivePortsAnalyzer,
            RejectedTrafficAnalyzer,
            PortSpecificAnalyzer,
        )

        # Test logs with various scenarios
        test_logs = [
            {
                "srcaddr": "203.0.113.1",
                "dstaddr": "10.0.1.100",
                "srcport": "49152",
                "dstport": "22",
                "action": "ACCEPT",
            },
            {
                "srcaddr": "10.0.1.100",
                "dstaddr": "203.0.113.2",
                "srcport": "22",
                "dstport": "49153",
                "action": "ACCEPT",
            },
            {
                "srcaddr": "10.0.1.100",
                "dstaddr": "8.8.8.8",
                "srcport": "49154",
                "dstport": "22",
                "action": "ACCEPT",
            },
            {
                "srcaddr": "203.0.113.3",
                "dstaddr": "10.0.1.100",
                "srcport": "49155",
                "dstport": "3389",
                "action": "REJECT",
            },
            {
                "srcaddr": "203.0.113.4",
                "dstaddr": "8.8.8.8",
                "srcport": "49156",
                "dstport": "443",
                "action": "ACCEPT",
            },
        ]

        config = {
            "instance_ips": ["10.0.1.100"],
            "vpc_cidr_prefix": "10.0.",
            "port": 22,
        }

        with patch("vpc_flow_investigator.whois_utils.get_whois_info") as mock_whois:
            with patch(
                "vpc_flow_investigator.whois_utils.is_external_ip"
            ) as mock_is_external:
                mock_whois.return_value = {"org": "Test Organization"}
                mock_is_external.side_effect = lambda ip, prefix: not ip.startswith(
                    prefix
                )

                # Test all analyzers to hit different branches
                SSHInboundAnalyzer.analyze(test_logs, config)
                SSHResponseAnalyzer.analyze(test_logs, config)
                SSHOutboundAnalyzer.analyze(test_logs, config)
                ExternalOutboundAnalyzer.analyze(test_logs, config)
                TopExternalAnalyzer.analyze(test_logs, config)
                SensitivePortsAnalyzer.analyze(test_logs, config)
                RejectedTrafficAnalyzer.analyze(test_logs, config)
                PortSpecificAnalyzer.analyze(test_logs, config)

    def test_analysis_result_processor_all_branches(self):
        """Test all branches of analysis result processor."""
        from vpc_flow_investigator.web import AnalysisResultProcessor

        test_logs = [
            {
                "srcaddr": "203.0.113.1",
                "dstaddr": "10.0.1.100",
                "srcport": "49152",
                "dstport": "22",
                "action": "ACCEPT",
            },
        ]

        config = {
            "instance_ips": ["10.0.1.100"],
            "vpc_cidr_prefix": "10.0.",
            "analysis": "traffic-summary",
        }

        with patch("vpc_flow_investigator.whois_utils.get_whois_info") as mock_whois:
            with patch(
                "vpc_flow_investigator.whois_utils.is_external_ip"
            ) as mock_is_external:
                mock_whois.return_value = {"org": "Test"}
                mock_is_external.return_value = False

                # Test different analysis types
                for analysis_type in [
                    "ssh-response",
                    "ssh-outbound",
                    "external-outbound",
                    "external-summary",
                    "top-external",
                    "sensitive-ports",
                    "rejected",
                ]:
                    config["analysis"] = analysis_type
                    result = AnalysisResultProcessor.process_logs(test_logs, config)
                    assert "analyses" in result

    def test_configuration_builder_edge_cases(self):
        """Test configuration builder edge cases for 100% coverage."""
        from vpc_flow_investigator.web import AnalysisRequest, ConfigurationBuilder

        # Test with non-integer start_time that falls back to parse_time_input
        request = AnalysisRequest(
            profile="test",
            instance_id="i-1234567890abcdef0",
            region="us-east-1",
            start_time="24h",  # This will cause ValueError in int() conversion
            end_time="12h",  # This will also cause ValueError
            analysis="all",
            port=None,
        )

        with patch("vpc_flow_investigator.web.parse_time_input") as mock_parse:
            mock_parse.side_effect = [1418530000, 1418530100]  # start_time, end_time
            config = ConfigurationBuilder.build_config(request)
            assert config["start_time"] == 1418530000
            assert config["end_time"] == 1418530100
            assert mock_parse.call_count == 2

    def test_rejected_traffic_analyzer_edge_cases(self):
        """Test rejected traffic analyzer edge cases."""
        from vpc_flow_investigator.web import RejectedTrafficAnalyzer

        # Test with both internal and external IPs in rejected traffic
        test_logs = [
            {
                "srcaddr": "10.0.1.100",
                "dstaddr": "203.0.113.1",
                "dstport": "443",
                "action": "REJECT",
            },
            {
                "srcaddr": "203.0.113.2",
                "dstaddr": "10.0.1.100",
                "dstport": "80",
                "action": "REJECT",
            },
        ]

        config = {"vpc_cidr_prefix": "10.0."}

        with patch("vpc_flow_investigator.whois_utils.get_whois_info") as mock_whois:
            with patch(
                "vpc_flow_investigator.whois_utils.is_external_ip"
            ) as mock_is_external:
                mock_whois.return_value = {"org": "External Org"}
                mock_is_external.side_effect = lambda ip, prefix: not ip.startswith(
                    prefix
                )

                result = RejectedTrafficAnalyzer.analyze(test_logs, config)
                assert isinstance(result, list)
                assert len(result) == 2

    def test_scan_cidrs_exception_handling(self, client):
        """Test CIDR scanning exception handling."""
        with patch("vpc_flow_investigator.time_utils.parse_time_input") as mock_parse:
            mock_parse.side_effect = Exception("Parse error")

            response = client.post(
                "/api/scan-cidrs",
                data={
                    "profile": "default",
                    "log_group": "test-log-group",
                    "start_time": "invalid",
                },
            )

            assert response.status_code == 500
            data = response.json()
            assert data["status"] == "error"

    def test_log_download_service_failure(self):
        """Test log download service failure."""
        from vpc_flow_investigator.web import LogDownloadService

        config = {
            "log_group": "test-group",
            "instance_id": "i-123",
            "start_time": 1418530000,
            "end_time": 1418530100,
            "region": "us-east-1",
            "profile": "default",
        }

        with patch("vpc_flow_investigator.web.download_vpc_flow_logs") as mock_download:
            mock_download.return_value = None

            with pytest.raises(Exception):
                LogDownloadService.download_and_validate_logs(config)

    def test_analysis_service_exception_handling(self, client):
        """Test analysis service exception handling."""
        with patch(
            "vpc_flow_investigator.web.ConfigurationBuilder.build_config"
        ) as mock_config:
            mock_config.side_effect = Exception("Configuration error")

            response = client.post(
                "/api/analyze",
                data={
                    "profile": "default",
                    "instance_id": "i-1234567890abcdef0",
                    "analysis": "all",
                },
            )

            assert response.status_code == 500

    def test_analysis_result_processor_port_specific(self):
        """Test analysis result processor with port-specific analysis."""
        from vpc_flow_investigator.web import AnalysisResultProcessor

        test_logs = [
            {
                "srcaddr": "203.0.113.1",
                "dstaddr": "10.0.1.100",
                "dstport": "22",
                "action": "ACCEPT",
            },
        ]

        config = {
            "instance_ips": ["10.0.1.100"],
            "vpc_cidr_prefix": "10.0.",
            "analysis": "port-specific",
            "port": 22,
        }

        with patch("vpc_flow_investigator.whois_utils.get_whois_info") as mock_whois:
            with patch(
                "vpc_flow_investigator.whois_utils.is_external_ip"
            ) as mock_is_external:
                mock_whois.return_value = {"org": "Test"}
                mock_is_external.return_value = False

                result = AnalysisResultProcessor.process_logs(test_logs, config)
                assert "port_specific" in result["analyses"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
