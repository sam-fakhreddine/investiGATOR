"""
Basic functionality tests for VPC Flow Log Investigator.
"""

import pytest
import time
from unittest.mock import patch, mock_open
from vpc_flow_investigator.parser import parse_log_line, LogLineParser, LogFilter
from vpc_flow_investigator.config import (
    DEFAULT_CONFIG,
    SENSITIVE_PORTS,
    VPC_FLOW_LOG_PATTERN,
    ConfigurationValidator,
    AnalysisConfig,
)
from vpc_flow_investigator.time_utils import parse_time_input, parse_time_duration


class TestLogParsing:
    """Test VPC Flow Log parsing functionality."""

    def test_parse_valid_log_line(self):
        """Test parsing a valid VPC Flow Log line."""
        log_line = "2 123456789012 eni-1234abcd 10.0.1.100 203.0.113.12 10.0.1.100 203.0.113.12 443 49152 6 20 4249 1418530010 1418530070 ACCEPT OK"
        
        result = parse_log_line(log_line)
        
        assert result is not None
        assert result["version"] == "2"
        assert result["account"] == "123456789012"
        assert result["srcaddr"] == "10.0.1.100"
        assert result["dstaddr"] == "203.0.113.12"
        assert result["srcport"] == "443"
        assert result["dstport"] == "49152"
        assert result["protocol"] == "6"
        assert result["action"] == "ACCEPT"

    def test_parse_invalid_log_line(self):
        """Test parsing an invalid log line returns None."""
        invalid_line = "invalid log line format"
        result = parse_log_line(invalid_line)
        assert result is None

    def test_parse_empty_line(self):
        """Test parsing empty line returns None."""
        result = parse_log_line("")
        assert result is None

    def test_log_line_parser_class(self):
        """Test LogLineParser class functionality."""
        parser = LogLineParser()
        log_line = "2 123456789012 eni-1234abcd 10.0.1.100 203.0.113.12 10.0.1.100 203.0.113.12 443 49152 6 20 4249 1418530010 1418530070 ACCEPT OK"
        
        result = parser.parse_line(log_line)
        assert result is not None
        assert result["srcaddr"] == "10.0.1.100"


class TestLogFiltering:
    """Test log filtering functionality."""

    def test_log_filter_matches_instance(self):
        """Test log filter matches correct instance IPs."""
        config = {
            "instance_ips": ["10.0.1.100", "10.0.1.101"],
            "start_time": 1418530000,
            "end_time": 1418530100,
        }
        
        log_filter = LogFilter(config)
        
        # Test source address match
        log1 = {"srcaddr": "10.0.1.100", "dstaddr": "203.0.113.12", "start": "1418530050"}
        assert log_filter._matches_instance(log1)
        
        # Test destination address match
        log2 = {"srcaddr": "203.0.113.12", "dstaddr": "10.0.1.101", "start": "1418530050"}
        assert log_filter._matches_instance(log2)
        
        # Test no match
        log3 = {"srcaddr": "192.168.1.1", "dstaddr": "203.0.113.12", "start": "1418530050"}
        assert not log_filter._matches_instance(log3)

    def test_log_filter_time_range(self):
        """Test log filter time range functionality."""
        config = {
            "instance_ips": ["10.0.1.100"],
            "start_time": 1418530000,
            "end_time": 1418530100,
        }
        
        log_filter = LogFilter(config)
        
        # Test within range
        log1 = {"start": "1418530050"}
        assert log_filter._within_time_range(log1)
        
        # Test before range
        log2 = {"start": "1418529999"}
        assert not log_filter._within_time_range(log2)
        
        # Test after range
        log3 = {"start": "1418530101"}
        assert not log_filter._within_time_range(log3)


class TestConfiguration:
    """Test configuration functionality."""

    def test_default_config_structure(self):
        """Test default configuration has required keys."""
        required_keys = [
            "instance_id", "instance_ip", "vpc_cidr_prefix", "log_file",
            "start_time", "end_time", "limit", "region", "log_group", "profile"
        ]
        
        for key in required_keys:
            assert key in DEFAULT_CONFIG

    def test_sensitive_ports_defined(self):
        """Test sensitive ports are properly defined."""
        assert isinstance(SENSITIVE_PORTS, dict)
        assert 22 in SENSITIVE_PORTS  # SSH
        assert 3389 in SENSITIVE_PORTS  # RDP
        assert SENSITIVE_PORTS[22] == "SSH"

    def test_vpc_flow_log_pattern(self):
        """Test VPC Flow Log pattern is defined."""
        assert isinstance(VPC_FLOW_LOG_PATTERN, str)
        assert len(VPC_FLOW_LOG_PATTERN) > 0

    def test_configuration_validator_time_range(self):
        """Test configuration validator for time ranges."""
        # Valid time range
        start_time = int(time.time()) - 3600  # 1 hour ago
        end_time = int(time.time())
        ConfigurationValidator.validate_time_range(start_time, end_time)
        
        # Invalid time range (start after end)
        with pytest.raises(ValueError, match="Start time must be before end time"):
            ConfigurationValidator.validate_time_range(end_time, start_time)

    def test_configuration_validator_instance_config(self):
        """Test configuration validator for instance config."""
        # Valid instance config
        ConfigurationValidator.validate_instance_config("i-1234567890abcdef0", ["10.0.1.100"])
        
        # Invalid instance ID
        with pytest.raises(ValueError, match="Invalid instance ID format"):
            ConfigurationValidator.validate_instance_config("invalid-id", ["10.0.1.100"])
        
        # Empty instance IPs
        with pytest.raises(ValueError, match="At least one instance IP is required"):
            ConfigurationValidator.validate_instance_config("i-1234567890abcdef0", [])

    def test_analysis_config_validation(self):
        """Test AnalysisConfig validation."""
        # Valid config
        config = AnalysisConfig(
            instance_id="i-1234567890abcdef0",
            instance_ips=["10.0.1.100"],
            vpc_cidr_prefix="10.0.",
            start_time=int(time.time()) - 3600,
            end_time=int(time.time()),
        )
        config.validate()  # Should not raise
        
        # Invalid config - empty instance ID
        config_invalid = AnalysisConfig(
            instance_id="",
            instance_ips=["10.0.1.100"],
            vpc_cidr_prefix="10.0.",
            start_time=int(time.time()) - 3600,
            end_time=int(time.time()),
        )
        with pytest.raises(ValueError, match="Instance ID is required"):
            config_invalid.validate()


class TestTimeUtils:
    """Test time utility functions."""

    def test_parse_time_input_relative(self):
        """Test parsing relative time inputs."""
        current_time = int(time.time())
        
        # Test Unix timestamp as string
        result = parse_time_input(str(current_time))
        assert result == current_time
        
        # Test relative times
        result_1h = parse_time_input("1h")
        expected_1h = current_time - 3600
        assert abs(result_1h - expected_1h) < 5

    def test_parse_time_duration(self):
        """Test parsing time duration strings."""
        assert parse_time_duration("1h") == 3600
        assert parse_time_duration("30m") == 1800
        assert parse_time_duration("2d") == 172800
        assert parse_time_duration("1W") == 604800  # Capital W for weeks

    def test_parse_time_duration_invalid(self):
        """Test parsing invalid time duration strings."""
        with pytest.raises(ValueError):
            parse_time_duration("invalid")


class TestIntegration:
    """Integration tests combining multiple components."""

    def test_end_to_end_log_processing(self):
        """Test end-to-end log processing workflow."""
        # Sample log data
        log_data = """2 123456789012 eni-1234abcd 10.0.1.100 203.0.113.12 10.0.1.100 203.0.113.12 443 49152 6 20 4249 1418530010 1418530070 ACCEPT OK
2 123456789012 eni-1234abcd 203.0.113.12 10.0.1.100 203.0.113.12 10.0.1.100 49152 443 6 20 4249 1418530010 1418530070 ACCEPT OK
2 123456789012 eni-5678efgh 192.168.1.1 203.0.113.12 192.168.1.1 203.0.113.12 80 49153 6 10 2048 1418530020 1418530080 REJECT OK"""
        
        config = {
            "instance_ips": ["10.0.1.100"],
            "start_time": 1418530000,
            "end_time": 1418530100,
        }
        
        # Mock file reading
        with patch("builtins.open", mock_open(read_data=log_data)):
            from vpc_flow_investigator.parser import LogFileReader, LogLineParser
            
            parser = LogLineParser()
            reader = LogFileReader(parser)
            
            # Read logs
            logs = list(reader.read_file("mock_file.log"))
            assert len(logs) == 3
            
            # Filter logs
            log_filter = LogFilter(config)
            filtered_logs = list(log_filter.filter_logs(iter(logs)))
            
            # Should match 2 logs (both involving 10.0.1.100)
            assert len(filtered_logs) == 2
            
            # Verify the filtered logs contain our target IP
            for log in filtered_logs:
                assert "10.0.1.100" in [log["srcaddr"], log["dstaddr"]]


if __name__ == "__main__":
    pytest.main([__file__])