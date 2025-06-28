"""
Tests for CLI functionality.
"""

from unittest.mock import patch

from vpc_flow_investigator.cli import ArgumentParser, ConfigurationPrinter


class TestArgumentParser:
    """Test CLI argument parsing."""

    def test_argument_parser_basic_args(self):
        """Test basic argument parsing."""
        test_args = [
            "--instance-id",
            "i-1234567890abcdef0",
            "--analysis",
            "traffic-summary",
            "--start-time",
            "1h",
            "--end-time",
            "now",
        ]

        with patch("sys.argv", ["vpc-flow-investigator"] + test_args):
            args = ArgumentParser.parse_args()

            assert args.instance_id == "i-1234567890abcdef0"
            assert args.analysis == "traffic-summary"
            assert args.start_time == "1h"
            assert args.end_time == "now"

    def test_argument_parser_optional_args(self):
        """Test optional argument parsing."""
        test_args = [
            "--instance-id",
            "i-1234567890abcdef0",
            "--analysis",
            "ssh-inbound",
            "--region",
            "us-west-2",
            "--profile",
            "test-profile",
            "--limit",
            "500",
        ]

        with patch("sys.argv", ["vpc-flow-investigator"] + test_args):
            args = ArgumentParser.parse_args()

            assert args.region == "us-west-2"
            assert args.profile == "test-profile"
            assert args.limit == 500


class TestConfigurationPrinter:
    """Test configuration printing functionality."""

    def test_print_configuration(self, basic_config, capsys):
        """Test configuration printing output."""
        basic_config["log_file"] = "/tmp/test.log"
        basic_config["log_group"] = "test-log-group"

        ConfigurationPrinter.print_configuration(basic_config)

        captured = capsys.readouterr()
        output = captured.out

        assert "VPC Flow Log Investigator" in output
        assert "i-1234567890abcdef0" in output
        assert "10.0.1.100" in output
        assert "/tmp/test.log" in output
        assert "test-log-group" in output

    def test_print_configuration_multiple_ips(self, basic_config, capsys):
        """Test configuration printing with multiple IPs."""
        basic_config["instance_ips"] = ["10.0.1.100", "10.0.1.101", "10.0.1.102"]
        basic_config["log_file"] = "/tmp/test.log"

        ConfigurationPrinter.print_configuration(basic_config)

        captured = capsys.readouterr()
        output = captured.out

        assert "Additional IPs: 10.0.1.101, 10.0.1.102" in output
        assert "Total instance IPs: 3" in output

    def test_print_configuration_debug_mode(self, basic_config, capsys):
        """Test configuration printing in debug mode."""
        basic_config["debug"] = True
        basic_config["log_file"] = "/tmp/test.log"

        ConfigurationPrinter.print_configuration(basic_config)

        captured = capsys.readouterr()
        output = captured.out

        assert "[DEBUG] Debug mode enabled" in output
        assert "[DEBUG] Full config:" in output
