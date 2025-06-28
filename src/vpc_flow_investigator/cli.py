"""
Command-line interface for VPC Flow Log Investigator.
"""

import argparse
import os
import time
from datetime import datetime
from typing import Any, Callable

from .analyzers import (
    external_inbound_traffic,
    external_outbound_traffic,
    external_traffic_summary,
    overall_traffic_summary,
    port_specific_traffic,
    rejected_traffic,
    sensitive_ports_traffic,
    ssh_inbound_traffic,
    ssh_outbound_connections,
    ssh_response_traffic,
    top_external_traffic_flows,
)
from .aws_utils import (
    download_vpc_flow_logs,
    find_vpc_flow_log_group,
    get_instance_info,
)
from .cidr_scanner import scan_flowlog_for_cidrs
from .config import DEFAULT_CONFIG
from .logging_utils import (
    generate_query_id,
    log_query_end,
    log_query_start,
    setup_logger,
)
from .parser import filter_logs, read_log_file
from .time_utils import parse_time_input


class ArgumentParser:
    """Handles command-line argument parsing."""

    ANALYSIS_CHOICES = [
        "all",
        "traffic-summary",
        "ssh-inbound",
        "ssh-response",
        "ssh-outbound",
        "external-inbound",
        "external-outbound",
        "external-summary",
        "top-external",
        "port-specific",
        "sensitive-ports",
        "rejected",
        "cidr-connections",
    ]

    @classmethod
    def parse_args(cls) -> argparse.Namespace:
        """Parse and return command-line arguments."""
        parser = argparse.ArgumentParser(description="VPC Flow Log Investigator")

        cls._add_required_args(parser)
        cls._add_aws_args(parser)
        cls._add_log_args(parser)
        cls._add_time_args(parser)
        cls._add_analysis_args(parser)

        return parser.parse_args()

    @staticmethod
    def _add_required_args(parser: argparse.ArgumentParser) -> None:
        """Add required arguments."""
        parser.add_argument(
            "--instance-id",
            help="Instance ID to investigate (not required for --scan-cidrs)",
        )

    @staticmethod
    def _add_aws_args(parser: argparse.ArgumentParser) -> None:
        """Add AWS-related arguments."""
        parser.add_argument("--profile", help="AWS profile name to use for API calls")
        parser.add_argument("--region", help="AWS region where the instance is located")

    @staticmethod
    def _add_log_args(parser: argparse.ArgumentParser) -> None:
        """Add log-related arguments."""
        parser.add_argument(
            "--log-file", help="Path to local VPC Flow Log file (if not using AWS)"
        )
        parser.add_argument(
            "--log-group", help="CloudWatch Logs group name for VPC Flow Logs"
        )
        parser.add_argument(
            "--instance-ip", help="Instance IP (will be auto-detected if not provided)"
        )
        parser.add_argument(
            "--vpc-cidr",
            help="VPC CIDR prefix (e.g., '10.0.', will be auto-detected if not provided)",
        )

    @staticmethod
    def _add_time_args(parser: argparse.ArgumentParser) -> None:
        """Add time-related arguments."""
        parser.add_argument(
            "--start-time",
            default="24h",
            help="Start time (Unix timestamp, duration like '1h', '3d', '2W', or ISO datetime)",
        )
        parser.add_argument(
            "--end-time",
            default="now",
            help="End time (Unix timestamp, 'now', or ISO datetime)",
        )

    @classmethod
    def _add_analysis_args(cls, parser: argparse.ArgumentParser) -> None:
        """Add analysis-related arguments."""
        parser.add_argument(
            "--limit",
            type=int,
            default=DEFAULT_CONFIG["limit"],
            help="Limit number of results",
        )
        parser.add_argument(
            "--analysis",
            choices=cls.ANALYSIS_CHOICES,
            default="all",
            help="Type of analysis to perform",
        )
        parser.add_argument(
            "--sensitive-ports",
            action="store_true",
            help="Analyze traffic on commonly sensitive ports (RDP, SQL, etc.)",
        )
        parser.add_argument(
            "--port",
            type=int,
            help="Specific port to analyze when using port-specific analysis",
        )
        parser.add_argument(
            "--debug",
            action="store_true",
            help="Enable debug output to see detailed processing information",
        )
        parser.add_argument(
            "--scan-cidrs",
            help="Scan AWS log group for CIDR matches (provide log group name)",
        )


class TimeParser:
    """Handles time parsing and validation."""

    @staticmethod
    def parse_time_arguments(args: argparse.Namespace) -> tuple[int, int]:
        """Parse and validate time arguments."""
        try:
            end_time = (
                int(time.time())
                if args.end_time == "now"
                else parse_time_input(args.end_time)
            )
            start_time = parse_time_input(args.start_time)
            return start_time, end_time
        except ValueError as e:
            raise ValueError(f"Error parsing time: {e}")


class ConfigurationBuilder:
    """Builds configuration from arguments and AWS data."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.config = DEFAULT_CONFIG.copy()

    def build_configuration(self) -> dict[str, Any]:
        """Build complete configuration from arguments."""
        self._set_basic_config()
        self._parse_time_config()

        if self.args.log_file:
            self._configure_local_file()
        else:
            self._configure_aws_source()

        return self.config

    def _set_basic_config(self) -> None:
        """Set basic configuration values."""
        self.config.update(
            {
                "instance_id": self.args.instance_id,
                "limit": self.args.limit,
                "region": self.args.region,
                "log_group": self.args.log_group,
                "profile": self.args.profile,
                "sensitive_ports": self.args.sensitive_ports,
                "debug": getattr(self.args, "debug", False),
            }
        )

    def _parse_time_config(self) -> None:
        """Parse and set time configuration."""
        start_time, end_time = TimeParser.parse_time_arguments(self.args)
        self.config["start_time"] = start_time
        self.config["end_time"] = end_time

    def _configure_local_file(self) -> None:
        """Configure for local log file usage."""
        self.config["log_file"] = self.args.log_file

        if self.args.instance_ip:
            self.config["instance_ip"] = self.args.instance_ip
            self.config["instance_ips"] = [self.args.instance_ip]
        else:
            self.config["instance_ips"] = []
            print(
                "Warning: No instance IP provided. Analysis requiring IP matching will not work correctly."
            )

        if self.args.vpc_cidr:
            self.config["vpc_cidr_prefix"] = self.args.vpc_cidr

    def _configure_aws_source(self) -> None:
        """Configure for AWS data source."""
        instance_info = self._get_instance_info()
        self._set_instance_config(instance_info)
        self._set_log_group_config(instance_info)
        self._download_logs()

    def _get_instance_info(self) -> dict[str, Any]:
        """Get instance information from AWS."""
        if self.config.get("debug"):
            print(
                f"[DEBUG] Getting information for instance {self.args.instance_id}..."
            )
            print(f"[DEBUG] Region: {self.args.region}")
            print(f"[DEBUG] Profile: {self.args.profile}")
        else:
            print(f"Getting information for instance {self.args.instance_id}...")

        instance_info = get_instance_info(
            self.args.instance_id, self.args.region, self.args.profile
        )

        if self.config.get("debug") and instance_info:
            print(f"[DEBUG] Instance info retrieved: {instance_info}")

        if not instance_info:
            raise RuntimeError(
                "Failed to get instance information from AWS. Please check your credentials and instance ID."
            )

        return instance_info

    def _set_instance_config(self, instance_info: dict[str, Any]) -> None:
        """Set instance-related configuration."""
        if self.args.instance_ip:
            self.config["instance_ips"] = [self.args.instance_ip]
            self.config["instance_ip"] = self.args.instance_ip
        else:
            self.config["instance_ips"] = instance_info["private_ips"]
            self.config["instance_ip"] = instance_info["primary_ip"]

        self.config["vpc_cidr_prefix"] = (
            self.args.vpc_cidr or instance_info["vpc_cidr_prefix"]
        )
        self.config["region"] = instance_info["region"]

    def _set_log_group_config(self, instance_info: dict[str, Any]) -> None:
        """Set log group configuration."""
        if not self.config["log_group"]:
            if self.config.get("debug"):
                print(
                    f"[DEBUG] Finding VPC Flow Log group for VPC {instance_info['vpc_id']}..."
                )
            else:
                print(
                    f"Finding VPC Flow Log group for VPC {instance_info['vpc_id']}..."
                )

            log_group = find_vpc_flow_log_group(
                instance_info["vpc_id"], self.config["region"], self.args.profile
            )

            if not log_group:
                if self.config.get("debug"):
                    print("[DEBUG] No VPC Flow Log group found")
                raise RuntimeError(
                    "Could not find VPC Flow Log group. Please specify with --log-group or provide a local log file with --log-file."
                )

            self.config["log_group"] = log_group
            if self.config.get("debug"):
                print(f"[DEBUG] Found VPC Flow Log group: {log_group}")
            else:
                print(f"Found VPC Flow Log group: {log_group}")

    def _download_logs(self) -> None:
        """Download VPC Flow Logs."""
        if self.config.get("debug"):
            print(f"[DEBUG] Downloading logs from group: {self.config['log_group']}")
            print(
                f"[DEBUG] Time range: {self.config['start_time']} to {self.config['end_time']}"
            )
            print(f"[DEBUG] Instance ID filter: {self.config['instance_id']}")

        log_file = download_vpc_flow_logs(
            self.config["log_group"],
            self.config["instance_id"],
            self.config["start_time"],
            self.config["end_time"],
            self.config["region"],
            self.args.profile,
            self.config.get("debug", False),
        )

        if not log_file:
            if self.config.get("debug"):
                print("[DEBUG] No log file returned from download")
            raise RuntimeError(
                "Failed to download VPC Flow Logs. Please check your permissions or provide a local log file."
            )

        if self.config.get("debug"):
            print(f"[DEBUG] Log file created: {log_file}")
        self.config["log_file"] = log_file


class ConfigurationPrinter:
    """Handles printing configuration information."""

    @staticmethod
    def print_configuration(config: dict[str, Any]) -> None:
        """Print configuration summary."""
        print("\n=== VPC Flow Log Investigator ===")
        print(f"Instance ID: {config['instance_id']}")
        print(f"Instance primary IP: {config['instance_ip']}")

        if len(config["instance_ips"]) > 1:
            additional_ips = [
                ip for ip in config["instance_ips"] if ip != config["instance_ip"]
            ]
            print(f"Additional IPs: {', '.join(additional_ips)}")

        print(f"Total instance IPs: {len(config['instance_ips'])}")
        print(f"VPC CIDR prefix: {config['vpc_cidr_prefix']}")
        print(f"Log file: {config['log_file']}")

        if config["log_group"]:
            print(f"Log group: {config['log_group']}")

        if config.get("debug"):
            print("[DEBUG] Debug mode enabled")
            print(f"[DEBUG] Full config: {config}")

        print(
            f"Time range: {datetime.fromtimestamp(config['start_time'])} to {datetime.fromtimestamp(config['end_time'])}"
        )
        print(f"Result limit: {config['limit']}")

        if config["region"]:
            print(f"AWS Region: {config['region']}")
        if config["profile"]:
            print(f"AWS Profile: {config['profile']}")


class AnalysisRunner:
    """Handles running different types of analysis."""

    ANALYSIS_FUNCTIONS: dict[str, Callable[..., None]] = {
        "traffic-summary": overall_traffic_summary,
        "ssh-inbound": ssh_inbound_traffic,
        "ssh-response": ssh_response_traffic,
        "ssh-outbound": ssh_outbound_connections,
        "external-inbound": external_inbound_traffic,
        "external-outbound": external_outbound_traffic,
        "external-summary": external_traffic_summary,
        "top-external": top_external_traffic_flows,
        "port-specific": port_specific_traffic,
        "rejected": rejected_traffic,
        "sensitive-ports": sensitive_ports_traffic,
        # "cidr-connections": cidr_connections_analysis,  # Removed due to missing import
    }

    def __init__(
        self,
        logs: list[dict[str, Any]],
        config: dict[str, Any],
        args: argparse.Namespace,
    ):
        self.logs = logs
        self.config = config
        self.args = args

    def run_analysis(self) -> None:
        """Run the selected analysis."""
        if self.args.analysis == "all":
            self._run_all_analyses()
        else:
            self._run_single_analysis(self.args.analysis)

    def _run_all_analyses(self) -> None:
        """Run all available analyses."""
        for analysis_name in [
            "traffic-summary",
            "ssh-inbound",
            "ssh-response",
            "ssh-outbound",
            "external-inbound",
            "external-outbound",
            "external-summary",
            "top-external",
            "rejected",
            # "cidr-connections",  # Removed due to missing import
        ]:
            self._run_single_analysis(analysis_name)
        # Run conditional analyses
        if self.config["sensitive_ports"]:
            self._run_single_analysis("sensitive-ports")

    def _run_single_analysis(self, analysis_name: str) -> None:
        """Run a single analysis."""
        analysis_func = self.ANALYSIS_FUNCTIONS[analysis_name]

        if analysis_name == "port-specific":
            analysis_func(self.logs, self.config, self.args.port)
        else:
            analysis_func(self.logs, self.config)


class FileCleanupManager:
    """Handles temporary file cleanup."""

    def __init__(self, config: dict[str, Any], args: argparse.Namespace):
        self.temp_file_created = not args.log_file and config.get("log_file")
        self.log_file_path = config.get("log_file")

    def cleanup(self) -> None:
        """Clean up temporary files if needed."""
        if (
            self.temp_file_created
            and self.log_file_path
            and os.path.exists(self.log_file_path)
        ):
            try:
                os.remove(self.log_file_path)
                print(f"Cleaned up temporary log file: {self.log_file_path}")
            except Exception as e:
                print(f"Warning: Failed to clean up temporary file: {e}")


def main() -> int:
    """Main entry point for the CLI."""
    logger = setup_logger("vpc-flow-cli")
    query_id = generate_query_id()
    config = None
    args = None

    try:
        args = ArgumentParser.parse_args()

        # Handle CIDR scanning mode
        if args.scan_cidrs:
            from .time_utils import parse_time_input

            end_time = (
                int(time.time())
                if args.end_time == "now"
                else parse_time_input(args.end_time)
            )
            start_time = parse_time_input(args.start_time)
            scan_flowlog_for_cidrs(
                args.scan_cidrs, start_time, end_time, args.region, args.profile
            )
            return 0

        log_query_start(
            logger,
            query_id,
            instance_id=args.instance_id,
            analysis=args.analysis,
            profile=args.profile,
        )

        config = ConfigurationBuilder(args).build_configuration()

        ConfigurationPrinter.print_configuration(config)

        # Read and filter logs
        if config.get("debug"):
            print(f"[DEBUG] Reading log file: {config['log_file']}")
            raw_logs = list(read_log_file(config["log_file"]))
            print(f"[DEBUG] Raw log entries read: {len(raw_logs)}")
            if raw_logs:
                print(f"[DEBUG] Sample log entry: {raw_logs[0]}")

            logs = list(filter_logs(read_log_file(config["log_file"]), config))  # type: ignore[misc]
            print(f"[DEBUG] Filtered log entries: {len(logs)}")
            if logs:
                print(f"[DEBUG] Sample filtered entry: {logs[0]}")
        else:
            logs = list(filter_logs(read_log_file(config["log_file"]), config))  # type: ignore[misc]

        print(f"Filtered log entries: {len(logs)}")

        # Run analysis
        AnalysisRunner(logs, config, args).run_analysis()

        log_query_end(logger, query_id, True, total_logs=len(logs))
        return 0

    except (ValueError, RuntimeError) as e:
        log_query_end(logger, query_id, False, error=str(e))
        print(f"Error: {e}")
        return 1
    except FileNotFoundError:
        log_query_end(logger, query_id, False, error="Log file not found")
        log_file = locals().get("config", {}).get("log_file", "unknown")
        print(f"Error: Log file '{log_file}' not found.")
        return 1
    except Exception as e:
        log_query_end(logger, query_id, False, error=str(e))
        print(f"Unexpected error: {e}")
        return 1
    finally:
        if (
            "config" in locals()
            and "args" in locals()
            and config is not None
            and args is not None
        ):
            FileCleanupManager(config, args).cleanup()
