"""
VPC Flow Log Investigator package.

A comprehensive tool for analyzing AWS VPC Flow Logs to investigate
network traffic patterns and security events.
"""

from typing import Final

# Package metadata
__version__: Final[str] = "1.0.0"
__author__: Final[str] = "VPC Flow Log Investigator Team"
__description__: Final[str] = "AWS VPC Flow Log analysis and investigation tool"

# Public API exports
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
from .aws_utils import download_vpc_flow_logs, find_vpc_flow_log_group, get_instance_info
from .config import DEFAULT_CONFIG, SENSITIVE_PORTS, VPC_FLOW_LOG_PATTERN
from .parser import filter_logs, parse_log_line, read_log_file
from .time_utils import parse_time_duration, parse_time_input
from .whois_utils import get_whois_info, is_external_ip

__all__ = [
    # Analyzers
    "external_inbound_traffic",
    "external_outbound_traffic",
    "external_traffic_summary",
    "overall_traffic_summary",
    "port_specific_traffic",
    "rejected_traffic",
    "sensitive_ports_traffic",
    "ssh_inbound_traffic",
    "ssh_outbound_connections",
    "ssh_response_traffic",
    "top_external_traffic_flows",
    # AWS utilities
    "download_vpc_flow_logs",
    "find_vpc_flow_log_group",
    "get_instance_info",
    # Configuration
    "DEFAULT_CONFIG",
    "SENSITIVE_PORTS",
    "VPC_FLOW_LOG_PATTERN",
    # Parser
    "filter_logs",
    "parse_log_line",
    "read_log_file",
    # Time utilities
    "parse_time_duration",
    "parse_time_input",
    # WHOIS utilities
    "get_whois_info",
    "is_external_ip",
]
