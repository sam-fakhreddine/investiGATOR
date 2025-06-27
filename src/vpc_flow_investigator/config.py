"""
Configuration module for VPC Flow Log Investigator.
"""

import time
from dataclasses import dataclass
from typing import Any, Final, Optional


class DefaultConfiguration:
    """Provides default configuration values."""

    DEFAULT_VPC_CIDR_PREFIX: Final[str] = "10.0."
    DEFAULT_LIMIT: Final[int] = 1000  # Increased for comprehensive analysis
    HOURS_24_IN_SECONDS: Final[int] = 86400

    @classmethod
    def get_default_config(cls) -> dict[str, Any]:
        """Get default configuration dictionary."""
        current_time = int(time.time())
        return {
            "instance_id": "",
            "instance_ip": "",
            "vpc_cidr_prefix": cls.DEFAULT_VPC_CIDR_PREFIX,
            "log_file": None,
            "start_time": current_time
            - cls.HOURS_24_IN_SECONDS,  # 24 hours ago (fallback)
            "end_time": current_time,  # Current time (fallback)
            "limit": cls.DEFAULT_LIMIT,  # Display limit, not query limit
            "region": None,
            "log_group": None,
            "profile": None,
            "sensitive_ports": False,
        }


class VPCFlowLogPatterns:
    """VPC Flow Log parsing patterns and constants."""

    # VPC Flow Log format regex pattern
    LOG_PATTERN: Final[str] = (
        r"(?P<version>\d+) (?P<account>\d+) (?P<eni>\S+) (?P<srcaddr>\S+) (?P<dstaddr>\S+) "
        r"(?P<pkt_srcaddr>\S+) (?P<pkt_dstaddr>\S+) (?P<srcport>\d+) (?P<dstport>\d+) "
        r"(?P<protocol>\d+) (?P<packets>\d+) (?P<bytes>\d+) (?P<start>\d+) (?P<end>\d+) "
        r"(?P<action>\S+)( (?P<pkt_src_aws_service>\S+) (?P<pkt_dst_aws_service>\S+))?"
    )


class ProtocolNumbers:
    """Maps protocol numbers to names."""

    PROTOCOLS: Final[dict[str, str]] = {
        "0": "HOPOPT",
        "1": "ICMP",
        "6": "TCP",
        "17": "UDP",
        "41": "IPv6",
        "47": "GRE",
        "50": "ESP",
        "51": "AH",
        "58": "ICMPv6",
        "89": "OSPF",
        "132": "SCTP",
    }


class SensitivePorts:
    """Defines sensitive ports for security analysis."""

    PORTS: Final[dict[int, str]] = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        135: "RPC",
        137: "NetBIOS Name Service",
        138: "NetBIOS Datagram Service",
        139: "NetBIOS Session Service",
        445: "SMB",
        1433: "MSSQL",
        1434: "MSSQL Browser",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP Alternate",
        27017: "MongoDB",
        27018: "MongoDB Shard",
    }


@dataclass
class AnalysisConfig:
    """Structured configuration for analysis operations."""

    instance_id: str
    instance_ips: list[str]
    vpc_cidr_prefix: str
    start_time: int
    end_time: int
    limit: int = 100
    region: Optional[str] = None
    profile: Optional[str] = None

    def validate(self) -> None:
        """Validate configuration parameters."""
        if not self.instance_id:
            raise ValueError("Instance ID is required")
        if not self.instance_ips:
            raise ValueError("At least one instance IP is required")
        if self.start_time >= self.end_time:
            raise ValueError("Start time must be before end time")
        if self.limit <= 0:
            raise ValueError("Limit must be positive")


class ConfigurationValidator:
    """Validates configuration parameters."""

    @staticmethod
    def validate_time_range(start_time: int, end_time: int) -> None:
        """Validate time range parameters."""
        if start_time >= end_time:
            raise ValueError("Start time must be before end time")

        # Check for reasonable time ranges (not more than 30 days)
        max_range = 30 * 24 * 3600  # 30 days in seconds
        if end_time - start_time > max_range:
            raise ValueError("Time range cannot exceed 30 days")

    @staticmethod
    def validate_instance_config(instance_id: str, instance_ips: list[str]) -> None:
        """Validate instance configuration."""
        if not instance_id or not instance_id.startswith("i-"):
            raise ValueError("Invalid instance ID format")

        if not instance_ips:
            raise ValueError("At least one instance IP is required")

        # Basic IP format validation
        import ipaddress

        for ip in instance_ips:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise ValueError(f"Invalid IP address format: {ip}")


# Public API - maintain backward compatibility
DEFAULT_CONFIG = DefaultConfiguration.get_default_config()
VPC_FLOW_LOG_PATTERN = VPCFlowLogPatterns.LOG_PATTERN
SENSITIVE_PORTS = SensitivePorts.PORTS
PROTOCOL_NUMBERS = ProtocolNumbers.PROTOCOLS
