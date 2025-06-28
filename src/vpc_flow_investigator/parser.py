"""
Parser module for VPC Flow Log Investigator.
"""

import gzip
import re
from pathlib import Path
from typing import Any, Generator, Optional

from .config import VPC_FLOW_LOG_PATTERN


class LogLineParser:
    """Handles parsing of individual VPC Flow Log lines."""

    def __init__(self, pattern: str = VPC_FLOW_LOG_PATTERN):
        self.pattern = re.compile(pattern)

    def parse_line(self, line: str) -> Optional[dict[str, Any]]:
        """Parse a VPC Flow Log line into a dictionary."""
        if match := self.pattern.match(line.strip()):
            return match.groupdict()
        return None


class LogFileReader:
    """Handles reading log files with support for compressed files."""

    def __init__(self, parser: LogLineParser):
        self.parser = parser

    def read_file(self, file_path: str) -> Generator[dict[str, Any], None, None]:
        """Read and parse VPC Flow Log file."""
        path = Path(file_path)

        if path.suffix == ".gz":
            yield from self._read_compressed_file(path)
        else:
            yield from self._read_text_file(path)

    def _read_compressed_file(self, path: Path) -> Generator[dict[str, Any], None, None]:
        """Read compressed log file."""
        with gzip.open(path, "rt") as f:
            yield from self._parse_lines(f)

    def _read_text_file(self, path: Path) -> Generator[dict[str, Any], None, None]:
        """Read text log file."""
        with open(path, "r") as f:
            yield from self._parse_lines(f)

    def _parse_lines(self, file_handle: Any) -> Generator[dict[str, Any], None, None]:
        """Parse lines from file handle."""
        for line in file_handle:
            if parsed := self.parser.parse_line(line):
                yield parsed


class LogFilter:
    """Filters logs based on configuration criteria."""

    def __init__(self, config: dict[str, Any]):
        self.config = config

    def filter_logs(
        self, logs: Generator[dict[str, Any], None, None]
    ) -> Generator[dict[str, Any], None, None]:
        """Filter logs based on instance ID and time range."""
        for log in logs:
            if self._matches_instance(log) and self._within_time_range(log):
                yield log

    def _matches_instance(self, log: dict[str, Any]) -> bool:
        """Check if log matches the target instance."""
        # Check if any of the instance IPs are in source or destination
        srcaddr = log.get("srcaddr", "")
        dstaddr = log.get("dstaddr", "")
        instance_ips = self.config.get("instance_ips", [])

        return any(ip in [srcaddr, dstaddr] for ip in instance_ips)

    def _within_time_range(self, log: dict[str, Any]) -> bool:
        """Check if log is within the specified time range."""
        try:
            start_time = int(log.get("start", 0))
            return self.config["start_time"] <= start_time <= self.config["end_time"]
        except (ValueError, TypeError):
            return False


class VPCFlowLogProcessor:
    """Main processor for VPC Flow Logs combining reading, parsing, and filtering."""

    def __init__(self):
        self.parser = LogLineParser()
        self.reader = LogFileReader(self.parser)

    def process_logs(
        self, file_path: str, config: dict[str, Any]
    ) -> Generator[dict[str, Any], None, None]:
        """Process logs from file with filtering."""
        logs = self.reader.read_file(file_path)
        log_filter = LogFilter(config)
        yield from log_filter.filter_logs(logs)


# Public API functions - maintain backward compatibility
def parse_log_line(line: str) -> Optional[dict[str, Any]]:
    """Parse a VPC Flow Log line into a dictionary."""
    parser = LogLineParser()
    return parser.parse_line(line)


def read_log_file(file_path: str) -> Generator[dict[str, Any], None, None]:
    """Read and parse VPC Flow Log file."""
    processor = VPCFlowLogProcessor()
    # For backward compatibility, read all logs without filtering
    yield from processor.reader.read_file(file_path)


def filter_logs(
    logs: Generator[dict[str, Any], None, None], config: dict[str, Any]
) -> Generator[dict[str, Any], None, None]:
    """Filter logs based on instance ID and time range."""
    log_filter = LogFilter(config)
    yield from log_filter.filter_logs(logs)
