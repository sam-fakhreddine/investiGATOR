"""
Pytest configuration and fixtures for VPC Flow Investigator tests.
"""

import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def sample_vpc_log_data():
    """Sample VPC Flow Log data for testing."""
    return """2 123456789012 eni-1234abcd 10.0.1.100 203.0.113.12 10.0.1.100 203.0.113.12 443 49152 6 20 4249 1418530010 1418530070 ACCEPT OK
2 123456789012 eni-1234abcd 203.0.113.12 10.0.1.100 203.0.113.12 10.0.1.100 49152 443 6 20 4249 1418530015 1418530075 ACCEPT OK
2 123456789012 eni-5678efgh 192.168.1.1 203.0.113.12 192.168.1.1 203.0.113.12 80 49153 6 10 2048 1418530020 1418530080 REJECT OK
2 123456789012 eni-1234abcd 10.0.1.100 8.8.8.8 10.0.1.100 8.8.8.8 53 53 17 5 512 1418530025 1418530085 ACCEPT OK"""


@pytest.fixture
def temp_log_file(sample_vpc_log_data):
    """Create a temporary log file with sample data."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(sample_vpc_log_data)
        temp_path = f.name

    yield temp_path

    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def basic_config():
    """Basic configuration for testing."""
    return {
        "instance_id": "i-1234567890abcdef0",
        "instance_ips": ["10.0.1.100"],
        "instance_ip": "10.0.1.100",
        "vpc_cidr_prefix": "10.0.",
        "start_time": 1418530000,
        "end_time": 1418530100,
        "limit": 100,
        "region": "us-east-1",
        "profile": None,
        "log_group": None,
        "log_file": None,
    }
