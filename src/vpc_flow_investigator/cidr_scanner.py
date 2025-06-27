#!/usr/bin/env python3
"""
Scan a specific VPC Flow Log file for IPs that appear in CIDR directory.
"""

import argparse
from .cidr_analyzer import CIDRAnalyzer
from .parser import read_log_file


def scan_flowlog_for_cidrs(log_group: str, start_time: int, end_time: int, region: str = None, profile: str = None) -> None:
    """Scan AWS flow log group for IPs matching CIDR ranges."""
    from .aws_utils import download_vpc_flow_logs
    
    analyzer = CIDRAnalyzer()
    
    if not analyzer.cidr_data:
        print("No CIDR data files found")
        return
    
    print(f"Downloading logs from {log_group}...")
    
    log_file = download_vpc_flow_logs(
        log_group, None, start_time, end_time, region, profile, False
    )
    
    if not log_file:
        print("Failed to download logs")
        return
        
    print(f"Scanning for IPs in CIDR ranges...")
    logs = list(read_log_file(log_file))
    config = {"limit": 50}
    
    analyzer.analyze_cidr_connections(logs, config)


def main():
    from .time_utils import parse_time_input
    import time
    
    parser = argparse.ArgumentParser(description="Scan VPC Flow Log for CIDR matches")
    parser.add_argument("log_group", help="CloudWatch Log Group name")
    parser.add_argument("--start-time", default="24h", help="Start time")
    parser.add_argument("--end-time", default="now", help="End time")
    parser.add_argument("--region", help="AWS region")
    parser.add_argument("--profile", help="AWS profile")
    
    args = parser.parse_args()
    
    end_time = int(time.time()) if args.end_time == "now" else parse_time_input(args.end_time)
    start_time = parse_time_input(args.start_time)
    
    scan_flowlog_for_cidrs(args.log_group, start_time, end_time, args.region, args.profile)


if __name__ == "__main__":
    main()