"""
CIDR analyzer for VPC Flow Log Investigator.
Analyzes connections to IPv4 addresses from CIDR JSON files.
"""

import ipaddress
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class CIDRAnalyzer:
    """Analyzes connections to IPv4 addresses from CIDR JSON files."""

    def __init__(self, cidrs_dir: str = None):
        """Initialize with path to CIDR JSON files directory."""
        if cidrs_dir is None:
            # Default to cidrs directory relative to this file
            cidrs_dir = Path(__file__).parent / "cidrs"
        self.cidrs_dir = Path(cidrs_dir)
        self.cidr_data = self._load_cidr_data()

    def _load_cidr_data(self) -> Dict[str, Any]:
        """Load all CIDR JSON files from the directory."""
        cidr_data = {}

        if not self.cidrs_dir.exists():
            return cidr_data

        for json_file in self.cidrs_dir.glob("*.json"):
            try:
                with open(json_file, "r") as f:
                    data = json.load(f)
                    cidr_data[json_file.stem] = data
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Failed to load {json_file}: {e}")

        return cidr_data

    def _ip_in_subnets(
        self, ip: str, subnets: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Check if IP is in any of the subnets and return subnet info."""
        try:
            ip_addr = ipaddress.ip_address(ip)
            for subnet in subnets:
                try:
                    network = ipaddress.ip_network(subnet["ip_prefix"], strict=False)
                    if ip_addr in network:
                        return subnet
                except (ValueError, KeyError):
                    continue
        except ValueError:
            pass
        return None

    def analyze_cidr_connections(
        self, logs: List[Dict[str, Any]], config: Dict[str, Any]
    ) -> None:
        """Analyze connections to IPs that match CIDR ranges."""
        if not self.cidr_data:
            print("\n=== CIDR Analysis ===")
            print("No CIDR data files found in cidrs directory")
            return

        results = defaultdict(int)
        matched_ips = set()

        for log in logs:
            srcaddr = log.get("srcaddr", "")
            dstaddr = log.get("dstaddr", "")
            action = log.get("action", "unknown")

            # Check both source and destination IPs
            for ip_addr in [srcaddr, dstaddr]:
                if not ip_addr:
                    continue

                for provider_name, provider_data in self.cidr_data.items():
                    subnets = provider_data.get("subnets", [])
                    subnet_match = self._ip_in_subnets(ip_addr, subnets)

                    if subnet_match:
                        matched_ips.add(ip_addr)
                        key = (
                            provider_name,
                            ip_addr,
                            subnet_match.get("city", "Unknown"),
                            subnet_match.get("region", "Unknown"),
                            action,
                        )
                        results[key] += 1

        self._print_cidr_results(results, config, matched_ips)

    def _print_cidr_results(
        self, results: Dict, config: Dict[str, Any], matched_ips: Set[str]
    ) -> None:
        """Print CIDR analysis results."""
        if not results:
            print("\n=== CIDR Analysis ===")
            print("No connections found to IPs in CIDR ranges")
            return

        sorted_results = sorted(results.items(), key=lambda x: x[1], reverse=True)

        print("\n=== CIDR Analysis ===")
        print(f"Found {len(matched_ips)} unique IPs matching CIDR ranges")
        print(
            f"{'Provider':<20} {'IP Address':<16} {'City':<15} {'Region':<10} {'Action':<8} {'Count':<8}"
        )
        print("-" * 85)

        for (provider, ip, city, region, action), count in sorted_results[
            : config["limit"]
        ]:
            print(
                f"{provider:<20} {ip:<16} {city:<15} {region:<10} {action:<8} {count:<8}"
            )


def cidr_connections_analysis(
    logs: List[Dict[str, Any]], config: Dict[str, Any]
) -> None:
    """Analyze connections to IPs in CIDR ranges - function for CLI integration."""
    analyzer = CIDRAnalyzer()
    analyzer.analyze_cidr_connections(logs, config)
