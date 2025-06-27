#!/usr/bin/env python3
"""
Example of using the CIDR analyzer to query connections to IPv4 addresses
from CIDR JSON files.
"""

from src.vpc_flow_investigator.cidr_analyzer import CIDRAnalyzer

def main():
    # Initialize the CIDR analyzer
    analyzer = CIDRAnalyzer()
    
    print(f"Loaded {len(analyzer.cidr_data)} CIDR data files:")
    for provider, data in analyzer.cidr_data.items():
        subnet_count = len(data.get('subnets', []))
        description = data.get('description', 'No description')
        print(f"  - {provider}: {subnet_count} subnets ({description})")
    
    # Example log entries to analyze
    sample_logs = [
        {
            "srcaddr": "10.0.1.100",
            "dstaddr": "8.3.29.50",  # Should match Vultr Los Angeles
            "dstport": "443",
            "action": "ACCEPT"
        },
        {
            "srcaddr": "45.32.10.20",  # Should match Vultr Japan
            "dstaddr": "10.0.1.100",
            "dstport": "22",
            "action": "ACCEPT"
        },
        {
            "srcaddr": "10.0.1.100",
            "dstaddr": "1.2.3.4",  # Should not match any CIDR
            "dstport": "80",
            "action": "REJECT"
        }
    ]
    
    # Configuration for analysis
    config = {"limit": 10}
    
    print("\nAnalyzing sample log entries...")
    analyzer.analyze_cidr_connections(sample_logs, config)

if __name__ == "__main__":
    main()