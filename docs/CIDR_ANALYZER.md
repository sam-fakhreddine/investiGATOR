# CIDR Analyzer

The CIDR Analyzer is a feature extension that allows you to query VPC Flow Log connections to IPv4 addresses that appear in CIDR JSON files.

## Overview

The analyzer loads JSON files from the `src/vpc_flow_investigator/cidrs/` directory and matches IP addresses from VPC Flow Logs against the CIDR ranges defined in those files. This is useful for identifying connections to specific cloud providers, CDNs, or other known IP ranges.

## JSON File Format

CIDR JSON files should follow this structure:

```json
{
  "description": "Provider Name / Service Description",
  "asn": 12345,
  "email": "contact@provider.com",
  "updated": "2025-01-01T00:00:00Z",
  "subnets": [
    {
      "ip_prefix": "8.3.29.0/24",
      "alpha2code": "US",
      "region": "US-CA",
      "city": "Los Angeles",
      "postal_code": "90012"
    }
  ]
}
```

## Usage

### Command Line

To run CIDR analysis from the command line:

```bash
# Analyze CIDR connections only
poetry run python -m vpc_flow_investigator --instance-id i-1234567890abcdef0 --analysis cidr-connections

# Include CIDR analysis in all analyses
poetry run python -m vpc_flow_investigator --instance-id i-1234567890abcdef0 --analysis all
```

### Programmatic Usage

```python
from src.vpc_flow_investigator.cidr_analyzer import CIDRAnalyzer

# Initialize analyzer
analyzer = CIDRAnalyzer()

# Analyze logs
sample_logs = [
    {
        "srcaddr": "10.0.1.100",
        "dstaddr": "8.3.29.50",
        "dstport": "443",
        "action": "ACCEPT"
    }
]

config = {"limit": 10}
analyzer.analyze_cidr_connections(sample_logs, config)
```

## Output

The analyzer provides:

- Total count of unique IPs matching CIDR ranges
- Detailed breakdown by:
  - Provider/source file
  - IP address
  - City and region (if available in JSON)
  - Connection action (ACCEPT/REJECT)
  - Connection count

Example output:
```
=== CIDR Analysis ===
Found 2 unique IPs matching CIDR ranges
Provider             IP Address       City            Region     Action   Count   
-------------------------------------------------------------------------------------
geofeed.constant.com 8.3.29.50        Los Angeles     US-CA      ACCEPT   1       
geofeed.constant.com 45.32.10.20      Shinagawa-ku    JP-13      ACCEPT   1       
```

## Adding New CIDR Data

1. Place JSON files in `src/vpc_flow_investigator/cidrs/`
2. Follow the JSON format structure above
3. The analyzer will automatically load all `.json` files in the directory

## Example Data

The project includes `geofeed.constant.com.json` as an example, containing Vultr.com/Constant.com IP ranges with geographic information.