# investiGATOR

<!-- markdownlint-disable MD033 -->
<div align="center">
  <img src="src/vpc_flow_investigator/static/investigator.webp" alt="investiGATOR Logo" width="200" height="200">
  
  [![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
</div>

**investiGATOR** - A comprehensive AWS VPC Flow Log analysis tool that provides both command-line and modern web interfaces for investigating network traffic patterns, security events, and potential threats in your AWS infrastructure.

## 🚀 Features

### Core Capabilities

- **🔍 Comprehensive Analysis**: 12 different analysis types for thorough traffic investigation
- **🌐 Modern Web Interface**: Interactive dashboard with calendar pickers and real-time results
- **⚡ Auto-Discovery**: Automatically finds instance IPs, VPC CIDR blocks, and CloudWatch log groups
- **🔐 Multi-Account Support**: AWS profile support for cross-account analysis
- **📊 Protocol Intelligence**: Human-readable protocol names (TCP, UDP, ICMP, etc.)
- **🎯 WHOIS Integration**: Automatic organization lookup for external IP addresses
- **📝 Audit Logging**: All queries logged with unique IDs for debugging and compliance
- **⚙️ Flexible Time Ranges**: Support for relative times (1h, 3d, 2w) and absolute timestamps

### Analysis Types

| Analysis Type | Description | Use Case |
|---------------|-------------|----------|
| `all` | Run all analysis types | Complete security assessment |
| `traffic-summary` | Protocol and action overview | High-level traffic patterns |
| `ssh-inbound` | SSH connection attempts | Brute force detection |
| `ssh-response` | SSH response traffic | Successful SSH sessions |
| `ssh-outbound` | Outbound SSH connections | Lateral movement detection |
| `external-inbound` | External traffic to instance | Inbound threat analysis |
| `external-outbound` | Instance traffic to external IPs | Data exfiltration detection |
| `external-summary` | External traffic by action | External communication overview |
| `top-external` | Highest volume external flows | Bandwidth and connection analysis |
| `port-specific` | Traffic for specific port | Service-specific investigation |
| `sensitive-ports` | RDP, SQL, MongoDB, Redis traffic | Database and remote access monitoring |
| `rejected` | Blocked connection attempts | Security group effectiveness |
| `cidr-connections` | Connections to specific CIDR ranges | Cloud provider traffic analysis |

## 📦 Installation

### Prerequisites

- Python 3.12 or higher
- AWS CLI configured with appropriate credentials
- Poetry (for dependency management)

### Quick Setup

```bash
# Navigate to project directory
cd vpcflowlogs

# Run automated setup
make setup

# Or use the setup script directly
./scripts/setup.sh
```

### Manual Installation

```bash
# Install Poetry if not already installed
curl -sSL https://install.python-poetry.org | python3 -

# Install project dependencies
poetry install

# Verify installation
poetry run vpc-flow-investigator --help
```

### Development Setup

```bash
# Install with development dependencies
poetry install --with dev

# Set up pre-commit hooks (optional)
poetry run pre-commit install

# Run tests
make test

# Format code
make format

# Run linting
make lint
```

## 🖥️ Usage

### Web Interface (Recommended)

Start the web server:

```bash
poetry run vpc-flow-web
```

Then open [http://localhost:8000](http://localhost:8000) in your browser.

**Web Interface Features:**

- 🎛️ **Analysis Type Selection**: All analysis types with dynamic options
- 📊 **Interactive Results**: JSON-formatted results display
- 🔄 **Real-time Processing**: Live updates during analysis
- 📱 **Responsive Design**: Works on desktop, tablet, and mobile
- 🔍 **CIDR Scanning**: Upload CIDR files for specialized analysis
- ⚙️ **AWS Profile Support**: Multi-account analysis capability
- 🎨 **Theme Support**: Light and dark mode toggle

### Command Line Interface

#### Basic Analysis

```bash
# Analyze all traffic for an instance (last 24 hours)
poetry run vpc-flow-investigator --instance-id i-0123456789abcdef0

# Specific analysis type
poetry run vpc-flow-investigator \
  --instance-id i-0123456789abcdef0 \
  --analysis ssh-inbound

# Custom time range
poetry run vpc-flow-investigator \
  --instance-id i-0123456789abcdef0 \
  --start-time "2024-01-01T00:00:00" \
  --end-time "2024-01-02T00:00:00"
```

#### Advanced Usage

```bash
# Port-specific analysis
poetry run vpc-flow-investigator \
  --instance-id i-0123456789abcdef0 \
  --analysis port-specific \
  --port 443

# Multi-account with specific profile
poetry run vpc-flow-investigator \
  --instance-id i-0123456789abcdef0 \
  --profile production \
  --region us-west-2

# Local log file analysis
poetry run vpc-flow-investigator \
  --instance-id i-0123456789abcdef0 \
  --log-file /path/to/vpc-flow-logs.txt \
  --instance-ip 10.0.1.100 \
  --vpc-cidr "10.0."

# CIDR scanning mode
poetry run vpc-flow-investigator \
  --scan-cidrs log-group-name \
  --start-time 24h \
  --region us-east-1

# Debug mode with detailed output
poetry run vpc-flow-investigator \
  --instance-id i-0123456789abcdef0 \
  --debug
```

#### Time Format Examples

```bash
# Relative time formats
--start-time 1h    # 1 hour ago
--start-time 3d    # 3 days ago
--start-time 2w    # 2 weeks ago
--start-time 1M    # 1 month ago

# Absolute timestamps
--start-time 1640995200                    # Unix timestamp
--start-time "2024-01-01T00:00:00"         # ISO format
--start-time "2024-01-01 00:00:00"         # Human readable

# End time options
--end-time now                             # Current time
--end-time 1d                              # 1 day ago
--end-time "2024-01-02T00:00:00"           # Specific time
```

#### CIDR Analysis

The tool includes specialized CIDR analysis capabilities:

```bash
# Scan logs for connections to specific CIDR ranges
poetry run vpc-flow-investigator --scan-cidrs log-group-name

# CIDR connections analysis (part of regular analysis)
poetry run vpc-flow-investigator \
  --instance-id i-0123456789abcdef0 \
  --analysis cidr-connections
```

**CIDR Data Files**: Place JSON files with CIDR ranges in `src/vpc_flow_investigator/cidrs/` directory. The analyzer will automatically load and use them for connection analysis.

## 🔧 Configuration

### AWS Permissions

The tool requires the following AWS permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeVpcs",
                "logs:DescribeLogGroups",
                "logs:StartQuery",
                "logs:GetQueryResults"
            ],
            "Resource": "*"
        }
    ]
}
```

### Environment Variables

```bash
# AWS Configuration
export AWS_PROFILE=your-profile
export AWS_REGION=us-east-1

# Application Configuration
export VPC_FLOW_LOG_LEVEL=INFO
export VPC_FLOW_WEB_HOST=0.0.0.0
export VPC_FLOW_WEB_PORT=8000
```

### Configuration Files

Customize logging and other settings in `config/logging.yaml`:

```yaml
version: 1
formatters:
  default:
    format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
handlers:
  console:
    class: logging.StreamHandler
    level: INFO
    formatter: default
  file:
    class: logging.FileHandler
    filename: ~/.vpc-flow-logs/vpc-flow-investigator.log
    level: DEBUG
    formatter: default
root:
  level: INFO
  handlers: [console, file]
```

## 📊 Output Examples

### SSH Inbound Traffic Analysis

```shell
=== SSH Inbound Traffic Analysis ===
Source IP            Action     Organization          Count     
-----------------------------------------------------------------
203.0.113.1         ACCEPT     Example Corp          45        
198.51.100.2        REJECT     Malicious ISP         23        
192.0.2.3           ACCEPT     Internal              12        
```

### External Traffic Summary

```text
=== External Traffic Summary by Action ===
Action     Count     
--------------------
ACCEPT     1,234     
REJECT     567       
```

### Sensitive Ports Analysis

```text
=== Sensitive Ports - Inbound Traffic ===
Source IP            Port   Service         Action   Organization         Count   
---------------------------------------------------------------------------
203.0.113.1         3389   RDP             REJECT   Unknown ISP          15      
198.51.100.2        1433   SQL Server      ACCEPT   Database Corp        8       
```

### CIDR Analysis

```text
=== CIDR Analysis ===
Found 5 unique IPs matching CIDR ranges
Provider             IP Address       City            Region     Action   Count   
---------------------------------------------------------------------------------
aws                  52.95.110.1      us-east-1       Virginia   ACCEPT   45      
cloudflare           104.16.123.4     San Francisco   CA         ACCEPT   23      
google               8.8.8.8          Mountain View   CA         ACCEPT   12      
```

## 🏗️ Architecture

### Project Structure

```text
vpcflowlogs/
├── src/vpc_flow_investigator/     # Main application code
│   ├── analyzers.py               # Analysis logic
│   ├── aws_utils.py               # AWS integration
│   ├── cli.py                     # Command-line interface
│   ├── web.py                     # Web interface
│   ├── parser.py                  # Log parsing
│   ├── whois_utils.py             # WHOIS lookups
│   ├── cidr_analyzer.py           # CIDR analysis
│   ├── cidr_scanner.py            # CIDR scanning
│   ├── performance_utils.py       # Performance monitoring
│   ├── cidrs/                     # CIDR data files
│   ├── static/                    # Web assets
│   └── templates/                 # HTML templates
├── tests/                         # Test suite
├── docs/                          # Documentation
├── scripts/                       # Utility scripts
├── config/                        # Configuration files
├── examples/                      # Usage examples
└── pyproject.toml                 # Project configuration
```

### Key Components

- **Analyzers**: Modular analysis functions for different traffic patterns
- **AWS Utils**: Integration with EC2, VPC, and CloudWatch Logs APIs
- **Parser**: Efficient VPC Flow Log parsing and filtering
- **WHOIS Utils**: External IP organization lookup with caching
- **CIDR Analyzer**: Analysis of connections to specific CIDR ranges
- **Performance Utils**: Performance monitoring and optimization
- **Web Interface**: FastAPI-based modern web UI
- **CLI**: Comprehensive command-line interface

## 🧪 Testing

```bash
# Run all tests
make test

# Run specific test file
poetry run pytest tests/test_analyzers.py

# Run with coverage
poetry run pytest --cov=vpc_flow_investigator tests/

# Run integration tests
poetry run pytest tests/integration/
```

## 🤝 Contributing

We welcome contributions! 

### Development Workflow

1. Create a feature branch: `git checkout -b feature/amazing-feature`
2. Make your changes
3. Run tests: `make test`
4. Format code: `make format`
5. Run linting: `make lint`
6. Commit changes: `git commit -m 'Add amazing feature'`
7. Push to branch: `git push origin feature/amazing-feature`
8. Open a Pull Request

### Code Style

- We use [Black](https://black.readthedocs.io/) for code formatting
- [isort](https://pycqa.github.io/isort/) for import sorting
- [flake8](https://flake8.pycqa.org/) for linting
- [mypy](https://mypy.readthedocs.io/) for type checking

## 📚 Documentation

- [Project Structure](docs/PROJECT_STRUCTURE.md)
- [Implementation Summary](docs/IMPLEMENTATION_SUMMARY.md)
- [CIDR Analyzer](docs/CIDR_ANALYZER.md)
- [Optimization Report](docs/OPTIMIZATION_REPORT.md)

## 📝 Examples

- [CIDR Analysis Example](examples/cidr_analysis_example.py) - Demonstrates CIDR analysis functionality

## 🔍 Use Cases

### Security Investigations

- **Brute Force Detection**: Identify SSH/RDP brute force attempts
- **Data Exfiltration**: Monitor unusual outbound connections
- **Lateral Movement**: Track internal network traversal
- **Compliance Auditing**: Generate traffic reports for compliance

### Network Analysis

- **Bandwidth Monitoring**: Identify high-volume connections
- **Service Discovery**: Map network services and dependencies
- **Performance Troubleshooting**: Analyze connection patterns
- **Capacity Planning**: Understand traffic trends

### Incident Response

- **Timeline Reconstruction**: Analyze traffic during incidents
- **IOC Investigation**: Search for indicators of compromise
- **Forensic Analysis**: Detailed traffic pattern analysis
- **Threat Hunting**: Proactive security monitoring

## ⚡ Performance

- **Efficient Parsing**: Optimized log parsing with minimal memory usage
- **Batch Processing**: WHOIS lookups batched to reduce API calls
- **Caching**: Intelligent caching of AWS API responses and WHOIS data
- **Streaming**: Large log files processed in streaming fashion
- **Parallel Processing**: Multi-threaded analysis for large datasets

## 🐛 Troubleshooting

### Common Issues

#### No VPC Flow Logs Found

```bash
# Ensure VPC Flow Logs are enabled
aws ec2 describe-flow-logs --region us-east-1

# Check CloudWatch Logs groups
aws logs describe-log-groups --region us-east-1
```

#### Permission Denied

```bash
# Verify AWS credentials
aws sts get-caller-identity

# Check IAM permissions
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::123456789012:user/username --action-names ec2:DescribeInstances
```

#### Instance Not Found

```bash
# Verify instance exists and region
aws ec2 describe-instances --instance-ids i-0123456789abcdef0 --region us-east-1
```

### Debug Mode

Enable debug mode for detailed troubleshooting:

```bash
poetry run vpc-flow-investigator --instance-id i-0123456789abcdef0 --debug
```

## 📄 License

This project is licensed under the MIT License.

## 🙏 Acknowledgments

- AWS VPC Flow Logs documentation and best practices
- The Python community for excellent libraries
- Contributors and users who provide feedback and improvements

## 📞 Support

For support, please contact the development team or create an issue in the project repository.

---

## investiGATOR - Made with ❤️ for AWS security professionals and network engineers
