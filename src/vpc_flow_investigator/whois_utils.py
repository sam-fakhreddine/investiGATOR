"""
WHOIS utilities for IP address lookups.
"""

import ipaddress
import re
import socket
from functools import lru_cache
from typing import Optional, TypedDict


class WhoisInfo(TypedDict):
    org: str
    country: str
    description: str


class WhoisClient:
    """Handles raw WHOIS queries to WHOIS servers."""

    # Regional Internet Registry WHOIS servers
    RIR_SERVERS = {
        "arin": "whois.arin.net",  # North America
        "ripe": "whois.ripe.net",  # Europe, Middle East, Central Asia
        "apnic": "whois.apnic.net",  # Asia Pacific
        "lacnic": "whois.lacnic.net",  # Latin America
        "afrinic": "whois.afrinic.net",  # Africa
    }

    WHOIS_PORT = 43
    TIMEOUT = 10

    def query_whois(self, ip_address: str) -> Optional[str]:
        """Perform raw WHOIS query for IP address."""
        try:
            # Try ARIN first (most common for US IPs)
            for server in ["whois.arin.net", "whois.ripe.net", "whois.apnic.net"]:
                if result := self._query_server(server, ip_address):
                    return result
            return None
        except Exception:
            return None

    def _query_server(self, server: str, ip_address: str) -> Optional[str]:
        """Query specific WHOIS server."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.TIMEOUT)
                sock.connect((server, self.WHOIS_PORT))
                sock.send(f"{ip_address}\r\n".encode())

                response = b""
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data

                return response.decode("utf-8", errors="ignore")
        except Exception:
            return None


class WhoisParser:
    """Parses WHOIS response data."""

    # Common patterns for extracting organization info
    ORG_PATTERNS = [
        r"(?:OrgName|org-name|organisation|Organization):\s*(.+)",
        r"(?:NetName|netname):\s*(.+)",
        r"(?:descr|Description):\s*(.+)",
    ]

    COUNTRY_PATTERNS = [
        r"(?:Country|country):\s*([A-Z]{2})",
        r"(?:CountryCode|country-code):\s*([A-Z]{2})",
    ]

    def parse_whois_response(self, response: str) -> WhoisInfo:
        """Parse WHOIS response into structured data."""
        if not response:
            return WhoisInfo(org="Unknown", country="-", description="No WHOIS data")

        org = self._extract_organization(response)
        country = self._extract_country(response)
        description = self._extract_description(response)

        return WhoisInfo(
            org=org or "Unknown",
            country=country or "-",
            description=description or "Unknown",
        )

    def _extract_organization(self, response: str) -> Optional[str]:
        """Extract organization from WHOIS response."""
        for pattern in self.ORG_PATTERNS:
            if match := re.search(pattern, response, re.IGNORECASE | re.MULTILINE):
                org = match.group(1).strip()
                if org and org != "-":
                    return org
        return None

    def _extract_country(self, response: str) -> Optional[str]:
        """Extract country code from WHOIS response."""
        for pattern in self.COUNTRY_PATTERNS:
            if match := re.search(pattern, response, re.IGNORECASE | re.MULTILINE):
                return match.group(1).strip()
        return None

    def _extract_description(self, response: str) -> Optional[str]:
        """Extract description from WHOIS response."""
        # Look for description or remarks
        desc_patterns = [
            r"(?:remarks|Remarks):\s*(.+)",
            r"(?:Comment|comment):\s*(.+)",
        ]

        for pattern in desc_patterns:
            if match := re.search(pattern, response, re.IGNORECASE | re.MULTILINE):
                desc = match.group(1).strip()
                if desc and desc != "-":
                    return desc
        return None


class ReverseDNSLookup:
    """Handles reverse DNS lookups as fallback."""

    CLOUD_PROVIDERS = {
        "amazonaws.com": "Amazon AWS",
        "googleusercontent.com": "Google Cloud",
        "compute.amazonaws.com": "Amazon EC2",
        "azure.com": "Microsoft Azure",
        "cloudflare.com": "Cloudflare",
        "akamai.com": "Akamai",
        "fastly.com": "Fastly",
    }

    def get_hostname_info(self, ip_address: str) -> WhoisInfo:
        """Get organization info from reverse DNS."""
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            org = self._extract_org_from_hostname(hostname)
            return WhoisInfo(
                org=org,
                country="-",
                description=hostname if hostname != "-" else "Unknown",
            )
        except (socket.herror, socket.gaierror):
            return WhoisInfo(
                org="Unknown", country="-", description="DNS lookup failed"
            )

    def _extract_org_from_hostname(self, hostname: str) -> str:
        """Extract organization from hostname."""
        if hostname == "-":
            return "Unknown"

        hostname_lower = hostname.lower()
        for domain, org in self.CLOUD_PROVIDERS.items():
            if domain in hostname_lower:
                return org

        # Extract domain
        if (parts := hostname.split(".")) and len(parts) >= 2:
            return f"{parts[-2]}.{parts[-1]}"

        return hostname


@lru_cache(maxsize=1000)
def get_whois_info(ip_address: str) -> WhoisInfo:
    """
    Get comprehensive WHOIS information for an IP address.
    Uses true WHOIS lookup with reverse DNS fallback.
    """
    try:
        # Skip private/local IPs
        ip = ipaddress.ip_address(ip_address)
        if ip.is_private or ip.is_loopback or ip.is_multicast:
            return WhoisInfo(org="Private/Local", country="-", description="Private IP")

        # Try true WHOIS lookup first
        whois_client = WhoisClient()
        whois_parser = WhoisParser()

        if whois_response := whois_client.query_whois(ip_address):
            whois_info = whois_parser.parse_whois_response(whois_response)
            # If we got good WHOIS data, return it
            if whois_info["org"] != "Unknown":
                return whois_info

        # Fallback to reverse DNS lookup
        dns_lookup = ReverseDNSLookup()
        return dns_lookup.get_hostname_info(ip_address)

    except Exception:
        return WhoisInfo(org="Unknown", country="-", description="Lookup failed")


def is_external_ip(ip_address: str, vpc_cidr_prefix: str) -> bool:
    """Check if IP is external (not in VPC)."""
    try:
        return not ip_address.startswith(vpc_cidr_prefix)
    except Exception:
        return False


# Legacy function for backward compatibility
def extract_org_from_hostname(hostname: str) -> str:
    """Extract organization from hostname."""
    dns_lookup = ReverseDNSLookup()
    return dns_lookup._extract_org_from_hostname(hostname)
