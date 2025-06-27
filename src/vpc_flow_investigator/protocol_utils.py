"""Protocol number to name mapping utilities."""

PROTOCOL_MAP = {
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


def get_protocol_name(protocol_number: str) -> str:
    """Convert protocol number to human-readable name."""
    return PROTOCOL_MAP.get(str(protocol_number), f"Protocol-{protocol_number}")
