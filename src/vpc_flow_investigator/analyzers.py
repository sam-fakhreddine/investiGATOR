"""
Analysis modules for VPC Flow Log Investigator.
"""

from collections import defaultdict
from typing import Any, Dict, Set

from .config import SENSITIVE_PORTS
from .protocol_utils import get_protocol_name
from .whois_utils import get_whois_info, is_external_ip


def _batch_whois_lookup(ips: Set[str], vpc_cidr_prefix: str) -> Dict[str, str]:
    """Batch WHOIS lookup for external IPs to reduce API calls."""
    external_ips = {ip for ip in ips if is_external_ip(ip, vpc_cidr_prefix)}
    return {ip: get_whois_info(ip)["org"] for ip in external_ips}


def overall_traffic_summary(logs: list[dict[str, Any]], config: dict[str, Any]) -> None:
    """Analyze overall traffic summary by protocol and action."""
    results: dict[tuple[str, str], int] = defaultdict(int)

    for log in logs:
        key = (log.get("protocol", "unknown"), log.get("action", "unknown"))
        results[key] += 1

    # Sort and format results
    sorted_results = sorted(results.items(), key=lambda x: x[1], reverse=True)

    print("\n=== Overall Traffic Summary ===")
    print(f"{'Protocol':<10} {'Action':<10} {'Count':<10}")
    print("-" * 30)

    for (protocol, action), count in sorted_results[: config["limit"]]:
        protocol_name = get_protocol_name(protocol)
        print(f"{protocol_name:<10} {action:<10} {count:<10}")


def ssh_inbound_traffic(logs: list[dict[str, Any]], config: dict[str, Any]) -> None:
    """Analyze SSH inbound traffic."""
    results: dict[tuple[str, str], int] = defaultdict(int)
    source_ips = set()

    for log in logs:
        if log.get("dstaddr") in config["instance_ips"] and log.get("dstport") == "22":
            srcaddr = log.get("srcaddr", "unknown")
            key = (srcaddr, log.get("action", "unknown"))
            results[key] += 1
            source_ips.add(srcaddr)

    # Batch WHOIS lookup
    whois_cache = _batch_whois_lookup(source_ips, config["vpc_cidr_prefix"])

    # Sort and format results
    sorted_results = sorted(results.items(), key=lambda x: x[1], reverse=True)

    print("\n=== SSH Inbound Traffic Analysis ===")
    print(f"{'Source IP':<20} {'Action':<10} {'Organization':<25} {'Count':<10}")
    print("-" * 65)

    for (srcaddr, action), count in sorted_results[: config["limit"]]:
        org = (
            whois_cache.get(srcaddr, "Internal")
            if is_external_ip(srcaddr, config["vpc_cidr_prefix"])
            else "Internal"
        )
        print(f"{srcaddr:<20} {action:<10} {org:<25} {count:<10}")


def ssh_response_traffic(logs: list[dict[str, Any]], config: dict[str, Any]) -> None:
    """Analyze SSH response traffic."""
    results: dict[tuple[str, str], int] = defaultdict(int)

    for log in logs:
        if log.get("srcaddr") in config["instance_ips"] and log.get("srcport") == "22":
            key = (log.get("dstaddr", "unknown"), log.get("action", "unknown"))
            results[key] += 1

    # Sort and format results
    sorted_results = sorted(results.items(), key=lambda x: x[1], reverse=True)

    print("\n=== SSH Response Traffic Analysis ===")
    print(f"{'Destination IP':<20} {'Action':<10} {'Organization':<25} {'Count':<10}")
    print("-" * 65)

    for (dstaddr, action), count in sorted_results[: config["limit"]]:
        org = (
            get_whois_info(dstaddr)["org"]
            if is_external_ip(dstaddr, config["vpc_cidr_prefix"])
            else "Internal"
        )
        print(f"{dstaddr:<20} {action:<10} {org:<25} {count:<10}")


def ssh_outbound_connections(logs: list[dict[str, Any]], config: dict[str, Any]) -> None:
    """Analyze SSH outbound connections."""
    results: dict[tuple[str, str], int] = defaultdict(int)

    for log in logs:
        if log.get("srcaddr") in config["instance_ips"] and log.get("dstport") == "22":
            key = (log.get("dstaddr", "unknown"), log.get("action", "unknown"))
            results[key] += 1

    # Sort and format results
    sorted_results = sorted(results.items(), key=lambda x: x[1], reverse=True)

    print("\n=== SSH Outbound Connections ===")
    print(f"{'Destination IP':<20} {'Action':<10} {'Organization':<25} {'Count':<10}")
    print("-" * 65)

    for (dstaddr, action), count in sorted_results[: config["limit"]]:
        org = (
            get_whois_info(dstaddr)["org"]
            if is_external_ip(dstaddr, config["vpc_cidr_prefix"])
            else "Internal"
        )
        print(f"{dstaddr:<20} {action:<10} {org:<25} {count:<10}")


def external_inbound_traffic(logs: list[dict[str, Any]], config: dict[str, Any]) -> None:
    """Analyze external inbound traffic."""
    results: dict[tuple[str, str, str], int] = defaultdict(int)
    external_ips = set()

    for log in logs:
        if log.get("dstaddr") in config["instance_ips"] and not log.get(
            "srcaddr", ""
        ).startswith(config["vpc_cidr_prefix"]):
            srcaddr = log.get("srcaddr", "unknown")
            key = (
                srcaddr,
                log.get("action", "unknown"),
                log.get("pkt_src_aws_service", "unknown"),
            )
            results[key] += 1
            external_ips.add(srcaddr)

    # Batch WHOIS lookup
    whois_cache = {ip: get_whois_info(ip)["org"] for ip in external_ips}

    # Sort and format results
    sorted_results = sorted(results.items(), key=lambda x: x[1], reverse=True)

    print("\n=== External Inbound Traffic Analysis ===")
    print(
        f"{'Source IP':<20} {'Action':<10} {'AWS Service':<20} {'Organization':<25} {'Count':<10}"
    )
    print("-" * 85)

    for (srcaddr, action, service), count in sorted_results[: config["limit"]]:
        org = whois_cache.get(srcaddr, "Unknown")
        print(f"{srcaddr:<20} {action:<10} {service:<20} {org:<25} {count:<10}")


def external_outbound_traffic(logs: list[dict[str, Any]], config: dict[str, Any]) -> None:
    """Analyze external outbound traffic."""
    results: dict[tuple[str, str, str], int] = defaultdict(int)

    for log in logs:
        if log.get("srcaddr") in config["instance_ips"] and not log.get(
            "dstaddr", ""
        ).startswith(config["vpc_cidr_prefix"]):
            key = (
                log.get("dstaddr", "unknown"),
                log.get("action", "unknown"),
                log.get("pkt_dst_aws_service", "unknown"),
            )
            results[key] += 1

    # Sort and format results
    sorted_results = sorted(results.items(), key=lambda x: x[1], reverse=True)

    print("\n=== External Outbound Traffic Analysis ===")
    print(
        f"{'Destination IP':<20} {'Action':<10} {'AWS Service':<20} {'Organization':<25} {'Count':<10}"
    )
    print("-" * 85)

    for (dstaddr, action, service), count in sorted_results[: config["limit"]]:
        whois_info = get_whois_info(dstaddr)
        print(
            f"{dstaddr:<20} {action:<10} {service:<20} {whois_info['org']:<25} {count:<10}"
        )


def external_traffic_summary(logs: list[dict[str, Any]], config: dict[str, Any]) -> None:
    """Analyze external traffic summary by action."""
    results: dict[str, int] = defaultdict(int)

    for log in logs:
        # Check if traffic is external (inbound or outbound)
        is_external = (
            log.get("srcaddr") in config["instance_ips"]
            and not log.get("dstaddr", "").startswith(config["vpc_cidr_prefix"])
        ) or (
            log.get("dstaddr") in config["instance_ips"]
            and not log.get("srcaddr", "").startswith(config["vpc_cidr_prefix"])
        )

        if is_external:
            results[log.get("action", "unknown")] += 1

    # Sort and format results
    sorted_results = sorted(results.items(), key=lambda x: x[1], reverse=True)

    print("\n=== External Traffic Summary by Action ===")
    print(f"{'Action':<10} {'Count':<10}")
    print("-" * 20)

    for action, count in sorted_results:
        print(f"{action:<10} {count:<10}")


def top_external_traffic_flows(
    logs: list[dict[str, Any]], config: dict[str, Any]
) -> None:
    """Analyze top external traffic flows."""
    results: dict[tuple[str, str, str, str], int] = defaultdict(int)

    for log in logs:
        # Check if traffic is external (inbound or outbound)
        is_external = (
            log.get("srcaddr") in config["instance_ips"]
            and not log.get("dstaddr", "").startswith(config["vpc_cidr_prefix"])
        ) or (
            log.get("dstaddr") in config["instance_ips"]
            and not log.get("srcaddr", "").startswith(config["vpc_cidr_prefix"])
        )

        if is_external:
            key = (
                log.get("srcaddr", "unknown"),
                log.get("dstaddr", "unknown"),
                log.get("dstport", "unknown"),
                log.get("action", "unknown"),
            )
            results[key] += 1

    # Sort and format results
    sorted_results = sorted(results.items(), key=lambda x: x[1], reverse=True)

    print("\n=== Top External Traffic Flows ===")
    print(
        f"{'Source IP':<18} {'Destination IP':<18} {'Port':<6} {'Action':<8} {'External Org':<20} {'Count':<8}"
    )
    print("-" * 80)

    for (srcaddr, dstaddr, dstport, action), count in sorted_results[: config["limit"]]:
        # Get WHOIS for external IP
        external_ip = dstaddr if srcaddr in config["instance_ips"] else srcaddr
        whois_info = get_whois_info(external_ip)
        print(
            f"{srcaddr:<18} {dstaddr:<18} {dstport:<6} {action:<8} {whois_info['org']:<20} {count:<8}"
        )


def port_specific_traffic(
    logs: list[dict[str, Any]], config: dict[str, Any], port: int | None = None
) -> None:
    """Analyze traffic for a specific port."""
    results: dict[tuple[str, str, str, str, str], int] = defaultdict(int)

    for log in logs:
        # If port is specified, filter by that port
        if port and not (
            log.get("dstport") == str(port) or log.get("srcport") == str(port)
        ):
            continue

        key = (
            log.get("srcaddr", "unknown"),
            log.get("dstaddr", "unknown"),
            log.get("dstport", "unknown"),
            log.get("srcport", "unknown"),
            log.get("action", "unknown"),
        )
        results[key] += 1

    # Sort and format results
    sorted_results = sorted(results.items(), key=lambda x: x[1], reverse=True)

    port_str = f" (Port {port})" if port else ""
    print(f"\n=== Port-Specific Traffic Analysis{port_str} ===")
    print(
        f"{'Source IP':<18} {'Destination IP':<18} {'SPort':<6} {'DPort':<6} {'Action':<8} {'Ext Org':<15} {'Count':<8}"
    )
    print("-" * 85)

    for (srcaddr, dstaddr, dstport, srcport, action), count in sorted_results[
        : config["limit"]
    ]:
        # Determine external IP for WHOIS
        match (
            is_external_ip(srcaddr, config["vpc_cidr_prefix"]),
            is_external_ip(dstaddr, config["vpc_cidr_prefix"]),
        ):
            case (True, _):
                org = get_whois_info(srcaddr)["org"]
            case (_, True):
                org = get_whois_info(dstaddr)["org"]
            case _:
                org = "Internal"

        print(
            f"{srcaddr:<18} {dstaddr:<18} {srcport:<6} {dstport:<6} {action:<8} {org:<15} {count:<8}"
        )


def sensitive_ports_traffic(logs: list[dict[str, Any]], config: dict[str, Any]) -> None:
    """Analyze traffic on sensitive ports."""
    # Track inbound and outbound traffic separately
    inbound_results: dict[tuple[str, str, str, str], int] = defaultdict(int)
    outbound_results: dict[tuple[str, str, str, str], int] = defaultdict(int)

    for log in logs:
        try:
            dstport = int(log.get("dstport", "0"))
            srcport = int(log.get("srcport", "0"))
        except ValueError:
            continue

        # Check inbound traffic to sensitive ports
        if log.get("dstaddr") in config["instance_ips"] and dstport in SENSITIVE_PORTS:
            key = (
                log.get("srcaddr", "unknown"),
                str(dstport),
                SENSITIVE_PORTS[dstport],
                log.get("action", "unknown"),
            )
            inbound_results[key] += 1

        # Check outbound traffic from sensitive ports
        if log.get("srcaddr") in config["instance_ips"] and srcport in SENSITIVE_PORTS:
            key = (
                log.get("dstaddr", "unknown"),
                str(srcport),
                SENSITIVE_PORTS[srcport],
                log.get("action", "unknown"),
            )
            outbound_results[key] += 1

    # Sort and format inbound results
    sorted_inbound = sorted(inbound_results.items(), key=lambda x: x[1], reverse=True)

    print("\n=== Sensitive Ports - Inbound Traffic ===")
    print(
        f"{'Source IP':<18} {'Port':<6} {'Service':<15} {'Action':<8} {'Organization':<20} {'Count':<8}"
    )
    print("-" * 75)

    for (srcaddr, port, service, action), count in sorted_inbound[: config["limit"]]:
        org = (
            get_whois_info(srcaddr)["org"]
            if is_external_ip(srcaddr, config["vpc_cidr_prefix"])
            else "Internal"
        )
        print(f"{srcaddr:<18} {port:<6} {service:<15} {action:<8} {org:<20} {count:<8}")

    # Sort and format outbound results
    sorted_outbound = sorted(outbound_results.items(), key=lambda x: x[1], reverse=True)

    print("\n=== Sensitive Ports - Outbound Traffic ===")
    print(
        f"{'Destination IP':<18} {'Port':<6} {'Service':<15} {'Action':<8} {'Organization':<20} {'Count':<8}"
    )
    print("-" * 75)

    for (dstaddr, port, service, action), count in sorted_outbound[: config["limit"]]:
        org = (
            get_whois_info(dstaddr)["org"]
            if is_external_ip(dstaddr, config["vpc_cidr_prefix"])
            else "Internal"
        )
        print(f"{dstaddr:<18} {port:<6} {service:<15} {action:<8} {org:<20} {count:<8}")


def rejected_traffic(logs: list[dict[str, Any]], config: dict[str, Any]) -> None:
    """Analyze rejected traffic."""
    results: dict[tuple[str, str, str, str], int] = defaultdict(int)

    for log in logs:
        if log.get("action") == "REJECT":
            key = (
                log.get("srcaddr", "unknown"),
                log.get("dstaddr", "unknown"),
                log.get("dstport", "unknown"),
                log.get("protocol", "unknown"),
            )
            results[key] += 1

    # Sort and format results
    sorted_results = sorted(results.items(), key=lambda x: x[1], reverse=True)

    print("\n=== Rejected Traffic Analysis ===")
    print(
        f"{'Source IP':<18} {'Destination IP':<18} {'Port':<6} {'Proto':<6} {'External Org':<20} {'Count':<8}"
    )
    print("-" * 76)

    for (srcaddr, dstaddr, dstport, protocol), count in sorted_results[: config["limit"]]:
        # Determine which IP is external for WHOIS lookup
        match (
            is_external_ip(srcaddr, config["vpc_cidr_prefix"]),
            is_external_ip(dstaddr, config["vpc_cidr_prefix"]),
        ):
            case (True, _):
                org = get_whois_info(srcaddr)["org"]
            case (_, True):
                org = get_whois_info(dstaddr)["org"]
            case _:
                org = "Internal"

        protocol_name = get_protocol_name(protocol)
        print(
            f"{srcaddr:<18} {dstaddr:<18} {dstport:<6} {protocol_name:<6} {org:<20} {count:<8}"
        )
