"""
Performance optimization utilities for VPC Flow Log Investigator.
"""

import time
from collections import defaultdict
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set

from .whois_utils import get_whois_info, is_external_ip


def timing_decorator(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator to measure function execution time."""

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"[PERF] {func.__name__} took {end_time - start_time:.2f} seconds")
        return result

    return wrapper


class BatchWhoisLookup:
    """Optimized batch WHOIS lookup utility."""

    def __init__(self, vpc_cidr_prefix: str):
        self.vpc_cidr_prefix = vpc_cidr_prefix
        self._cache: Dict[str, str] = {}

    def add_ips(self, ips: Set[str]) -> None:
        """Add IPs to the lookup queue."""
        external_ips = {ip for ip in ips if is_external_ip(ip, self.vpc_cidr_prefix)}
        new_ips = external_ips - set(self._cache.keys())

        # Batch lookup for new IPs only
        for ip in new_ips:
            self._cache[ip] = get_whois_info(ip)["org"]

    def get_org(self, ip: str) -> str:
        """Get organization for IP address."""
        if is_external_ip(ip, self.vpc_cidr_prefix):
            return self._cache.get(ip, "Unknown")
        return "Internal"


class LogProcessor:
    """Optimized log processing utilities."""

    @staticmethod
    def extract_unique_ips(
        logs: List[Dict[str, Any]], fields: Optional[List[str]] = None
    ) -> Set[str]:
        """Extract unique IP addresses from logs."""
        if fields is None:
            fields = ["srcaddr", "dstaddr"]

        ips = set()
        for log in logs:
            for field in fields:
                if ip := log.get(field):
                    ips.add(ip)
        return ips

    @staticmethod
    def filter_by_criteria(
        logs: List[Dict[str, Any]], criteria: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Filter logs by multiple criteria efficiently."""
        filtered = []
        for log in logs:
            if all(log.get(key) == value for key, value in criteria.items()):
                filtered.append(log)
        return filtered


class MemoryOptimizer:
    """Memory usage optimization utilities."""

    @staticmethod
    def process_in_chunks(data: List[Any], chunk_size: int = 1000) -> Any:
        """Process data in chunks to reduce memory usage."""
        for i in range(0, len(data), chunk_size):
            yield data[i : i + chunk_size]

    @staticmethod
    def get_top_results(
        results: Dict[Any, int], limit: int = 20
    ) -> List[tuple[Any, int]]:
        """Get top results without sorting entire dataset."""
        if len(results) <= limit:
            return sorted(results.items(), key=lambda x: x[1], reverse=True)

        # Use heap for large datasets
        import heapq

        return heapq.nlargest(limit, results.items(), key=lambda x: x[1])


class AnalysisOptimizer:
    """Optimized analysis patterns."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.whois_lookup = BatchWhoisLookup(config["vpc_cidr_prefix"])

    def analyze_with_whois(
        self, logs: List[Dict[str, Any]], analysis_func: Callable[..., Any]
    ) -> Any:
        """Run analysis with optimized WHOIS lookups."""
        # Pre-collect all IPs
        all_ips = LogProcessor.extract_unique_ips(logs)
        self.whois_lookup.add_ips(all_ips)

        # Run analysis with cached lookups
        return analysis_func(logs, self.config, self.whois_lookup)


# Performance monitoring utilities
class PerformanceMonitor:
    """Monitor and report performance metrics."""

    def __init__(self):
        self.metrics: Dict[str, List[float]] = defaultdict(list)

    def record_time(self, operation: str, duration: float) -> None:
        """Record operation duration."""
        self.metrics[operation].append(duration)

    def get_stats(self, operation: str) -> Dict[str, float]:
        """Get statistics for an operation."""
        times = self.metrics.get(operation, [])
        if not times:
            return {}

        return {
            "count": len(times),
            "total": sum(times),
            "average": sum(times) / len(times),
            "min": min(times),
            "max": max(times),
        }

    def print_report(self) -> None:
        """Print performance report."""
        print("\n=== Performance Report ===")
        for operation, times in self.metrics.items():
            stats = self.get_stats(operation)
            print(
                f"{operation}: {stats['count']} calls, "
                f"avg {stats['average']:.2f}s, "
                f"total {stats['total']:.2f}s"
            )


# Global performance monitor instance
perf_monitor = PerformanceMonitor()
