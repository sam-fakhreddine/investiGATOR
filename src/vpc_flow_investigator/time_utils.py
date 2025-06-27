"""
Time utilities for parsing human-readable time formats.
"""

import re
import time
from datetime import datetime
from typing import Union


def parse_time_duration(duration_str: str) -> int:
    """
    Parse human-readable time duration to seconds.

    Supported formats:
    - 1m (1 minute)
    - 3d (3 days)
    - 4h (4 hours)
    - 3M (3 months, approximated as 30 days each)
    - 2W (2 weeks)
    - 5s (5 seconds)
    - 1y (1 year, approximated as 365 days)
    """
    if not duration_str:
        raise ValueError("Duration string cannot be empty")

    # Match number followed by unit
    if not (match := re.match(r"^(\d+)([smhdWMy])$", duration_str.strip())):
        raise ValueError(
            f"Invalid duration format: {duration_str}. Use format like '1m', '3d', '4h', '2W', '3M'"
        )

    value, unit = match.groups()
    value = int(value)

    # Convert to seconds using match-case
    match unit:
        case "s":
            return value
        case "m":
            return value * 60
        case "h":
            return value * 3600
        case "d":
            return value * 86400
        case "W":
            return value * 604800
        case "M":
            return value * 2592000
        case "y":
            return value * 31536000
        case _:
            raise ValueError(f"Unknown unit: {unit}")


def parse_time_input(time_input: Union[int, str]) -> int:
    """
    Parse time input which can be:
    - Unix timestamp (int)
    - Duration string like "1h" (relative to now)
    - ISO datetime string
    """
    match time_input:
        case int():
            return time_input
        case str():
            # Try duration format first
            try:
                duration_seconds = parse_time_duration(time_input)
                return int(time.time() - duration_seconds)
            except ValueError:
                pass

            # Try Unix timestamp as string
            if time_input.isdigit():
                return int(time_input)

            # Try ISO datetime
            try:
                dt = datetime.fromisoformat(time_input.replace("Z", "+00:00"))
                return int(dt.timestamp())
            except ValueError:
                pass
        case _:
            pass

    raise ValueError(f"Invalid time format: {time_input}")
