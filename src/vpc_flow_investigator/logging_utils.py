"""Logging utilities with UUID tracking."""

import json
import logging
import logging.handlers
import uuid

from pathlib import Path
from typing import Any, Dict, Optional


def setup_logger(name: str) -> logging.Logger:
    """Setup logger with rotating file and console handlers."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    # Create logs directory
    log_dir = Path.home() / ".vpc-flow-logs"
    log_dir.mkdir(exist_ok=True)

    # Rotating file handler (30MB max, 5 backups)
    file_handler = logging.handlers.RotatingFileHandler(
        log_dir / "vpc-flow-investigator.log",
        maxBytes=30 * 1024 * 1024,  # 30MB
        backupCount=5,
    )
    file_handler.setLevel(logging.INFO)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def generate_query_id() -> str:
    """Generate unique query ID."""
    return str(uuid.uuid4())[:8]


def log_query_start(logger: logging.Logger, query_id: str, **kwargs: Any) -> None:
    """Log query start with parameters."""
    logger.info(f"Query {query_id} started - {kwargs}")


def log_query_end(
    logger: logging.Logger,
    query_id: str,
    success: bool,
    result_data: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> None:
    """Log query completion with optional result data."""
    status = "SUCCESS" if success else "FAILED"
    log_data = {"query_id": query_id, "status": status, **kwargs}

    if result_data:
        log_data["result_data"] = result_data
        store_query_result(query_id, result_data)

    logger.info(f"Query {query_id} {status} - {json.dumps(log_data, default=str)}")


def store_query_result(query_id: str, result_data: Dict[str, Any]) -> None:
    """Store query result data for later retrieval."""
    log_dir = Path.home() / ".vpc-flow-logs" / "results"
    log_dir.mkdir(exist_ok=True)

    result_file = log_dir / f"{query_id}.json"
    with open(result_file, "w") as f:
        json.dump(result_data, f, indent=2, default=str)


def get_query_result(query_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve stored query result by ID."""
    log_dir = Path.home() / ".vpc-flow-logs" / "results"
    result_file = log_dir / f"{query_id}.json"

    if result_file.exists():
        with open(result_file, "r") as f:
            return json.load(f)  # type: ignore[no-any-return]
    return None
