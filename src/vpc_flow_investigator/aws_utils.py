"""
AWS utilities for VPC Flow Log Investigator.
"""

import os
import tempfile
import time
from typing import Any, Optional

import boto3
from botocore.waiter import WaiterModel, create_waiter_with_client


class AWSClientFactory:
    """Factory for creating AWS clients with consistent configuration."""

    @staticmethod
    def create_client(
        service: str, region: Optional[str] = None, profile: Optional[str] = None
    ) -> Any:
        """Create a boto3 client with optional profile and region."""
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        return session.client(service, region_name=region)


class RegionResolver:
    """Handles AWS region resolution logic."""

    DEFAULT_REGION = "us-east-1"

    @classmethod
    def resolve_region(cls, region: Optional[str] = None) -> str:
        """Resolve AWS region from parameter, environment, or default."""
        if region:
            return region

        resolved_region = (
            os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
            or cls.DEFAULT_REGION
        )

        if resolved_region == cls.DEFAULT_REGION:
            print(f"No region specified, using default: {resolved_region}")

        return resolved_region


class EC2InstanceInfoExtractor:
    """Extracts and processes EC2 instance information."""

    def __init__(self, ec2_client: Any):
        self.ec2_client = ec2_client

    def get_instance_info(
        self, instance_id: str, region: str
    ) -> Optional[dict[str, Any]]:
        """Get comprehensive instance information from AWS EC2."""
        try:
            response = self.ec2_client.describe_instances(InstanceIds=[instance_id])

            if (
                not response["Reservations"]
                or not response["Reservations"][0]["Instances"]
            ):
                raise ValueError(f"Instance {instance_id} not found in region {region}")

            instance = response["Reservations"][0]["Instances"][0]
            vpc_id = instance.get("VpcId", "")

            return {
                "private_ips": self._extract_all_ips(instance),
                "primary_ip": instance.get("PrivateIpAddress"),
                "vpc_id": vpc_id,
                "vpc_cidr_prefix": self._get_vpc_cidr_prefix(vpc_id),
                "region": region,
            }
        except Exception as e:
            print(f"Error getting instance info: {e}")
            return None

    def _extract_all_ips(self, instance: dict[str, Any]) -> list[str]:
        """Extract all IP addresses from instance network interfaces."""
        ip_addresses = []

        # Add primary private IP
        if primary_ip := instance.get("PrivateIpAddress"):
            ip_addresses.append(primary_ip)

        # Add IPs from all network interfaces
        for network_interface in instance.get("NetworkInterfaces", []):
            self._add_interface_ips(network_interface, ip_addresses)

        return ip_addresses

    def _add_interface_ips(
        self, network_interface: dict[str, Any], ip_addresses: list[str]
    ) -> None:
        """Add IPs from a network interface to the list."""
        # Add primary IP from interface if not already added
        if (
            interface_primary_ip := network_interface.get("PrivateIpAddress")
        ) and interface_primary_ip not in ip_addresses:
            ip_addresses.append(interface_primary_ip)

        # Add all secondary private IPs
        for private_ip_info in network_interface.get("PrivateIpAddresses", []):
            if (
                private_ip := private_ip_info.get("PrivateIpAddress")
            ) and private_ip not in ip_addresses:
                ip_addresses.append(private_ip)

    def _get_vpc_cidr_prefix(self, vpc_id: str) -> str:
        """Get VPC CIDR prefix for the given VPC ID."""
        if not vpc_id:
            return "10.0."

        try:
            vpc_response = self.ec2_client.describe_vpcs(VpcIds=[vpc_id])
            vpc_cidr = (
                vpc_response["Vpcs"][0]["CidrBlock"]
                if vpc_response["Vpcs"]
                else "10.0.0.0/16"
            )
            parts = vpc_cidr.split(".")
            return ".".join(parts[:2]) + "."
        except Exception:
            return "10.0."


class CloudWatchLogsQueryWaiter:
    """Handles waiting for CloudWatch Logs query completion."""

    WAITER_CONFIG = {
        "version": 2,
        "waiters": {
            "QueryComplete": {
                "operation": "GetQueryResults",
                "delay": 2,
                "maxAttempts": 150,
                "acceptors": [
                    {
                        "matcher": "path",
                        "expected": "Complete",
                        "argument": "status",
                        "state": "success",
                    },
                    {
                        "matcher": "path",
                        "expected": "Failed",
                        "argument": "status",
                        "state": "failure",
                    },
                    {
                        "matcher": "path",
                        "expected": "Cancelled",
                        "argument": "status",
                        "state": "failure",
                    },
                ],
            }
        },
    }

    def __init__(self, logs_client: Any):
        self.logs_client = logs_client

    def wait_for_query_completion(self, query_id: str) -> dict[str, Any]:
        """Wait for CloudWatch Logs query to complete using custom waiter."""
        try:
            print("Waiting for query to complete...")
            waiter_model = WaiterModel(self.WAITER_CONFIG)
            waiter = create_waiter_with_client(
                "QueryComplete", waiter_model, self.logs_client
            )
            waiter.wait(queryId=query_id)
            return self.logs_client.get_query_results(queryId=query_id)  # type: ignore[no-any-return]
        except Exception as waiter_error:
            print(f"Custom waiter failed, using manual polling: {waiter_error}")
            return self._manual_polling(query_id)

    def _manual_polling(self, query_id: str) -> dict[str, Any]:
        """Fallback manual polling for query completion."""
        status = "Running"
        max_attempts = 150
        attempt = 0

        while status == "Running" and attempt < max_attempts:
            time.sleep(2)
            response = self.logs_client.get_query_results(queryId=query_id)
            status = response["status"]
            attempt += 1

            if attempt % 15 == 0:  # Progress update every 30 seconds
                print(f"Query still running... ({attempt * 2}s elapsed)")

        return response  # type: ignore[no-any-return]


class VPCFlowLogDownloader:
    """Handles VPC Flow Log downloading from CloudWatch Logs."""

    def __init__(self, logs_client: Any):
        self.logs_client = logs_client
        self.waiter = CloudWatchLogsQueryWaiter(logs_client)

    def download_logs(
        self,
        log_group: str,
        instance_id: Optional[str],
        start_time: int,
        end_time: int,
        debug: bool = False,
    ) -> Optional[str]:
        """Download VPC Flow Logs with pagination for comprehensive analysis."""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".log")
        total_results = 0

        try:
            if debug:
                instance_desc = instance_id or "all instances"
                print(f"[DEBUG] Starting comprehensive download for {instance_desc}")
                print(f"[DEBUG] Log group: {log_group}")
                print(f"[DEBUG] Time range: {start_time} to {end_time}")
                print(f"[DEBUG] Temp file: {temp_file.name}")
            else:
                instance_desc = instance_id or "all instances"
                print(
                    f"Downloading VPC Flow Logs for {instance_desc} (comprehensive analysis)..."
                )

            # Use pagination to get all results
            current_start = start_time
            time_chunk = min(
                3600, end_time - start_time
            )  # 1 hour chunks or full range if smaller

            with open(temp_file.name, "w") as f:
                while current_start < end_time:
                    current_end = min(current_start + time_chunk, end_time)

                    if debug:
                        print(
                            f"[DEBUG] Querying chunk: {current_start} to {current_end}"
                        )

                    query_id = self._start_query(
                        log_group, instance_id, current_start, current_end, debug
                    )
                    response = self.waiter.wait_for_query_completion(query_id)

                    if response["status"] == "Complete":
                        results = response.get("results", [])
                        chunk_count = self._write_chunk_to_file(results, f, debug)
                        total_results += chunk_count

                        if debug:
                            print(
                                f"[DEBUG] Chunk results: {chunk_count}, Total so far: {total_results}"
                            )

                        # If we got less than 10k results, we can increase chunk size
                        if len(results) < 9000:
                            time_chunk = min(
                                time_chunk * 2, 86400
                            )  # Max 24 hour chunks
                    else:
                        if debug:
                            print(
                                f"[DEBUG] Query failed for chunk: {response['status']}"
                            )
                        # Continue with next chunk even if one fails

                    current_start = current_end

            if debug:
                print(f"[DEBUG] Total results downloaded: {total_results}")
            else:
                print(f"Downloaded {total_results} log entries to {temp_file.name}")

            return temp_file.name if total_results > 0 else None

        except Exception as e:
            print(f"Error downloading VPC flow logs: {e}")
            if debug:
                import traceback

                print(f"[DEBUG] Full traceback: {traceback.format_exc()}")
            return None

    def _start_query(
        self,
        log_group: str,
        instance_id: Optional[str],
        start_time: int,
        end_time: int,
        debug: bool = False,
    ) -> str:
        """Start CloudWatch Logs query and return query ID."""
        if instance_id:
            query = (
                f"fields @timestamp, @message | filter @message like '{instance_id}'"
            )
        else:
            query = "fields @timestamp, @message"

        if debug:
            print(f"[DEBUG] CloudWatch query: {query}")
            print(f"[DEBUG] Start time (ms): {int(start_time * 1000)}")
            print(f"[DEBUG] End time (ms): {int(end_time * 1000)}")

        response = self.logs_client.start_query(
            logGroupName=log_group,
            startTime=int(start_time * 1000),
            endTime=int(end_time * 1000),
            queryString=query,
            limit=10000,  # CloudWatch Logs maximum per query
        )

        return response["queryId"]  # type: ignore[no-any-return]

    def _write_results_to_file(
        self, results: list[list[dict[str, Any]]], file_path: str, debug: bool = False
    ) -> str:
        """Write query results to temporary file."""
        written_count = 0
        with open(file_path, "w") as f:
            written_count = self._write_chunk_to_file(results, f, debug)

        if debug:
            print(f"[DEBUG] Wrote {written_count} log entries to {file_path}")
        else:
            print(f"Downloaded {len(results)} log entries to {file_path}")
        return file_path

    def _write_chunk_to_file(
        self, results: list[list[dict[str, Any]]], file_handle: Any, debug: bool = False
    ) -> int:
        """Write a chunk of results to file handle."""
        written_count = 0
        for result in results:
            if message := next(
                (
                    field["value"]
                    for field in result
                    if field.get("field") == "@message"
                ),
                None,
            ):
                file_handle.write(f"{message}\n")
                written_count += 1
                if debug and written_count <= 3:
                    message_str = str(message) if message is not None else ""
                    print(
                        f"[DEBUG] Sample log line {written_count}: {message_str[:100]}..."
                    )

        return written_count


class VPCFlowLogGroupFinder:
    """Finds VPC Flow Log groups in CloudWatch Logs."""

    FLOW_LOG_PATTERNS = ["vpc-flow", "flowlog", "flow-log"]

    def __init__(self, logs_client: Any):
        self.logs_client = logs_client

    def find_log_group(self, vpc_id: str) -> Optional[str]:
        """Find VPC Flow Log group for the given VPC ID."""
        try:
            paginator = self.logs_client.get_paginator("describe_log_groups")

            for page in paginator.paginate():
                for log_group in page["logGroups"]:
                    log_group_name = log_group["logGroupName"]
                    if self._matches_flow_log_pattern(log_group_name, vpc_id):
                        return log_group_name

            return None
        except Exception as e:
            print(f"Error finding VPC flow log group: {e}")
            return None

    def _matches_flow_log_pattern(self, log_group_name: str, vpc_id: str) -> bool:
        """Check if log group name matches VPC flow log patterns."""
        log_group_lower = log_group_name.lower()
        patterns = [vpc_id] + self.FLOW_LOG_PATTERNS
        return any(pattern in log_group_lower for pattern in patterns)


# Public API functions
def get_instance_info(
    instance_id: str, region: Optional[str] = None, profile: Optional[str] = None
) -> Optional[dict[str, Any]]:
    """Get instance information from AWS EC2."""
    resolved_region = RegionResolver.resolve_region(region)
    ec2_client = AWSClientFactory.create_client("ec2", resolved_region, profile)
    extractor = EC2InstanceInfoExtractor(ec2_client)
    return extractor.get_instance_info(instance_id, resolved_region)


def find_vpc_flow_log_group(
    vpc_id: str, region: Optional[str] = None, profile: Optional[str] = None
) -> Optional[str]:
    """Find VPC Flow Log group in CloudWatch Logs."""
    logs_client = AWSClientFactory.create_client("logs", region, profile)
    finder = VPCFlowLogGroupFinder(logs_client)
    return finder.find_log_group(vpc_id)  # type: ignore[no-any-return]


def download_vpc_flow_logs(
    log_group: str,
    instance_id: Optional[str],
    start_time: int,
    end_time: int,
    region: Optional[str] = None,
    profile: Optional[str] = None,
    debug: bool = False,
) -> Optional[str]:
    """Download VPC Flow Logs from CloudWatch Logs."""
    logs_client = AWSClientFactory.create_client("logs", region, profile)
    downloader = VPCFlowLogDownloader(logs_client)
    return downloader.download_logs(log_group, instance_id, start_time, end_time, debug)
