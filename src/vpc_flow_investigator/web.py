"""
Web interface for VPC Flow Log Investigator.
"""

import os
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import boto3
import uvicorn
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .aws_utils import download_vpc_flow_logs, find_vpc_flow_log_group, get_instance_info
from .config import DEFAULT_CONFIG
from .logging_utils import (
    generate_query_id,
    get_query_result,
    log_query_end,
    log_query_start,
    setup_logger,
)
from .parser import filter_logs, read_log_file
from .protocol_utils import get_protocol_name
from .time_utils import parse_time_input

# Setup logger
logger = setup_logger("vpc-flow-web")


class WebApplicationFactory:
    """Factory for creating and configuring the FastAPI application."""

    @staticmethod
    def create_app() -> FastAPI:
        """Create and configure FastAPI application."""
        app = FastAPI(title="VPC Flow Log Investigator", version="1.0.0")

        # Setup templates and static files
        templates_dir = Path(__file__).parent / "templates"
        static_dir = Path(__file__).parent / "static"
        templates_dir.mkdir(exist_ok=True)
        static_dir.mkdir(exist_ok=True)

        templates = Jinja2Templates(directory=str(templates_dir))
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

        # Register routes
        RouteRegistrar.register_routes(app, templates)

        return app


class RouteRegistrar:
    """Handles registration of web routes."""

    @staticmethod
    def register_routes(app: FastAPI, templates: Jinja2Templates) -> None:
        """Register all application routes."""

        @app.get("/", response_class=HTMLResponse)
        async def home(request: Request) -> Any:
            """Serve the main web interface."""
            profiles = AWSProfileService.get_profiles()
            return templates.TemplateResponse(
                request, "index.html", {"profiles": profiles}
            )

        @app.get("/api/profiles")
        async def get_profiles() -> Any:
            """Get available AWS profiles."""
            return {"profiles": AWSProfileService.get_profiles()}

        @app.get("/api/test")
        async def test_endpoint() -> Any:
            """Test endpoint to verify API is working."""
            return {"status": "ok", "message": "API is working"}

        @app.get("/api/query/{query_id}")
        async def get_query_result_endpoint(query_id: str) -> Any:
            """Retrieve stored query result by ID."""
            result = get_query_result(query_id)
            if result:
                return JSONResponse(content=result)
            else:
                raise HTTPException(status_code=404, detail="Query result not found")

        @app.post("/api/analyze")
        async def analyze_logs(
            profile: str = Form(...),
            instance_id: str = Form(...),
            region: Optional[str] = Form(None),
            start_time: str = Form("24h"),
            end_time: str = Form("now"),
            analysis: str = Form("all"),
            port: Optional[int] = Form(None),
        ) -> Any:
            """Run VPC Flow Log analysis."""
            query_id = generate_query_id()
            log_query_start(
                logger,
                query_id,
                instance_id=instance_id,
                analysis=analysis,
                profile=profile,
                region=region,
            )

            request_data = AnalysisRequest(
                profile=profile,
                instance_id=instance_id,
                region=region,
                start_time=start_time,
                end_time=end_time,
                analysis=analysis,
                port=port,
                query_id=query_id,
            )

            service = AnalysisService()
            return await service.run_analysis(request_data)

        @app.post("/api/scan-cidrs")
        async def scan_cidrs(
            profile: str = Form(...),
            log_group: str = Form(...),
            region: Optional[str] = Form(None),
            start_time: str = Form("24h"),
            end_time: str = Form("now"),
            cidr_file: Optional[UploadFile] = File(None),
        ) -> Any:
            """Run CIDR scanning."""
            import json
            import time

            from .aws_utils import download_vpc_flow_logs
            from .cidr_analyzer import CIDRAnalyzer
            from .parser import read_log_file
            from .time_utils import parse_time_input

            try:
                end_time_parsed = (
                    int(time.time()) if end_time == "now" else parse_time_input(end_time)
                )
                start_time_parsed = parse_time_input(start_time)
                log_group = log_group.strip()

                # Handle uploaded CIDR file
                analyzer = CIDRAnalyzer()
                if cidr_file:
                    try:
                        content = await cidr_file.read()
                        cidr_data = json.loads(content.decode("utf-8"))
                        analyzer.cidr_data = {"uploaded": cidr_data}
                    except json.JSONDecodeError:
                        return JSONResponse(
                            content={"status": "error", "message": "Invalid JSON file"},
                            status_code=400,
                        )

                # Download logs
                log_file = download_vpc_flow_logs(
                    log_group,
                    None,
                    start_time_parsed,
                    end_time_parsed,
                    region,
                    profile,
                    False,
                )
                if not log_file:
                    return JSONResponse(
                        content={
                            "status": "error",
                            "message": "Failed to download logs",
                        },
                        status_code=500,
                    )

                # Analyze logs
                logs = list(read_log_file(log_file))
                config = {"limit": 50}
                analyzer.analyze_cidr_connections(logs, config)

                return JSONResponse(
                    content={"status": "success", "message": "CIDR scan completed"}
                )
            except Exception as e:
                return JSONResponse(
                    content={"status": "error", "message": str(e)}, status_code=500
                )


class AnalysisRequest:
    """Data class for analysis request parameters."""

    def __init__(
        self,
        profile: str,
        instance_id: str,
        region: Optional[str],
        start_time: str,
        end_time: str,
        analysis: str,
        port: Optional[int],
        query_id: Optional[str] = None,
    ):
        self.profile = profile
        self.instance_id = instance_id
        self.region = region
        self.start_time = start_time
        self.end_time = end_time

        self.analysis = analysis
        self.port = port
        self.query_id = query_id or generate_query_id()


class ConfigurationBuilder:
    """Builds analysis configuration from request parameters."""

    @staticmethod
    def build_config(request: AnalysisRequest) -> Dict[str, Any]:
        """Build configuration dictionary from request."""
        config = DEFAULT_CONFIG.copy()
        config.update(
            {
                "instance_id": request.instance_id,
                "profile": request.profile,
                "region": request.region,
                "analysis": request.analysis,
                "port": request.port,
            }
        )

        # Parse time inputs - handle Unix timestamps from web interface
        try:
            # Try to parse as Unix timestamp first
            config["start_time"] = int(request.start_time)
        except ValueError:
            # Fall back to time parsing for CLI compatibility
            config["start_time"] = parse_time_input(request.start_time)

        try:
            # Try to parse as Unix timestamp first
            if request.end_time == "now":
                import time

                config["end_time"] = int(time.time())
            else:
                config["end_time"] = int(request.end_time)
        except ValueError:
            # Fall back to time parsing for CLI compatibility
            config["end_time"] = parse_time_input(request.end_time)

        return config


class InstanceInfoService:
    """Handles EC2 instance information retrieval."""

    @staticmethod
    def get_and_validate_instance_info(
        instance_id: str, region: Optional[str], profile: str
    ) -> Dict[str, Any]:
        """Get instance information and validate it exists."""
        instance_info = get_instance_info(instance_id, region, profile)
        if not instance_info:
            raise HTTPException(
                status_code=400, detail="Failed to get instance information"
            )
        return instance_info


class LogGroupService:
    """Handles VPC Flow Log group discovery."""

    @staticmethod
    def find_and_validate_log_group(vpc_id: str, region: str, profile: str) -> str:
        """Find log group and validate it exists."""
        log_group = find_vpc_flow_log_group(vpc_id, region, profile)
        if not log_group:
            raise HTTPException(
                status_code=400, detail="Could not find VPC Flow Log group"
            )
        return log_group


class LogDownloadService:
    """Handles VPC Flow Log downloading."""

    @staticmethod
    def download_and_validate_logs(config: Dict[str, Any]) -> str:
        """Download logs and validate success."""
        log_file = download_vpc_flow_logs(
            config["log_group"],
            config["instance_id"],
            config["start_time"],
            config["end_time"],
            config["region"],
            config["profile"],
            False,  # debug=False for web
        )

        if not log_file:
            raise HTTPException(
                status_code=500, detail="Failed to download VPC Flow Logs"
            )

        return log_file


class AnalysisResultProcessor:
    """Processes analysis results for web display."""

    @staticmethod
    def process_logs(
        logs: List[Dict[str, Any]], config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Process logs and return structured results."""
        if not logs:
            return {"total_logs": 0, "analyses": {}}

        analysis_type = config.get("analysis", "all")
        analyses = {}

        if analysis_type == "all" or analysis_type == "traffic-summary":
            analyses["traffic_summary"] = TrafficSummaryAnalyzer.analyze(logs)
        elif analysis_type != "traffic-summary":
            # Always include traffic summary for the chart
            analyses["traffic_summary"] = TrafficSummaryAnalyzer.analyze(logs)
        if analysis_type == "all" or analysis_type == "ssh-inbound":
            analyses["ssh_inbound"] = SSHInboundAnalyzer.analyze(logs, config)
        if analysis_type == "all" or analysis_type == "ssh-response":
            analyses["ssh_response"] = SSHResponseAnalyzer.analyze(logs, config)
        if analysis_type == "all" or analysis_type == "ssh-outbound":
            analyses["ssh_outbound"] = SSHOutboundAnalyzer.analyze(logs, config)
        if analysis_type == "all" or analysis_type == "external-inbound":
            analyses["external_inbound"] = ExternalInboundAnalyzer.analyze(logs, config)
        if analysis_type == "all" or analysis_type == "external-outbound":
            analyses["external_outbound"] = ExternalOutboundAnalyzer.analyze(logs, config)
        if analysis_type == "all" or analysis_type == "external-summary":
            analyses["external_summary"] = ExternalSummaryAnalyzer.analyze(logs, config)
        if analysis_type == "all" or analysis_type == "top-external":
            analyses["top_external"] = TopExternalAnalyzer.analyze(logs, config)
        if analysis_type == "port-specific":
            analyses["port_specific"] = PortSpecificAnalyzer.analyze(logs, config)
        if analysis_type == "all" or analysis_type == "sensitive-ports":
            analyses["sensitive_ports"] = SensitivePortsAnalyzer.analyze(logs, config)
        if analysis_type == "all" or analysis_type == "rejected":
            analyses["rejected"] = RejectedTrafficAnalyzer.analyze(logs, config)

        return {"total_logs": len(logs), "analyses": analyses}


class BaseAnalyzer:
    """Base class for traffic analyzers."""

    @staticmethod
    def _get_top_results(
        results: Dict[Any, int], limit: int = 20
    ) -> List[tuple[Any, int]]:
        """Get top results sorted by count."""
        return sorted(results.items(), key=lambda x: x[1], reverse=True)[:limit]


class TrafficSummaryAnalyzer(BaseAnalyzer):
    """Analyzes overall traffic summary."""

    @staticmethod
    def analyze(logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze traffic summary by protocol and action."""
        from collections import defaultdict

        results: dict[tuple[str, str], int] = defaultdict(int)

        for log in logs:
            key = (log.get("protocol", "unknown"), log.get("action", "unknown"))
            results[key] += 1

        top_results = TrafficSummaryAnalyzer._get_top_results(results)
        return [
            {"protocol": get_protocol_name(protocol), "action": action, "count": count}
            for (protocol, action), count in top_results
        ]


class SSHInboundAnalyzer(BaseAnalyzer):
    """Analyzes SSH inbound traffic."""

    @staticmethod
    def analyze(
        logs: List[Dict[str, Any]], config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze SSH inbound traffic."""
        from .whois_utils import get_whois_info, is_external_ip

        results: dict[tuple[str, str], int] = defaultdict(int)
        external_ips = set()

        for log in logs:
            if (
                log.get("dstaddr") in config["instance_ips"]
                and log.get("dstport") == "22"
            ):
                srcaddr = log.get("srcaddr", "unknown")
                key = (srcaddr, log.get("action", "unknown"))
                results[key] += 1

                if is_external_ip(srcaddr, config["vpc_cidr_prefix"]):
                    external_ips.add(srcaddr)

        # Batch WHOIS lookups
        whois_cache = {ip: get_whois_info(ip)["org"] for ip in external_ips}

        top_results = SSHInboundAnalyzer._get_top_results(results)
        return [
            {
                "source_ip": srcaddr,
                "action": action,
                "count": count,
                "organization": (
                    whois_cache.get(srcaddr, "Internal")
                    if is_external_ip(srcaddr, config["vpc_cidr_prefix"])
                    else "Internal"
                ),
            }
            for (srcaddr, action), count in top_results
        ]


class ExternalInboundAnalyzer(BaseAnalyzer):
    """Analyzes external inbound traffic."""

    @staticmethod
    def analyze(
        logs: List[Dict[str, Any]], config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze external inbound traffic."""
        from .whois_utils import get_whois_info

        results: dict[tuple[str, str], int] = defaultdict(int)
        external_ips = set()

        for log in logs:
            if log.get("dstaddr") in config["instance_ips"] and not log.get(
                "srcaddr", ""
            ).startswith(config["vpc_cidr_prefix"]):
                srcaddr = log.get("srcaddr", "unknown")
                key = (srcaddr, log.get("action", "unknown"))
                results[key] += 1
                external_ips.add(srcaddr)

        # Batch WHOIS lookups
        whois_cache = {ip: get_whois_info(ip)["org"] for ip in external_ips}

        top_results = ExternalInboundAnalyzer._get_top_results(results, 15)
        return [
            {
                "source_ip": srcaddr,
                "action": action,
                "count": count,
                "organization": whois_cache.get(srcaddr, "Unknown"),
            }
            for (srcaddr, action), count in top_results
        ]


class ExternalOutboundAnalyzer(BaseAnalyzer):
    """Analyzes external outbound traffic."""

    @staticmethod
    def analyze(
        logs: List[Dict[str, Any]], config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze external outbound traffic."""
        from .whois_utils import get_whois_info

        results: dict[tuple[str, str], int] = defaultdict(int)
        external_ips = set()

        for log in logs:
            if log.get("srcaddr") in config["instance_ips"] and not log.get(
                "dstaddr", ""
            ).startswith(config["vpc_cidr_prefix"]):
                dstaddr = log.get("dstaddr", "unknown")
                key = (dstaddr, log.get("action", "unknown"))
                results[key] += 1
                external_ips.add(dstaddr)

        # Batch WHOIS lookups
        whois_cache = {ip: get_whois_info(ip)["org"] for ip in external_ips}

        top_results = ExternalOutboundAnalyzer._get_top_results(results)
        return [
            {
                "destination_ip": dstaddr,
                "action": action,
                "count": count,
                "organization": whois_cache.get(dstaddr, "Unknown"),
            }
            for (dstaddr, action), count in top_results
        ]


class SSHResponseAnalyzer(BaseAnalyzer):
    """Analyzes SSH response traffic."""

    @staticmethod
    def analyze(
        logs: List[Dict[str, Any]], config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze SSH response traffic."""
        from .whois_utils import get_whois_info, is_external_ip

        results: dict[tuple[str, str], int] = defaultdict(int)
        external_ips = set()

        for log in logs:
            if (
                log.get("srcaddr") in config["instance_ips"]
                and log.get("srcport") == "22"
            ):
                dstaddr = log.get("dstaddr", "unknown")
                key = (dstaddr, log.get("action", "unknown"))
                results[key] += 1

                if is_external_ip(dstaddr, config["vpc_cidr_prefix"]):
                    external_ips.add(dstaddr)

        # Batch WHOIS lookups
        whois_cache = {ip: get_whois_info(ip)["org"] for ip in external_ips}

        top_results = SSHResponseAnalyzer._get_top_results(results)
        return [
            {
                "destination_ip": dstaddr,
                "action": action,
                "count": count,
                "organization": (
                    whois_cache.get(dstaddr, "Internal")
                    if is_external_ip(dstaddr, config["vpc_cidr_prefix"])
                    else "Internal"
                ),
            }
            for (dstaddr, action), count in top_results
        ]


class SSHOutboundAnalyzer(BaseAnalyzer):
    """Analyzes SSH outbound connections."""

    @staticmethod
    def analyze(
        logs: List[Dict[str, Any]], config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze SSH outbound connections."""
        from .whois_utils import get_whois_info, is_external_ip

        results: dict[tuple[str, str], int] = defaultdict(int)
        external_ips = set()

        for log in logs:
            if (
                log.get("srcaddr") in config["instance_ips"]
                and log.get("dstport") == "22"
            ):
                dstaddr = log.get("dstaddr", "unknown")
                key = (dstaddr, log.get("action", "unknown"))
                results[key] += 1

                if is_external_ip(dstaddr, config["vpc_cidr_prefix"]):
                    external_ips.add(dstaddr)

        # Batch WHOIS lookups
        whois_cache = {ip: get_whois_info(ip)["org"] for ip in external_ips}

        top_results = SSHOutboundAnalyzer._get_top_results(results)
        return [
            {
                "destination_ip": dstaddr,
                "action": action,
                "count": count,
                "organization": (
                    whois_cache.get(dstaddr, "Internal")
                    if is_external_ip(dstaddr, config["vpc_cidr_prefix"])
                    else "Internal"
                ),
            }
            for (dstaddr, action), count in top_results
        ]


class ExternalSummaryAnalyzer(BaseAnalyzer):
    """Analyzes external traffic summary by action."""

    @staticmethod
    def analyze(
        logs: List[Dict[str, Any]], config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze external traffic summary by action."""
        from collections import defaultdict

        results: dict[str, int] = defaultdict(int)

        for log in logs:
            is_external = not log.get("srcaddr", "").startswith(
                config["vpc_cidr_prefix"]
            ) or not log.get("dstaddr", "").startswith(config["vpc_cidr_prefix"])
            if is_external:
                results[log.get("action", "unknown")] += 1

        return [
            {"action": action, "count": count}
            for action, count in sorted(results.items(), key=lambda x: x[1], reverse=True)
        ]


class TopExternalAnalyzer(BaseAnalyzer):
    """Analyzes top external traffic flows."""

    @staticmethod
    def analyze(
        logs: List[Dict[str, Any]], config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze top external traffic flows."""
        from collections import defaultdict

        from .whois_utils import get_whois_info, is_external_ip

        results: dict[tuple[str, str, str, str], int] = defaultdict(int)
        external_ips = set()

        for log in logs:
            srcaddr = log.get("srcaddr", "unknown")
            dstaddr = log.get("dstaddr", "unknown")

            if is_external_ip(srcaddr, config["vpc_cidr_prefix"]) or is_external_ip(
                dstaddr, config["vpc_cidr_prefix"]
            ):
                key = (
                    srcaddr,
                    dstaddr,
                    log.get("dstport", "unknown"),
                    log.get("action", "unknown"),
                )
                results[key] += 1

                # Collect external IPs for batch lookup
                if is_external_ip(srcaddr, config["vpc_cidr_prefix"]):
                    external_ips.add(srcaddr)
                if is_external_ip(dstaddr, config["vpc_cidr_prefix"]):
                    external_ips.add(dstaddr)

        # Batch WHOIS lookups
        whois_cache = {}
        for ip in external_ips:
            whois_cache[ip] = get_whois_info(ip)["org"]

        top_results = TopExternalAnalyzer._get_top_results(results)
        return [
            {
                "source_ip": srcaddr,
                "destination_ip": dstaddr,
                "port": dstport,
                "action": action,
                "count": count,
                "src_org": (
                    whois_cache.get(srcaddr, "Internal")
                    if is_external_ip(srcaddr, config["vpc_cidr_prefix"])
                    else "Internal"
                ),
                "dst_org": (
                    whois_cache.get(dstaddr, "Internal")
                    if is_external_ip(dstaddr, config["vpc_cidr_prefix"])
                    else "Internal"
                ),
            }
            for (srcaddr, dstaddr, dstport, action), count in top_results
        ]


class PortSpecificAnalyzer(BaseAnalyzer):
    """Analyzes traffic for a specific port."""

    @staticmethod
    def analyze(
        logs: List[Dict[str, Any]], config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze traffic for a specific port."""
        from .whois_utils import get_whois_info, is_external_ip

        port = config.get("port")
        if not port:
            return []

        results: dict[tuple[str, str, str], int] = defaultdict(int)
        external_ips = set()

        for log in logs:
            if log.get("dstport") == str(port):
                srcaddr = log.get("srcaddr", "unknown")
                key = (
                    srcaddr,
                    log.get("dstaddr", "unknown"),
                    log.get("action", "unknown"),
                )
                results[key] += 1

                if is_external_ip(srcaddr, config["vpc_cidr_prefix"]):
                    external_ips.add(srcaddr)

        # Batch WHOIS lookups
        whois_cache = {ip: get_whois_info(ip)["org"] for ip in external_ips}

        top_results = PortSpecificAnalyzer._get_top_results(results)
        return [
            {
                "source_ip": srcaddr,
                "destination_ip": dstaddr,
                "action": action,
                "count": count,
                "src_org": (
                    whois_cache.get(srcaddr, "Internal")
                    if is_external_ip(srcaddr, config["vpc_cidr_prefix"])
                    else "Internal"
                ),
            }
            for (srcaddr, dstaddr, action), count in top_results
        ]


class SensitivePortsAnalyzer(BaseAnalyzer):
    """Analyzes traffic on commonly sensitive ports."""

    SENSITIVE_PORTS = {
        "3389",
        "1433",
        "3306",
        "5432",
        "1521",
        "27017",
        "6379",
        "11211",
        "5984",
        "9200",
    }

    @staticmethod
    def analyze(
        logs: List[Dict[str, Any]], config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze traffic on sensitive ports."""
        from .whois_utils import get_whois_info, is_external_ip

        results: dict[tuple[str, str, str], int] = defaultdict(int)
        external_ips = set()

        for log in logs:
            if log.get("dstport") in SensitivePortsAnalyzer.SENSITIVE_PORTS:
                srcaddr = log.get("srcaddr", "unknown")
                key = (
                    srcaddr,
                    log.get("dstport", "unknown"),
                    log.get("action", "unknown"),
                )
                results[key] += 1

                if is_external_ip(srcaddr, config["vpc_cidr_prefix"]):
                    external_ips.add(srcaddr)

        # Batch WHOIS lookups
        whois_cache = {ip: get_whois_info(ip)["org"] for ip in external_ips}

        top_results = SensitivePortsAnalyzer._get_top_results(results)
        return [
            {
                "source_ip": srcaddr,
                "port": dstport,
                "action": action,
                "count": count,
                "organization": (
                    whois_cache.get(srcaddr, "Internal")
                    if is_external_ip(srcaddr, config["vpc_cidr_prefix"])
                    else "Internal"
                ),
            }
            for (srcaddr, dstport, action), count in top_results
        ]


class RejectedTrafficAnalyzer(BaseAnalyzer):
    """Analyzes rejected traffic."""

    @staticmethod
    def analyze(
        logs: List[Dict[str, Any]], config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze rejected traffic."""
        from .whois_utils import get_whois_info, is_external_ip

        results: dict[tuple[str, str, str], int] = defaultdict(int)
        external_ips = set()

        for log in logs:
            if log.get("action") == "REJECT":
                srcaddr = log.get("srcaddr", "unknown")
                dstaddr = log.get("dstaddr", "unknown")
                key = (
                    srcaddr,
                    dstaddr,
                    log.get("dstport", "unknown"),
                )
                results[key] += 1

                # Collect both source and destination external IPs
                if is_external_ip(srcaddr, config["vpc_cidr_prefix"]):
                    external_ips.add(srcaddr)
                if is_external_ip(dstaddr, config["vpc_cidr_prefix"]):
                    external_ips.add(dstaddr)

        # Batch WHOIS lookups
        whois_cache = {ip: get_whois_info(ip)["org"] for ip in external_ips}

        top_results = RejectedTrafficAnalyzer._get_top_results(results)
        return [
            {
                "source_ip": srcaddr,
                "destination_ip": dstaddr,
                "port": dstport,
                "count": count,
                "external_org": (
                    whois_cache.get(dstaddr, "Internal")
                    if is_external_ip(dstaddr, config["vpc_cidr_prefix"])
                    else (
                        whois_cache.get(srcaddr, "Internal")
                        if is_external_ip(srcaddr, config["vpc_cidr_prefix"])
                        else "Internal"
                    )
                ),
            }
            for (srcaddr, dstaddr, dstport), count in top_results
        ]


class AWSProfileService:
    """Handles AWS profile operations."""

    @staticmethod
    def get_profiles() -> List[str]:
        """Get available AWS profiles from credentials file."""
        try:
            session = boto3.Session()
            return session.available_profiles  # type: ignore[no-any-return]
        except Exception:
            return ["default"]


class FileCleanupService:
    """Handles temporary file cleanup."""

    @staticmethod
    def cleanup_file(file_path: Optional[str]) -> None:
        """Clean up temporary file."""
        try:
            if file_path and os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            pass  # Ignore cleanup errors


class AnalysisService:
    """Main service for handling analysis requests."""

    async def run_analysis(self, request: AnalysisRequest) -> JSONResponse:
        """Run complete analysis workflow."""
        log_file: Optional[str] = None
        query_id = request.query_id

        try:
            # Build configuration
            config = ConfigurationBuilder.build_config(request)

            # Get instance info
            instance_info = InstanceInfoService.get_and_validate_instance_info(
                request.instance_id, request.region, request.profile
            )

            # Update config with instance info
            config.update(
                {
                    "instance_ips": instance_info["private_ips"],
                    "instance_ip": instance_info["primary_ip"],
                    "vpc_cidr_prefix": instance_info["vpc_cidr_prefix"],
                    "region": instance_info["region"],
                }
            )

            # Find log group
            log_group = LogGroupService.find_and_validate_log_group(
                instance_info["vpc_id"], config["region"], request.profile
            )
            config["log_group"] = log_group

            # Download logs
            log_file = LogDownloadService.download_and_validate_logs(config)
            config["log_file"] = log_file

            # Process logs
            logs = list(filter_logs(read_log_file(config["log_file"]), config))
            results = AnalysisResultProcessor.process_logs(logs, config)
            results["query_id"] = query_id

            log_query_end(
                logger, query_id, True, result_data=results, total_logs=len(logs)
            )
            return JSONResponse(content=results)

        except HTTPException as e:
            log_query_end(logger, query_id, False, error=str(e.detail))
            raise
        except Exception as e:
            log_query_end(logger, query_id, False, error=str(e))
            raise HTTPException(status_code=500, detail=str(e))
        finally:
            FileCleanupService.cleanup_file(log_file)


# Application instance
app = WebApplicationFactory.create_app()


def run_server() -> None:
    """Run the web server."""
    print("Starting VPC Flow Log Investigator Web Interface...")
    print("Open your browser to: http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
