"""Template data helpers for consistent data across components."""

def get_regions():
    """Get list of AWS regions for form options."""
    return [
        {"value": "us-east-1", "label": "us-east-1", "selected": True},
        {"value": "us-east-2", "label": "us-east-2"},
        {"value": "us-west-1", "label": "us-west-1"},
        {"value": "us-west-2", "label": "us-west-2"},
        {"value": "eu-west-1", "label": "eu-west-1"},
        {"value": "eu-west-2", "label": "eu-west-2"},
        {"value": "eu-west-3", "label": "eu-west-3"},
        {"value": "eu-central-1", "label": "eu-central-1"},
        {"value": "ap-southeast-1", "label": "ap-southeast-1"},
        {"value": "ap-southeast-2", "label": "ap-southeast-2"},
        {"value": "ap-northeast-1", "label": "ap-northeast-1"},
        {"value": "ap-northeast-2", "label": "ap-northeast-2"},
        {"value": "ca-central-1", "label": "ca-central-1"},
        {"value": "sa-east-1", "label": "sa-east-1"},
    ]

def get_analysis_types():
    """Get list of analysis types for form options."""
    return [
        {"value": "all", "label": "All Analysis Types"},
        {"value": "traffic-summary", "label": "Traffic Summary"},
        {"value": "ssh-inbound", "label": "SSH Inbound"},
        {"value": "ssh-response", "label": "SSH Response"},
        {"value": "ssh-outbound", "label": "SSH Outbound"},
        {"value": "external-inbound", "label": "External Inbound"},
        {"value": "external-outbound", "label": "External Outbound"},
        {"value": "external-summary", "label": "External Summary"},
        {"value": "top-external", "label": "Top External"},
        {"value": "port-specific", "label": "Port Specific"},
        {"value": "sensitive-ports", "label": "Sensitive Ports"},
        {"value": "rejected", "label": "Rejected Traffic"},
    ]

def get_template_context(profiles):
    """Get complete template context with all necessary data."""
    return {
        "profiles": [{"value": p, "label": p} for p in profiles],
        "regions": get_regions(),
        "analysis_types": get_analysis_types(),
    }