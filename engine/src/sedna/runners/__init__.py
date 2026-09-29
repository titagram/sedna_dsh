"""Safe, small wrappers around locally installed security tools."""

from sedna.runners.core import ToolResult, ToolRunner
from sedna.runners.nmap import nmap_service_scan, nmap_tcp_discovery

__all__ = [
    "ToolResult",
    "ToolRunner",
    "nmap_service_scan",
    "nmap_tcp_discovery",
]
