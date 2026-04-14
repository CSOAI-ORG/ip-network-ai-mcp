"""IP Network AI MCP Server — Networking tools."""

import sys, os
sys.path.insert(0, os.path.expanduser('~/clawd/meok-labs-engine/shared'))
from auth_middleware import check_access

import ipaddress
import socket
import time
from typing import Any
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ip-network-ai-mcp")
_calls: dict[str, list[float]] = {}
DAILY_LIMIT = 50

def _rate_check(tool: str) -> bool:
    now = time.time()
    _calls.setdefault(tool, [])
    _calls[tool] = [t for t in _calls[tool] if t > now - 86400]
    if len(_calls[tool]) >= DAILY_LIMIT:
        return False
    _calls[tool].append(now)
    return True

# Well-known ports
COMMON_PORTS = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP Alt", 8443: "HTTPS Alt", 27017: "MongoDB",
}

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

@mcp.tool()
def parse_ip(ip_address: str, api_key: str = "") -> dict[str, Any]:
    """Parse and analyze an IP address (v4 or v6)."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if not _rate_check("parse_ip"):
        return {"error": "Rate limit exceeded (50/day)"}
    try:
        ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return {"error": f"Invalid IP address: {ip_address}"}
    is_private = ip.is_private
    result = {
        "ip": str(ip), "version": ip.version, "is_private": is_private,
        "is_loopback": ip.is_loopback, "is_multicast": ip.is_multicast,
        "is_link_local": ip.is_link_local, "is_reserved": ip.is_reserved,
        "is_global": ip.is_global,
    }
    if ip.version == 4:
        packed = ip.packed
        result["binary"] = ".".join(f"{b:08b}" for b in packed)
        result["decimal"] = int(ip)
        result["hex"] = hex(int(ip))
        result["class"] = "A" if packed[0] < 128 else "B" if packed[0] < 192 else "C" if packed[0] < 224 else "D" if packed[0] < 240 else "E"
    else:
        result["compressed"] = ip.compressed
        result["exploded"] = ip.exploded
    return result

@mcp.tool()
def subnet_calculator(network: str, api_key: str = "") -> dict[str, Any]:
    """Calculate subnet details from CIDR notation (e.g., 192.168.1.0/24)."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if not _rate_check("subnet_calculator"):
        return {"error": "Rate limit exceeded (50/day)"}
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return {"error": f"Invalid network: {network}"}
    hosts = list(net.hosts())
    result = {
        "network": str(net.network_address), "broadcast": str(net.broadcast_address),
        "netmask": str(net.netmask), "hostmask": str(net.hostmask),
        "prefix_length": net.prefixlen, "total_addresses": net.num_addresses,
        "usable_hosts": max(0, net.num_addresses - 2) if net.version == 4 else net.num_addresses,
        "first_host": str(hosts[0]) if hosts else None,
        "last_host": str(hosts[-1]) if hosts else None,
        "version": net.version, "is_private": net.is_private,
    }
    if net.prefixlen < 30:
        # Suggest subnetting
        new_prefix = net.prefixlen + 1
        subnets = list(net.subnets(prefixlen_diff=1))
        result["can_subnet_to"] = f"/{new_prefix} ({len(subnets)} subnets of {subnets[0].num_addresses} addresses each)"
    return result

@mcp.tool()
def cidr_to_range(cidr: str, api_key: str = "") -> dict[str, Any]:
    """Convert CIDR notation to IP range with detailed info."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if not _rate_check("cidr_to_range"):
        return {"error": "Rate limit exceeded (50/day)"}
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return {"error": f"Invalid CIDR: {cidr}"}
    hosts = list(net.hosts())
    # Show first and last 5
    sample_start = [str(h) for h in hosts[:5]]
    sample_end = [str(h) for h in hosts[-5:]] if len(hosts) > 5 else []
    wildcard = str(net.hostmask)
    return {
        "cidr": str(net), "start": str(net.network_address),
        "end": str(net.broadcast_address), "range": f"{net.network_address} - {net.broadcast_address}",
        "total_ips": net.num_addresses, "usable_hosts": len(hosts),
        "netmask": str(net.netmask), "wildcard": wildcard,
        "sample_start": sample_start, "sample_end": sample_end
    }

@mcp.tool()
def dns_lookup_data(hostname: str, api_key: str = "") -> dict[str, Any]:
    """Perform DNS lookup for a hostname."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if not _rate_check("dns_lookup_data"):
        return {"error": "Rate limit exceeded (50/day)"}
    results: dict[str, Any] = {"hostname": hostname}
    try:
        ips = socket.getaddrinfo(hostname, None)
        ipv4 = list(set(addr[4][0] for addr in ips if addr[0] == socket.AF_INET))
        ipv6 = list(set(addr[4][0] for addr in ips if addr[0] == socket.AF_INET6))
        results["ipv4_addresses"] = ipv4
        results["ipv6_addresses"] = ipv6
        results["total_records"] = len(ipv4) + len(ipv6)
    except socket.gaierror as e:
        results["error"] = f"DNS resolution failed: {e}"
        return results
    # Reverse DNS
    if ipv4:
        try:
            reverse = socket.gethostbyaddr(ipv4[0])
            results["reverse_dns"] = reverse[0]
        except (socket.herror, socket.gaierror):
            results["reverse_dns"] = None
    # Check if IPs are private
    for ip_str in ipv4:
        try:
            ip = ipaddress.ip_address(ip_str)
            results["is_private"] = ip.is_private
        except ValueError:
            pass
    # Common ports info
    results["common_services"] = {str(p): name for p, name in COMMON_PORTS.items()}
    return results

if __name__ == "__main__":
    mcp.run()
