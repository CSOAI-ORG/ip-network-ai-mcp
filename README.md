# IP Network AI

> By [MEOK AI Labs](https://meok.ai) — Networking tools for IP analysis, subnetting, and DNS

## Installation

```bash
pip install ip-network-ai-mcp
```

## Usage

```bash
python server.py
```

## Tools

### `parse_ip`
Parse and analyze an IP address (v4 or v6). Returns version, class, binary representation, and scope flags.

**Parameters:**
- `ip_address` (str): IPv4 or IPv6 address to analyze

### `subnet_calculator`
Calculate subnet details from CIDR notation (e.g., 192.168.1.0/24).

**Parameters:**
- `network` (str): Network in CIDR notation

### `cidr_to_range`
Convert CIDR notation to IP range with detailed info.

**Parameters:**
- `cidr` (str): CIDR notation to convert

### `dns_lookup_data`
Perform DNS lookup for a hostname including reverse DNS and IPv4/IPv6 resolution.

**Parameters:**
- `hostname` (str): Hostname to resolve

## Authentication

Free tier: 15 calls/day. Upgrade at [meok.ai/pricing](https://meok.ai/pricing) for unlimited access.

## License

MIT — MEOK AI Labs
