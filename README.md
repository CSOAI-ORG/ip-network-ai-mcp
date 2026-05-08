<div align="center">

# Ip Network Ai MCP

**IP Network AI MCP Server — Networking tools.**

[![PyPI](https://img.shields.io/pypi/v/meok-ip-network-ai-mcp)](https://pypi.org/project/meok-ip-network-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

IP Network AI MCP Server — Networking tools.

## Tools

| Tool | Description |
|------|-------------|
| `parse_ip` | Parse and analyze an IP address (v4 or v6). |
| `subnet_calculator` | Calculate subnet details from CIDR notation (e.g., 192.168.1.0/24). |
| `cidr_to_range` | Convert CIDR notation to IP range with detailed info. |
| `dns_lookup_data` | Perform DNS lookup for a hostname. |

## Installation

```bash
pip install meok-ip-network-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "ip-network-ai": {
      "command": "python",
      "args": ["-m", "meok_ip_network_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 4 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
