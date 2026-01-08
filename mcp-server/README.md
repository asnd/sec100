# 3GPP Database MCP Server

This is a Model Context Protocol (MCP) server that provides tools to query the 3GPP scanner SQLite database.

## Tools Available

- `query_mnc(mnc_code: int)`: List operators with the specified MNC.
- `query_mcc(mcc_code: int)`: List operators with the specified MCC.
- `query_operator(operator_name: str)`: Get details (MNC/MCC pairs and FQDNs) for a specific operator.

## Installation

```bash
cd mcp-server
python3 -m venv .venv
source .venv/bin/activate
pip install mcp
```

## Connecting to Claude Desktop

Add this to your `claude_desktop_config.json` (typically in `~/.config/Claude/claude_desktop_config.json` on Linux):

```json
{
  "mcpServers": {
    "3gpp-scanner": {
      "command": "/home/niko/git/sec100/mcp-server/.venv/bin/python",
      "args": ["/home/niko/git/sec100/mcp-server/main.py"],
      "env": {
        "DB_PATH": "/home/niko/git/sec100/go-3gpp-scanner/bin/database.db"
      }
    }
  }
}
```

## Manual Testing (Stdio)

You can test the server manually by piping an initialize request:

```bash
echo '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}, "clientInfo": {"name": "test", "version": "1.0"}, "protocolVersion": "2024-11-05"}}' | .venv/bin/python main.py
```