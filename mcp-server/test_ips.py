import asyncio
import os
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Define the server parameters
server_params = StdioServerParameters(
    command="/home/niko/git/sec100/mcp-server/.venv/bin/python",
    args=["/home/niko/git/sec100/mcp-server/main.py"],
    env=os.environ.copy()
)

async def main():
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            print("\n--- Querying 'AT&T Mobility' to check for IPs ---")
            result = await session.call_tool("query_operator", arguments={"operator_name": "AT&T Mobility"})
            
            for content in result.content:
                if hasattr(content, "text"):
                    print(content.text)

if __name__ == "__main__":
    asyncio.run(main())

