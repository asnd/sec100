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

async def query_mcc_info(session, mcc, country_name):
    print(f"\n--- Fetching Active Infrastructure for {country_name} (MCC {mcc}) ---")
    result = await session.call_tool("query_mcc", arguments={"mcc_code": mcc})
    for content in result.content:
        if hasattr(content, "text"):
            print(content.text)

async def main():
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # Query Sweden (MCC 240)
            await query_mcc_info(session, 240, "Sweden")
            
            # Query Norway (MCC 242)
            await query_mcc_info(session, 242, "Norway")

if __name__ == "__main__":
    asyncio.run(main())

