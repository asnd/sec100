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
    print(f"\n--- Fetching Operators for {country_name} (MCC {mcc}) ---")
    result = await session.call_tool("query_mcc", arguments={"mcc_code": mcc})
    for content in result.content:
        if hasattr(content, "text"):
            print(content.text)

async def main():
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # Query Russia (MCC 250)
            await query_mcc_info(session, 250, "Russia")
            
            # Query Ukraine (MCC 255)
            await query_mcc_info(session, 255, "Ukraine")

if __name__ == "__main__":
    asyncio.run(main())

