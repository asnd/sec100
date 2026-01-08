import asyncio
import os
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Define the server parameters
server_params = StdioServerParameters(
    command=sys.executable, # Use the current python executable
    args=["main.py"],
    env=os.environ.copy()
)

async def main():
    print(f"Connecting to server using: {server_params.command} {' '.join(server_params.args)}")
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # 1. Initialize
            await session.initialize()
            print("\n--- Connected & Initialized ---")
            
            # 2. List Tools
            tools = await session.list_tools()
            print(f"Server provides {len(tools.tools)} tools:")
            for tool in tools.tools:
                print(f" - {tool.name}: {tool.description}")
            
            # 3. Call a Tool (Query MNC 310 - usually US)
            print("\n--- Querying MNC 310 (USA) ---")
            result = await session.call_tool("query_mnc", arguments={"mnc_code": 410}) # 410 is AT&T
            
            # Print text content from result
            for content in result.content:
                if hasattr(content, "text"):
                    print(content.text)
                else:
                    print(content)

if __name__ == "__main__":
    # Ensure we are in the right directory or path is absolute
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    asyncio.run(main())
