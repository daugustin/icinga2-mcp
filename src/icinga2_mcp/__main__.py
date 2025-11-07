"""Main entry point for Icinga2 MCP server."""

import asyncio
import logging
import sys

from mcp.server.stdio import stdio_server

from .server import app

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)

logger = logging.getLogger(__name__)


async def main():
    """Run the MCP server using stdio transport."""
    logger.info("Starting Icinga2 MCP server...")

    try:
        async with stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options(),
            )
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
