import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerAESTool } from "./service/aes.js";
import { registerDigestTool } from "./service/digest.js";
// Create an MCP server
const server = new McpServer({
  name: "crypto-mcp",
  version: "1.0.0",
});

// Register tools
registerAESTool(server);
registerDigestTool(server);
/*
 * Start the server using stdio transport.
 */
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Crypto MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error in main():", error);
  process.exit(1);
});
