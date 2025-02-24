import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { AESUtil, OutputFormat, PaddingMode } from "./service/aes.js";
import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";

// Create an MCP server
const server = new McpServer({
  name: "crypto-mcp",
  version: "1.0.0",
});

// AES Encrypt
server.tool(
  "aes_encrypt",
  "encrypt text with aes",
  {
    content: z.string().describe("text to encrypt and decrypt"),
    key: z
      .string()
      .optional()
      .describe("encrypt key, default is your-key-0123456"),
    padding: z
      .enum([
        "Pkcs7",
        "Iso97971",
        "AnsiX923",
        "Iso10126",
        "ZeroPadding",
        "NoPadding",
      ])
      .optional()
      .describe("padding mode, default is Pkcs7")
      .default("Pkcs7"),
    outputFormat: z
      .enum(["base64", "hex"])
      .optional()
      .describe("output format, default is base64")
      .default("base64"),
    iv: z
      .string()
      .optional()
      .describe("iv, default is your-iv-01234567")
      .default("your-iv-01234567"),
    mode: z.string().optional().describe("mode, default is ECB").default("ECB"),
  },
  async ({ content, key, padding, outputFormat, iv, mode }) => {
    let result = "";
    if (mode === "ECB") {
      result = AESUtil.encryptECB(
        content,
        key ?? "your-key-0123456",
        (padding ?? "Pkcs7") as PaddingMode,
        (outputFormat ?? "base64") as OutputFormat
      );
    } else if (mode === "CBC") {
      result = AESUtil.encryptCBC(
        content,
        key ?? "your-key-0123456",
        iv ?? "your-iv-01234567",
        (padding ?? "Pkcs7") as PaddingMode,
        (outputFormat ?? "base64") as OutputFormat
      );
    } else if (mode === "CFB") {
      result = AESUtil.encryptCFB(
        content,
        key ?? "your-key-0123456",
        iv ?? "your-iv-01234567",
        (padding ?? "Pkcs7") as PaddingMode,
        (outputFormat ?? "base64") as OutputFormat
      );
    } else if (mode === "OFB") {
      result = AESUtil.encryptOFB(
        content,
        key ?? "your-key-0123456",
        iv ?? "your-iv-01234567",
        (padding ?? "Pkcs7") as PaddingMode,
        (outputFormat ?? "base64") as OutputFormat
      );
    } else if (mode === "CTR") {
      result = AESUtil.encryptCTR(
        content,
        key ?? "your-key-0123456",
        iv ?? "your-iv-01234567",
        (padding ?? "Pkcs7") as PaddingMode,
        (outputFormat ?? "base64") as OutputFormat
      );
    } else {
      throw new McpError(ErrorCode.InvalidParams, "Unknown mode");
    }
    return {
      content: [
        {
          type: "text",
          text: result,
        },
      ],
    };
  }
);

// AES Decrypt
server.tool(
  "aes_decrypt",
  "decrypt text with aes",
  {
    content: z.string().describe("text to encrypt and decrypt"),
    key: z
      .string()
      .optional()
      .describe("decrypt key, default is your-key-0123456"),
    padding: z
      .enum([
        "Pkcs7",
        "Iso97971",
        "AnsiX923",
        "Iso10126",
        "ZeroPadding",
        "NoPadding",
      ])
      .optional()
      .describe("padding mode, default is Pkcs7")
      .default("Pkcs7"),
    inputFormat: z
      .enum(["base64", "hex"])
      .optional()
      .describe("input format, default is base64")
      .default("base64"),
    iv: z.string().optional().describe("iv, default is your-iv-01234567"),
    mode: z
      .enum(["ECB", "CBC", "CFB", "OFB", "CTR"])
      .optional()
      .describe("mode, default is ECB")
      .default("ECB"),
  },
  async ({ content, key, padding, inputFormat, iv, mode }) => {
    let result = "";
    if (mode === "ECB") {
      result = AESUtil.decryptECB(content, key ?? "your-key-0123456");
    } else if (mode === "CBC") {
      result = AESUtil.decryptCBC(
        content,
        key ?? "your-key-0123456",
        iv ?? "your-iv-01234567",
        (padding ?? "Pkcs7") as PaddingMode,
        (inputFormat ?? "base64") as OutputFormat
      );
    } else if (mode === "CFB") {
      result = AESUtil.decryptCFB(
        content,
        key ?? "your-key-0123456",
        iv ?? "your-iv-01234567",
        (padding ?? "Pkcs7") as PaddingMode,
        (inputFormat ?? "base64") as OutputFormat
      );
    } else if (mode === "OFB") {
      result = AESUtil.decryptOFB(
        content,
        key ?? "your-key-0123456",
        iv ?? "your-iv-01234567",
        (padding ?? "Pkcs7") as PaddingMode,
        (inputFormat ?? "base64") as OutputFormat
      );
    } else if (mode === "CTR") {
      result = AESUtil.decryptCTR(
        content,
        key ?? "your-key-0123456",
        iv ?? "your-iv-01234567",
        (padding ?? "Pkcs7") as PaddingMode,
        (inputFormat ?? "base64") as OutputFormat
      );
    }
    return {
      content: [
        {
          type: "text",
          text: result,
        },
      ],
    };
  }
);

/**
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
