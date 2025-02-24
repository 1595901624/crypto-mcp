import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { AESUtil, OutputFormat, PaddingMode } from "./service/aes.js";
import test from "node:test";
import { text } from "node:stream/consumers";

// 定义响应类型
interface FetchResponse {
  ok: boolean;
  text(): Promise<string>;
}
// Create an MCP server
const server = new Server(
  {
    name: "crypto-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      resources: {},
      tools: {},
    },
  }
);

/**
 * Handler that lists available tools.
 * Exposes a single "ProxyNodes" tool that waits for a specified duration.
 */
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "aes_encrypt",
        description: "encrypt text with aes",
        inputSchema: {
          type: "object",
          properties: {
            content: {
              type: "string",
              description: "text to encrypt and decrypt",
            },
            key: {
              type: "string",
              description: "key",
            },
            padding: {
              type: "string",
              description: "padding mode",
              enum: [
                "Pkcs7",
                "Iso97971",
                "AnsiX923",
                "Iso10126",
                "ZeroPadding",
                "NoPadding",
              ],
            },
            outputFormat: {
              type: "string",
              description: "output format",
              enum: ["base64", "hex"],
            },
            iv: {
              type: "string",
              description: "iv",
            },
            mode: {
              type: "string",
              description: "mode",
              enum: ["ECB", "CBC", "CFB", "OFB", "CTR"],
            },
          },
          required: ["content", "key", "padding", "outputFormat", "iv", "mode"],
        },
      },
      {
        name: "aes_decrypt",
        description: "decrypt text with aes",
        inputSchema: {
          type: "object",
          properties: {
            content: {
              type: "string",
              description: "text to encrypt and decrypt",
            },
            mode: {
              type: "string",
              description: "mode",
              enum: ["ECB", "CBC", "CFB", "OFB", "CTR"],
            },
            padding: {
              type: "string",
              description: "padding mode",
              enum: [
                "Pkcs7",
                "Iso97971",
                "AnsiX923",
                "Iso10126",
                "ZeroPadding",
                "NoPadding",
              ],
            },
            inputFormat: {
              type: "string",
              description: "output format",
              enum: ["base64", "hex"],
            },
            iv: {
              type: "string",
              description: "iv",
            },
          },
          required: ["content", "key", "padding", "inputFormat", "iv", "mode"],
        },
      },
    ],
  };
});

/**
 * Handler for the crypto tool.
 * Waits for the specified duration and returns a success message.
 */
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  switch (request.params.name) {
    case "aes_encrypt":
      return aesEncrypt(request);
    case "aes_decrypt":
      return aesDecrypt(request);
    default:
      throw new McpError(ErrorCode.MethodNotFound, "Unknown tool");
  }
  // try {
  //   const content = (request.params.arguments?.content ?? '') as string ;
  //   const key = (request.params.arguments?.key ?? '') as string;
  //   const mode = (request.params.arguments?.mode ?? '') as string;
  //   const padding = (request.params.arguments?.padding ?? '') as string;
  //   const format = (request.params.arguments?.format ?? '') as string;
  //   const iv = (request.params.arguments?.iv ?? '') as string;

  //   // const qrcode = await generateQRCode(text, {
  //   //   width: size,
  //   //   color: {
  //   //     dark: darkColor,
  //   //     light: lightColor,
  //   //   },
  //   //   errorCorrectionLevel,
  //   //   margin,
  //   // });

  //   // const base64Image = qrcode.split(",")[1];

  //   return {
  //     content: [
  //       // {
  //       //   type: "image",
  //       //   data: base64Image,
  //       //   mimeType: "image/png",
  //       // },
  //       // {
  //       //   type: "text",
  //       //   text: "original qrcode: \n" + qrcode,
  //       // },
  //     ],
  //   };
  // } catch (error) {
  //   // throw new McpError(
  //   //   ErrorCode.InvalidParams,
  //   //   error instanceof Error ? error.message : "Unknown error"
  //   // );
  //   return {
  //     content: [
  //       {
  //         type: "text",
  //         data: "Unknown error: " + JSON.stringify(error),
  //       },
  //     ],
  //   };
  // }
});
function aesEncrypt(request: any) {
  const content = (request.params.arguments?.content ?? "") as string;
  const mode = (request.params.arguments?.mode ?? "ECB") as string;
  const key = (request.params.arguments?.key ?? "your-key-0123456") as string;
  const padding = (request.params.arguments?.padding ?? "Pkcs7") as string;
  const format = (request.params.arguments?.outputFormat ?? "base64") as string;
  const iv = (request.params.arguments?.iv ?? "your-iv-01234567") as string;
  let result = "";
  if (mode === "ECB") {
    result = AESUtil.encryptECB(
      content,
      key,
      padding as PaddingMode,
      format as OutputFormat
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

async function aesDecrypt(request: any) {
  const content = (request.params.arguments?.content ?? "") as string;
  const mode = (request.params.arguments?.mode ?? "") as string;
  const key = (request.params.arguments?.key ?? "") as string;
  const padding = (request.params.arguments?.padding ?? "") as string;
  const format = (request.params.arguments?.inputFormat ?? "") as string;
  const iv = (request.params.arguments?.iv ?? "") as string;

  return {
    content: [
      {
        type: "text",
        text: "test",
      },
    ],
  };
}

/**
 * Start the server using stdio transport.
 */
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("ProxyNodes MCP server running on stdio");
}

main().catch((error) => {
  console.error("Server error:", error);
});
