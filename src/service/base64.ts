import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export class Base64Util {
    /**
     * 将字符串编码为base64
     * @param {string} input - 要编码的字符串
     * @returns {string} base64编码后的字符串
     */
    static encode(input: string): string {
        return Buffer.from(input).toString('base64');
    }

    /**
     * 解码base64编码的字符串
     * @param {string} input - 要解码的base64编码字符串
     * @returns {string} 解码后的字符串
     */
    static decode(input: string): string {
        return Buffer.from(input, 'base64').toString('utf-8');
    }
}

/**
 * Register Base64 tool
 * @param server McpServer
 */
export function registerBase64Tool(server: McpServer) {
    // Base64 Encode
    server.tool(
        "base64_encode",
        "encode text to base64",
        {
            content: z.string().describe("text to encode"),
        },
        async ({ content }) => {
            const result = Base64Util.encode(content);
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

    // Base64 Decode
    server.tool(
        "base64_decode",
        "decode base64 to text",
        {
            content: z.string().describe("base64 text to decode"),
        },
        async ({ content }) => {
            const result = Base64Util.decode(content);
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
}

