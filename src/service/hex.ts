import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

/**
 * HexUtil 类提供字符串与十六进制格式之间的转换功能
 */
export class HexUtil {
    /**
     * 将字符串转换为十六进制格式
     * @param {string} str - 要转换的字符串
     * @returns {string} 转换后的十六进制字符串
     */
    static stringToHex(str: string): string {
        return Array.from(str)
            .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * 将十六进制字符串转换为原始字符串
     * @param {string} hex - 要转换的十六进制字符串
     * @returns {string} 转换后的原始字符串
     */
    static hexToString(hex: string): string {
        let str = '';
        for (let i = 0; i < hex.length; i += 2) {
            str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
        }
        return str;
    }
}

/**
 * 注册 HexUtil 工具
 * @param {McpServer} server - McpServer 实例
 */
export function registerHexTool(server: McpServer) {
    // Hex Encode
    server.tool(
        "hex_encode",
        "encode text to hex",
        {
            content: z.string().describe("text to encode"),
        },
        async ({ content }: { content: string }) => {
            const result = HexUtil.stringToHex(content);
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

    // Hex Decode
    server.tool(
        "hex_decode",
        "decode hex to text",
        {
            content: z.string().describe("hex to decode"),
        },
        async ({ content }: { content: string }) => {
            const result = HexUtil.hexToString(content);
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