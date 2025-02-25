import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import CryptoJS from "crypto-js";
import { z } from "zod";

export class DigestUtil {
  /**
   * Calculate MD5 hash of a string
   * @param input The input string to hash
   * @returns 32-character hexadecimal MD5 hash
   */
  static md5(input: string): string {
    const hash = CryptoJS.MD5(input);
    return hash.toString();
  }

  /**
   * Calculate SHA-1 hash of a string
   * @param input The input string to hash
   * @returns 40-character hexadecimal SHA-1 hash
   */
  static sha1(input: string): string {
    const hash = CryptoJS.SHA1(input);
    return hash.toString();
  }

  /**
   * Calculate SHA-256 hash of a string
   * @param input The input string to hash
   * @returns 64-character hexadecimal SHA-256 hash
   */
  static sha256(input: string): string {
    const hash = CryptoJS.SHA256(input);
    return hash.toString();
  }

  /**
   * Calculate SHA-384 hash of a string
   * @param input The input string to hash
   * @returns 96-character hexadecimal SHA-384 hash
   */
  static sha384(input: string): string {
    const hash = CryptoJS.SHA384(input);
    return hash.toString();
  }

  /**
   * Calculate SHA-512 hash of a string
   * @param input The input string to hash
   * @returns 128-character hexadecimal SHA-512 hash
   */
  static sha512(input: string): string {
    const hash = CryptoJS.SHA512(input);
    return hash.toString();
  }

  /**
   * Calculate SHA-224 hash of a string
   * @param input The input string to hash
   * @returns 56-character hexadecimal SHA-224 hash
   */
  static sha224(input: string): string {
    const hash = CryptoJS.SHA224(input);
    return hash.toString();
  }
}

/**
 * Register digest tool
 * @param server McpServer
 */
export function registerDigestTool(server: McpServer) {
  // Register MD5 tool
  server.tool(
    "md5",
    "Calculate MD5 hash of a string",
    {
      input: z.string().describe("The input string to hash"),
    },
    ({ input }) => {
      const hash = DigestUtil.md5(input);
      return {
        content: [{ type: "text", text: hash }],
      };
    }
  );
  // Register SHA-1 tool
  server.tool(
    "sha1",
    "Calculate SHA-1 hash of a string",
    {
      input: z.string().describe("The input string to hash"),
    },
    ({ input }) => {
      const hash = DigestUtil.sha1(input);
      return {
        content: [{ type: "text", text: hash }],
      };
    }
  );
  // Register SHA-256 tool
  server.tool(
    "sha256",
    "Calculate SHA-256 hash of a string",
    {
      input: z.string().describe("The input string to hash"),
    },
    ({ input }) => {
      const hash = DigestUtil.sha256(input);
      return {
        content: [{ type: "text", text: hash }],
      };
    }
  );

  // Register SHA-384 tool
  server.tool(
    "sha384",
    "Calculate SHA-384 hash of a string",
    {
      input: z.string().describe("The input string to hash"),
    },
    ({ input }) => {
      const hash = DigestUtil.sha384(input);
      return {
        content: [{ type: "text", text: hash }],
      };
    }
  );

  // Register SHA-512 tool
  server.tool(
    "sha512",
    "Calculate SHA-512 hash of a string",
    {
      input: z.string().describe("The input string to hash"),
    },
    ({ input }) => {
      const hash = DigestUtil.sha512(input);
      return {
        content: [{ type: "text", text: hash }],
      };
    }
  );

  // Register SHA-224 tool
  server.tool(
    "sha224",
    "Calculate SHA-224 hash of a string",
    {
      input: z.string().describe("The input string to hash"),
    },
    ({ input }) => {
      const hash = DigestUtil.sha224(input);
      return {
        content: [{ type: "text", text: hash }],
      };
    }
  );
}
