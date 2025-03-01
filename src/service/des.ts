import CryptoJS from "crypto-js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

export type PaddingMode =
  | "Pkcs7"
  | "Iso97971"
  | "AnsiX923"
  | "Iso10126"
  | "ZeroPadding"
  | "NoPadding";
export type OutputFormat = "base64" | "hex";

export class DESUtil {
  /**
   * Encrypt in ECB mode
   * @param message Message to encrypt
   * @param key Encryption key
   * @param padding Padding mode
   * @param outputFormat Output format
   * @returns Encrypted string
   */
  static encryptECB(
    message: string,
    key: string,
    padding: PaddingMode = "Pkcs7",
    outputFormat: OutputFormat = "base64"
  ): string {
    const keyHex = CryptoJS.enc.Utf8.parse(key);
    const encrypted = CryptoJS.DES.encrypt(message, keyHex, {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad[padding],
    });

    return outputFormat === "base64"
      ? encrypted.toString()
      : encrypted.ciphertext.toString();
  }

  /**
   * Decrypt in ECB mode
   * @param ciphertext Ciphertext to decrypt
   * @param key Decryption key
   * @param padding Padding mode
   * @param inputFormat Input format
   * @returns Decrypted string
   */
  static decryptECB(
    ciphertext: string,
    key: string,
    padding: PaddingMode = "Pkcs7",
    inputFormat: OutputFormat = "base64"
  ): string {
    const keyHex = CryptoJS.enc.Utf8.parse(key);
    let decrypted;

    if (inputFormat === "hex") {
      const ciphertextHex = CryptoJS.enc.Hex.parse(ciphertext);
      const ciphertextParams = CryptoJS.lib.CipherParams.create({
        ciphertext: ciphertextHex,
      });
      decrypted = CryptoJS.DES.decrypt(ciphertextParams, keyHex, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad[padding],
      });
    } else {
      decrypted = CryptoJS.DES.decrypt(ciphertext, keyHex, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad[padding],
      });
    }

    return decrypted.toString(CryptoJS.enc.Utf8);
  }

  /**
   * Encrypt in CBC mode
   * @param message Message to encrypt
   * @param key Encryption key
   * @param iv Initialization vector
   * @param padding Padding mode
   * @param outputFormat Output format
   * @returns Encrypted string
   */
  static encryptCBC(
    message: string,
    key: string,
    iv: string,
    padding: PaddingMode = "Pkcs7",
    outputFormat: OutputFormat = "base64"
  ): string {
    const keyHex = CryptoJS.enc.Utf8.parse(key);
    const ivHex = CryptoJS.enc.Utf8.parse(iv);
    const encrypted = CryptoJS.DES.encrypt(message, keyHex, {
      iv: ivHex,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad[padding],
    });

    return outputFormat === "base64"
      ? encrypted.toString()
      : encrypted.ciphertext.toString();
  }

  /**
   * Decrypt in CBC mode
   * @param ciphertext Ciphertext to decrypt
   * @param key Decryption key
   * @param iv Initialization vector
   * @param padding Padding mode
   * @param inputFormat Input format
   * @returns Decrypted string
   */
  static decryptCBC(
    ciphertext: string,
    key: string,
    iv: string,
    padding: PaddingMode = "Pkcs7",
    inputFormat: OutputFormat = "base64"
  ): string {
    const keyHex = CryptoJS.enc.Utf8.parse(key);
    const ivHex = CryptoJS.enc.Utf8.parse(iv);
    let decrypted;

    if (inputFormat === "hex") {
      const ciphertextHex = CryptoJS.enc.Hex.parse(ciphertext);
      const ciphertextParams = CryptoJS.lib.CipherParams.create({
        ciphertext: ciphertextHex,
      });
      decrypted = CryptoJS.DES.decrypt(ciphertextParams, keyHex, {
        iv: ivHex,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad[padding],
      });
    } else {
      decrypted = CryptoJS.DES.decrypt(ciphertext, keyHex, {
        iv: ivHex,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad[padding],
      });
    }

    return decrypted.toString(CryptoJS.enc.Utf8);
  }

  /**
   * Encrypt in CFB mode
   * @param message Message to encrypt
   * @param key Encryption key
   * @param iv Initialization vector
   * @param padding Padding mode
   * @param outputFormat Output format
   * @returns Encrypted string
   */
  static encryptCFB(
    message: string,
    key: string,
    iv: string,
    padding: PaddingMode = "Pkcs7",
    outputFormat: OutputFormat = "base64"
  ): string {
    const keyHex = CryptoJS.enc.Utf8.parse(key);
    const ivHex = CryptoJS.enc.Utf8.parse(iv);
    const encrypted = CryptoJS.DES.encrypt(message, keyHex, {
      iv: ivHex,
      mode: CryptoJS.mode.CFB,
      padding: CryptoJS.pad[padding],
    });

    return outputFormat === "base64"
      ? encrypted.toString()
      : encrypted.ciphertext.toString();
  }

  /**
   * Decrypt in CFB mode
   * @param ciphertext Ciphertext to decrypt
   * @param key Decryption key
   * @param iv Initialization vector
   * @param padding Padding mode
   * @param inputFormat Input format
   * @returns Decrypted string
   */
  static decryptCFB(
    ciphertext: string,
    key: string,
    iv: string,
    padding: PaddingMode = "Pkcs7",
    inputFormat: OutputFormat = "base64"
  ): string {
    const keyHex = CryptoJS.enc.Utf8.parse(key);
    const ivHex = CryptoJS.enc.Utf8.parse(iv);
    let decrypted;

    if (inputFormat === "hex") {
      const ciphertextHex = CryptoJS.enc.Hex.parse(ciphertext);
      const ciphertextParams = CryptoJS.lib.CipherParams.create({
        ciphertext: ciphertextHex,
      });
      decrypted = CryptoJS.DES.decrypt(ciphertextParams, keyHex, {
        iv: ivHex,
        mode: CryptoJS.mode.CFB,
        padding: CryptoJS.pad[padding],
      });
    } else {
      decrypted = CryptoJS.DES.decrypt(ciphertext, keyHex, {
        iv: ivHex,
        mode: CryptoJS.mode.CFB,
        padding: CryptoJS.pad[padding],
      });
    }

    return decrypted.toString(CryptoJS.enc.Utf8);
  }

  /**
   * Encrypt in OFB mode
   * @param message Message to encrypt
   * @param key Encryption key
   * @param iv Initialization vector
   * @param padding Padding mode
   * @param outputFormat Output format
   * @returns Encrypted string
   */
  static encryptOFB(
    message: string,
    key: string,
    iv: string,
    padding: PaddingMode = "Pkcs7",
    outputFormat: OutputFormat = "base64"
  ): string {
    const keyHex = CryptoJS.enc.Utf8.parse(key);
    const ivHex = CryptoJS.enc.Utf8.parse(iv);
    const encrypted = CryptoJS.DES.encrypt(message, keyHex, {
      iv: ivHex,
      mode: CryptoJS.mode.OFB,
      padding: CryptoJS.pad[padding],
    });

    return outputFormat === "base64"
      ? encrypted.toString()
      : encrypted.ciphertext.toString();
  }

  /**
   * Decrypt in OFB mode
   * @param ciphertext Ciphertext to decrypt
   * @param key Decryption key
   * @param iv Initialization vector
   * @param padding Padding mode
   * @param inputFormat Input format
   * @returns Decrypted string
   */
  static decryptOFB(
    ciphertext: string,
    key: string,
    iv: string,
    padding: PaddingMode = "Pkcs7",
    inputFormat: OutputFormat = "base64"
  ): string {
    const keyHex = CryptoJS.enc.Utf8.parse(key);
    const ivHex = CryptoJS.enc.Utf8.parse(iv);
    let decrypted;

    if (inputFormat === "hex") {
      const ciphertextHex = CryptoJS.enc.Hex.parse(ciphertext);
      const ciphertextParams = CryptoJS.lib.CipherParams.create({
        ciphertext: ciphertextHex,
      });
      decrypted = CryptoJS.DES.decrypt(ciphertextParams, keyHex, {
        iv: ivHex,
        mode: CryptoJS.mode.OFB,
        padding: CryptoJS.pad[padding],
      });
    } else {
      decrypted = CryptoJS.DES.decrypt(ciphertext, keyHex, {
        iv: ivHex,
        mode: CryptoJS.mode.OFB,
        padding: CryptoJS.pad[padding],
      });
    }

    return decrypted.toString(CryptoJS.enc.Utf8);
  }

  /**
   * Encrypt in CTR mode
   * @param message Message to encrypt
   * @param key Encryption key
   * @param iv Initialization vector/counter
   * @param padding Padding mode
   * @param outputFormat Output format
   * @returns Encrypted string
   */
  static encryptCTR(
    message: string,
    key: string,
    iv: string,
    padding: PaddingMode = "Pkcs7",
    outputFormat: OutputFormat = "base64"
  ): string {
    const keyHex = CryptoJS.enc.Utf8.parse(key);
    const ivHex = CryptoJS.enc.Utf8.parse(iv);
    const encrypted = CryptoJS.DES.encrypt(message, keyHex, {
      iv: ivHex,
      mode: CryptoJS.mode.CTR,
      padding: CryptoJS.pad[padding],
    });

    return outputFormat === "base64"
      ? encrypted.toString()
      : encrypted.ciphertext.toString();
  }

  /**
   * Decrypt in CTR mode
   * @param ciphertext Ciphertext to decrypt
   * @param key Decryption key
   * @param iv Initialization vector/counter
   * @param padding Padding mode
   * @param inputFormat Input format
   * @returns Decrypted string
   */
  static decryptCTR(
    ciphertext: string,
    key: string,
    iv: string,
    padding: PaddingMode = "Pkcs7",
    inputFormat: OutputFormat = "base64"
  ): string {
    const keyHex = CryptoJS.enc.Utf8.parse(key);
    const ivHex = CryptoJS.enc.Utf8.parse(iv);
    let decrypted;

    if (inputFormat === "hex") {
      const ciphertextHex = CryptoJS.enc.Hex.parse(ciphertext);
      const ciphertextParams = CryptoJS.lib.CipherParams.create({
        ciphertext: ciphertextHex,
      });
      decrypted = CryptoJS.DES.decrypt(ciphertextParams, keyHex, {
        iv: ivHex,
        mode: CryptoJS.mode.CTR,
        padding: CryptoJS.pad[padding],
      });
    } else {
      decrypted = CryptoJS.DES.decrypt(ciphertext, keyHex, {
        iv: ivHex,
        mode: CryptoJS.mode.CTR,
        padding: CryptoJS.pad[padding],
      });
    }

    return decrypted.toString(CryptoJS.enc.Utf8);
  }
}

/**
 * Register DES tool
 * @param server McpServer
 */
export function registerDESTool(server: McpServer) {
  // DES Encrypt
  server.tool(
    "des_encrypt",
    "encrypt text with des",
    {
      content: z.string().describe("text to encrypt"),
      key: z
        .string()
        .optional()
        .describe("encryption key, default is your-key"),
      iv: z
        .string()
        .optional()
        .describe("initialization vector, default is your-iv-")
        .default("your-iv-"),
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
      mode: z
        .string()
        .optional()
        .describe("mode, default is ECB")
        .default("ECB"),
    },
    async ({ content, key, iv, padding, outputFormat, mode }) => {
      let result = "";
      if (mode === "ECB") {
        result = DESUtil.encryptECB(
          content,
          key ?? "your-key",
          (padding ?? "Pkcs7") as PaddingMode,
          (outputFormat ?? "base64") as OutputFormat
        );
      } else if (mode === "CBC") {
        result = DESUtil.encryptCBC(
          content,
          key ?? "your-key",
          iv ?? "your-iv-",
          (padding ?? "Pkcs7") as PaddingMode,
          (outputFormat ?? "base64") as OutputFormat
        );
      } else if (mode === "CFB") {
        result = DESUtil.encryptCFB(
          content,
          key ?? "your-key",
          iv ?? "your-iv-",
          (padding ?? "Pkcs7") as PaddingMode,
          (outputFormat ?? "base64") as OutputFormat
        );
      } else if (mode === "OFB") {
        result = DESUtil.encryptOFB(
          content,
          key ?? "your-key",
          iv ?? "your-iv-",
          (padding ?? "Pkcs7") as PaddingMode,
          (outputFormat ?? "base64") as OutputFormat
        );
      } else if (mode === "CTR") {
        result = DESUtil.encryptCTR(
          content,
          key ?? "your-key",
          iv ?? "your-iv-",
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

  // DES Decrypt
  server.tool(
    "des_decrypt",
    "decrypt text with des",
    {
      content: z.string().describe("text to decrypt"),
      key: z
        .string()
        .optional()
        .describe("decryption key, default is your-key"),
      iv: z
        .string()
        .optional()
        .describe("initialization vector, default is your-iv-")
        .default("your-iv-"),
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
      mode: z
        .enum(["ECB", "CBC", "CFB", "OFB", "CTR"])
        .optional()
        .describe("mode, default is ECB")
        .default("ECB"),
    },
    async ({ content, key, iv, padding, inputFormat, mode }) => {
      let result = "";
      if (mode === "ECB") {
        result = DESUtil.decryptECB(content, key ?? "your-key");
      } else if (mode === "CBC") {
        result = DESUtil.decryptCBC(
          content,
          key ?? "your-key",
          iv ?? "your-iv-",
          (padding ?? "Pkcs7") as PaddingMode,
          (inputFormat ?? "base64") as OutputFormat
        );
      } else if (mode === "CFB") {
        result = DESUtil.decryptCFB(
          content,
          key ?? "your-key",
          iv ?? "your-iv-",
          (padding ?? "Pkcs7") as PaddingMode,
          (inputFormat ?? "base64") as OutputFormat
        );
      } else if (mode === "OFB") {
        result = DESUtil.decryptOFB(
          content,
          key ?? "your-key",
          iv ?? "your-iv-",
          (padding ?? "Pkcs7") as PaddingMode,
          (inputFormat ?? "base64") as OutputFormat
        );
      } else if (mode === "CTR") {
        result = DESUtil.decryptCTR(
          content,
          key ?? "your-key",
          iv ?? "your-iv-",
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
}
