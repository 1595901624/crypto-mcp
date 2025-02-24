import CryptoJS from "crypto-js";

export type PaddingMode =
  | "Pkcs7"
  | "Iso97971"
  | "AnsiX923"
  | "Iso10126"
  | "ZeroPadding"
  | "NoPadding";
export type OutputFormat = "base64" | "hex";

export class AESUtil {
  /**
   * ECB 模式加密
   * @param message 待加密的消息
   * @param key 密钥
   * @param padding 填充模式
   * @param outputFormat 输出格式
   * @returns 加密后的字符串
   */
  static encryptECB(
    message: string,
    key: string,
    padding: PaddingMode = "Pkcs7",
    outputFormat: OutputFormat = "base64"
  ): string {
    const keyHex = CryptoJS.enc.Utf8.parse(key);
    const encrypted = CryptoJS.AES.encrypt(message, keyHex, {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad[padding],
    });

    return outputFormat === "base64"
      ? encrypted.toString()
      : encrypted.ciphertext.toString();
  }

  /**
   * ECB 模式解密
   * @param ciphertext 密文
   * @param key 密钥
   * @param padding 填充模式
   * @param inputFormat 输入格式
   * @returns 解密后的字符串
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
      decrypted = CryptoJS.AES.decrypt(ciphertextParams, keyHex, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad[padding],
      });
    } else {
      decrypted = CryptoJS.AES.decrypt(ciphertext, keyHex, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad[padding],
      });
    }

    return decrypted.toString(CryptoJS.enc.Utf8);
  }

  /**
   * CBC 模式加密
   * @param message 待加密的消息
   * @param key 密钥
   * @param iv 初始向量
   * @param padding 填充模式
   * @param outputFormat 输出格式
   * @returns 加密后的字符串
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
    const encrypted = CryptoJS.AES.encrypt(message, keyHex, {
      iv: ivHex,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad[padding],
    });

    return outputFormat === "base64"
      ? encrypted.toString()
      : encrypted.ciphertext.toString();
  }

  /**
   * CBC 模式解密
   * @param ciphertext 密文
   * @param key 密钥
   * @param iv 初始向量
   * @param padding 填充模式
   * @param inputFormat 输入格式
   * @returns 解密后的字符串
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
      decrypted = CryptoJS.AES.decrypt(ciphertextParams, keyHex, {
        iv: ivHex,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad[padding],
      });
    } else {
      decrypted = CryptoJS.AES.decrypt(ciphertext, keyHex, {
        iv: ivHex,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad[padding],
      });
    }

    return decrypted.toString(CryptoJS.enc.Utf8);
  }

  /**
   * CFB 模式加密
   * @param message 待加密的消息
   * @param key 密钥
   * @param iv 初始向量
   * @param padding 填充模式
   * @param outputFormat 输出格式
   * @returns 加密后的字符串
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
    const encrypted = CryptoJS.AES.encrypt(message, keyHex, {
      iv: ivHex,
      mode: CryptoJS.mode.CFB,
      padding: CryptoJS.pad[padding],
    });

    return outputFormat === "base64"
      ? encrypted.toString()
      : encrypted.ciphertext.toString();
  }

  /**
   * CFB 模式解密
   * @param ciphertext 密文
   * @param key 密钥
   * @param iv 初始向量
   * @param padding 填充模式
   * @param inputFormat 输入格式
   * @returns 解密后的字符串
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
      decrypted = CryptoJS.AES.decrypt(ciphertextParams, keyHex, {
        iv: ivHex,
        mode: CryptoJS.mode.CFB,
        padding: CryptoJS.pad[padding],
      });
    } else {
      decrypted = CryptoJS.AES.decrypt(ciphertext, keyHex, {
        iv: ivHex,
        mode: CryptoJS.mode.CFB,
        padding: CryptoJS.pad[padding],
      });
    }

    return decrypted.toString(CryptoJS.enc.Utf8);
  }

  /**
   * OFB 模式加密
   * @param message 待加密的消息
   * @param key 密钥
   * @param iv 初始向量
   * @param padding 填充模式
   * @param outputFormat 输出格式
   * @returns 加密后的字符串
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
    const encrypted = CryptoJS.AES.encrypt(message, keyHex, {
      iv: ivHex,
      mode: CryptoJS.mode.OFB,
      padding: CryptoJS.pad[padding],
    });

    return outputFormat === "base64"
      ? encrypted.toString()
      : encrypted.ciphertext.toString();
  }

  /**
   * OFB 模式解密
   * @param ciphertext 密文
   * @param key 密钥
   * @param iv 初始向量
   * @param padding 填充模式
   * @param inputFormat 输入格式
   * @returns 解密后的字符串
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
      decrypted = CryptoJS.AES.decrypt(ciphertextParams, keyHex, {
        iv: ivHex,
        mode: CryptoJS.mode.OFB,
        padding: CryptoJS.pad[padding],
      });
    } else {
      decrypted = CryptoJS.AES.decrypt(ciphertext, keyHex, {
        iv: ivHex,
        mode: CryptoJS.mode.OFB,
        padding: CryptoJS.pad[padding],
      });
    }

    return decrypted.toString(CryptoJS.enc.Utf8);
  }

  /**
   * CTR 模式加密
   * @param message 待加密的消息
   * @param key 密钥
   * @param iv 初始向量/计数器
   * @param padding 填充模式
   * @param outputFormat 输出格式
   * @returns 加密后的字符串
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
    const encrypted = CryptoJS.AES.encrypt(message, keyHex, {
      iv: ivHex,
      mode: CryptoJS.mode.CTR,
      padding: CryptoJS.pad[padding],
    });

    return outputFormat === "base64"
      ? encrypted.toString()
      : encrypted.ciphertext.toString();
  }

  /**
   * CTR 模式解密
   * @param ciphertext 密文
   * @param key 密钥
   * @param iv 初始向量/计数器
   * @param padding 填充模式
   * @param inputFormat 输入格式
   * @returns 解密后的字符串
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
      decrypted = CryptoJS.AES.decrypt(ciphertextParams, keyHex, {
        iv: ivHex,
        mode: CryptoJS.mode.CTR,
        padding: CryptoJS.pad[padding],
      });
    } else {
      decrypted = CryptoJS.AES.decrypt(ciphertext, keyHex, {
        iv: ivHex,
        mode: CryptoJS.mode.CTR,
        padding: CryptoJS.pad[padding],
      });
    }

    return decrypted.toString(CryptoJS.enc.Utf8);
  }
}