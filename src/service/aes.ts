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
    const encrypted = CryptoJS.AES.encrypt(message, keyHex, {
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
