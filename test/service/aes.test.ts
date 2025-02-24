// import AESUtil from "../../build/service/aes.js";
// describe("AESUtil", () => {
//   const testMessage = "Hello, World!";
//   const testKey = "1234567890123456"; // 16字节密钥
//   const testIv = "abcdefghijklmnop"; // 16字节IV

//   describe("ECB Mode", () => {
//     it("should encrypt and decrypt using ECB mode with base64", () => {
//       const encrypted = AESUtil.encryptECB(testMessage, testKey);
//       const decrypted = AESUtil.decryptECB(encrypted, testKey);
//       expect(decrypted).toBe(testMessage);
//     });

//     it("should encrypt and decrypt using ECB mode with hex", () => {
//       const encrypted = AESUtil.encryptECB(
//         testMessage,
//         testKey,
//         "Pkcs7",
//         "hex"
//       );
//       const decrypted = AESUtil.decryptECB(encrypted, testKey, "Pkcs7", "hex");
//       expect(decrypted).toBe(testMessage);
//     });

//     it("should work with different padding modes", () => {
//       const paddings = [
//         "Pkcs7",
//         "ZeroPadding",
//         "Iso97971",
//         "AnsiX923",
//         "Iso10126",
//       ];
//       paddings.forEach((padding) => {
//         const encrypted = AESUtil.encryptECB(testMessage, testKey, padding);
//         const decrypted = AESUtil.decryptECB(encrypted, testKey, padding);
//         expect(decrypted).toBe(testMessage);
//       });
//     });
//   });

//   describe("CBC Mode", () => {
//     it("should encrypt and decrypt using CBC mode with base64", () => {
//       const encrypted = AESUtil.encryptCBC(testMessage, testKey, testIv);
//       const decrypted = AESUtil.decryptCBC(encrypted, testKey, testIv);
//       expect(decrypted).toBe(testMessage);
//     });

//     it("should encrypt and decrypt using CBC mode with hex", () => {
//       const encrypted = AESUtil.encryptCBC(
//         testMessage,
//         testKey,
//         testIv,
//         "Pkcs7",
//         "hex"
//       );
//       const decrypted = AESUtil.decryptCBC(
//         encrypted,
//         testKey,
//         testIv,
//         "Pkcs7",
//         "hex"
//       );
//       expect(decrypted).toBe(testMessage);
//     });
//   });

//   describe("CFB Mode", () => {
//     it("should encrypt and decrypt using CFB mode with base64", () => {
//       const encrypted = AESUtil.encryptCFB(testMessage, testKey, testIv);
//       const decrypted = AESUtil.decryptCFB(encrypted, testKey, testIv);
//       expect(decrypted).toBe(testMessage);
//     });

//     it("should encrypt and decrypt using CFB mode with hex", () => {
//       const encrypted = AESUtil.encryptCFB(
//         testMessage,
//         testKey,
//         testIv,
//         "Pkcs7",
//         "hex"
//       );
//       const decrypted = AESUtil.decryptCFB(
//         encrypted,
//         testKey,
//         testIv,
//         "Pkcs7",
//         "hex"
//       );
//       expect(decrypted).toBe(testMessage);
//     });
//   });

//   describe("OFB Mode", () => {
//     it("should encrypt and decrypt using OFB mode with base64", () => {
//       const encrypted = AESUtil.encryptOFB(testMessage, testKey, testIv);
//       const decrypted = AESUtil.decryptOFB(encrypted, testKey, testIv);
//       expect(decrypted).toBe(testMessage);
//     });

//     it("should encrypt and decrypt using OFB mode with hex", () => {
//       const encrypted = AESUtil.encryptOFB(
//         testMessage,
//         testKey,
//         testIv,
//         "Pkcs7",
//         "hex"
//       );
//       const decrypted = AESUtil.decryptOFB(
//         encrypted,
//         testKey,
//         testIv,
//         "Pkcs7",
//         "hex"
//       );
//       expect(decrypted).toBe(testMessage);
//     });
//   });

//   describe("CTR Mode", () => {
//     it("should encrypt and decrypt using CTR mode with base64", () => {
//       const encrypted = AESUtil.encryptCTR(testMessage, testKey, testIv);
//       const decrypted = AESUtil.decryptCTR(encrypted, testKey, testIv);
//       expect(decrypted).toBe(testMessage);
//     });

//     it("should encrypt and decrypt using CTR mode with hex", () => {
//       const encrypted = AESUtil.encryptCTR(
//         testMessage,
//         testKey,
//         testIv,
//         "Pkcs7",
//         "hex"
//       );
//       const decrypted = AESUtil.decryptCTR(
//         encrypted,
//         testKey,
//         testIv,
//         "Pkcs7",
//         "hex"
//       );
//       expect(decrypted).toBe(testMessage);
//     });
//   });

//   describe("Error Handling", () => {
//     it("should throw error with invalid key length", () => {
//       const invalidKey = "123"; // Key too short
//       expect(() => {
//         AESUtil.encryptECB(testMessage, invalidKey);
//       }).toThrow();
//     });

//     it("should throw error with invalid IV length", () => {
//       const invalidIv = "123"; // IV too short
//       expect(() => {
//         AESUtil.encryptCBC(testMessage, testKey, invalidIv);
//       }).toThrow();
//     });

//     it("should throw error with invalid base64 input", () => {
//       const invalidBase64 = "not-a-valid-base64";
//       expect(() => {
//         AESUtil.decryptECB(invalidBase64, testKey);
//       }).toThrow();
//     });

//     it("should throw error with invalid hex input", () => {
//       const invalidHex = "not-a-valid-hex";
//       expect(() => {
//         AESUtil.decryptECB(invalidHex, testKey, "Pkcs7", "hex");
//       }).toThrow();
//     });
//   });
// });
