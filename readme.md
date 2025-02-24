<div align="center">
    <img src="logo/icon_crypto.png" alt="Crypto_MCP Logo" width="60">
    <h1>Crypto_MCP</h1>
    <p>
        <strong>A Model Context Protocol (MCP) server for encrypting/decrypting/algorithm/hash</strong>
    </p>
    <p>
        <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version">
        <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
    </p>
</div>

## 📝 Description

A Model Context Protocol (MCP) server for encrypting and decrypting text with AES.

## ✨ Features

- [x] Support AES encryption and decryption (128 key length)
  - Support mode: ECB, CBC, CFB, OFB, CTR
  - Support padding mode: Pkcs7, Iso97971, AnsiX923, Iso10126, ZeroPadding, NoPadding.
  - Support output format: base64, hex
  - Support input format: base64, hex

## 🔮 Comming Soon

- [ ] Support MD5 algorithm
- [ ] Support SHA1 algorithm
- [ ] Support SHA256 algorithm
- [ ] Support SHA512 algorithm
- [ ] Support DES encryption and decryption
- [ ] Support RSA encryption and decryption

## 📦 Installation

1. Clone the Repository

```
git clone https://github.com/1595901624/crypto-mcp.git
```

2. Install Dependencies

```
pnpm install
```

3. Build the Project

```
pnpm run build
```

## 🔧 Configuration

Add to your Cline MCP settings file

```
{
   "mcpServers": {
    "crypto-mcp": {
      "command": "node",
      "args": ["path/to/crypto-mcp/build/index.js"],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

## 📝 Usage

### Available Tools

- `aes_encrypt`: Encrypt text with AES
  parameters:

  - `text`: The text to encrypt (**Required**)
  - `key`: The key to encrypt the text (optional, default is your-key-0123456)
  - `padding`: The padding mode (optional, default is Pkcs7)
  - `outputFormat`: The output format (optional, default is base64)
  - `iv`: The initialization vector (optional, default is your-iv-01234567)
  - `mode`: The mode to encrypt the text (optional, default is ECB)

- `aes_decrypt`: Decrypt text with AES
  parameters:
  - `text`: The text to decrypt (**Required**)
  - `key`: The key to decrypt the text (optional, default is your-key-0123456)
  - `padding`: The padding mode (optional, default is Pkcs7)
  - `inputFormat`: The input format (optional, default is base64)
  - `iv`: The initialization vector (optional, default is your-iv-01234567)
  - `mode`: The mode to decrypt the text (optional, default is ECB)

## 📝 Development

```
# Install dependencies
npm install

# Build the project
npm run build

# Development with auto-rebuild
npm run watch
```

## 📝 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
