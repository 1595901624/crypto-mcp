<div align="center">
    <img src="logo/qrcode_mcp.png" alt="QRCode_MCP Logo" width="60">
    <h1>QRCode_MCP</h1>
    <p>
        <strong>A Model Context Protocol (MCP) server for generating simple QR codes</strong>
    </p>
    <p>
        <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="版本">
        <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="许可证">
    </p>
</div>

## 📝 Description

A Model Context Protocol (MCP) server for generating simple QR codes. Support custom QR code styles.

## ✨ Features

- 🎨 Support custom QR code styles
- 🛠️ Easy to use

## 📦 Installation

1. Clone the Repository

```
git clone https://github.com/1595901624/qrcode-mcp.git
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
    "qrcode-mcp": {
      "command": "node",
      "args": ["path/to/qrcode-mcp/build/index.js"],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

## 📝 Usage

### Available Tools

- `qrcode`: Generate a QR code image
  parameters:
  - `text`: The text to encode in the QR code (**Required**)
  - `size`: The size of the QR code (optional, default is 256)
  - `darkColor`: The color of the dark module (optional, default is #000000)
  - `lightColor`: The color of the light module (optional, default is #ffffff)
  - `errorCorrectionLevel`: The error correction level (optional, default is M)
  - `margin`: The margin of the QR code (optional, default is 4)

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
