# sdm-backend-js

A high-performance, modern, and dependency-free Node.js backend to decrypt and verify **Secure Dynamic Messaging (SDM) / Secure Unique NFC (SUN)** from NXP NTAG 424 DNA NFC tags. This project is a direct port of the Python Flask `sdm-backend` repository.

---

## 🚀 Features

- **No External Cryptographic Dependencies:** Standard NIST SP 800-38B AES-128-CMAC and NIST SP 800-108 key diversification implemented from scratch using the built-in Node.js `crypto` library.
- **Dual Key Derivation Support:** Supports both standard NIST SP 800-108 and legacy PBKDF2 (HMAC-SHA512) key derivation models.
- **Interoperable Routing:** Fully compatible with standard python query parameters (`picc_data`, `enc`, `cmac`) and custom subpaths (`/tag/:uid?p=...&c=...`), integrating seamlessly with native mobile setups like **NFC Developer 2**.
- **Stunning UI Dashboard:** Displays decrypted tag UID, tap counters, file content, and tamper loop statuses in a premium dark glassmorphism dashboard.
- **Environment-based Configuration:** Configure key numbers, derivation modes, ports, and master keys easily inside a secure `.env` file.

---

## 🛠️ Project Structure

```
├── package.json              # Project dependencies and run scripts
├── .env                      # Local server configuration (ignored in git)
├── config.js                 # Configuration manager using dotenv
├── app.js                    # Core Express server entry point
├── libsdm/
│   ├── crypto_utils.js       # Core AES block encryption, CMAC, and HMAC-SHA256 helpers
│   ├── sdm.js                # Secure Dynamic Messaging verification engine
│   ├── derive.js             # Standard key diversification (NIST SP 800-108)
│   └── legacy_derive.js      # Legacy key diversification (PBKDF2 HMAC-SHA512)
└── views/
    └── sdm_info.ejs          # Premium glassmorphism EJS render template
```

---

## 📦 Installation & Setup

### 1. Clone & Install Dependencies
```bash
# Clone this repository
git clone https://github.com/xheen908/sdm-backend-js.git
cd sdm-backend-js

# Install dependencies
npm install
```

### 2. Configure Environment Variables
Create a `.env` file in the root directory:
```env
PORT=3000
DERIVE_MODE=legacy
MASTER_KEY=00000000000000000000000000000000
```

### 3. Start Server
```bash
# Run in production mode
npm start

# Run in development mode (hot reload)
npm run dev
```

### 🐳 Docker Support (Node 22-slim)
You can build and run this backend inside a lightweight Docker container using the preconfigured `Dockerfile`:

```bash
# Build the Docker image
docker build -t sdm-backend-js .

# Run the container (mapping port 3000 and loading your .env)
docker run -p 3000:3000 --env-file .env sdm-backend-js
```

---

## 📡 API Reference

### Web Decryption Endpoints
- **`GET /tag?p={PICC}&c={MAC}`**: Standard query parameter endpoint.
- **`GET /tag/:uid?p={PICC}&c={MAC}`**: Route-diversified verification endpoint matching **NFC Developer 2**'s default configuration.

### JSON API Endpoint
- **`GET /api/tag?p={PICC}&c={MAC}`**: Returns verification metadata in raw JSON.
  ```json
  {
    "success": true,
    "uid": "04A1B2C3D4E5F6",
    "read_ctr": 12,
    "enc_mode": "AES",
    "file_data": null,
    "tt_status": ""
  }
  ```

---

## 🛡️ License

This project is licensed under the MIT License.
