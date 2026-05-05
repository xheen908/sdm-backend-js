// Load environment variables from .env file
require('dotenv').config();

module.exports = {
  // Key derivation mode: "legacy" (PBKDF2) or "standard" (NIST SP 800-108)
  DERIVE_MODE: process.env.DERIVE_MODE || "legacy",

  // Master AES-128 key (32-character hex)
  MASTER_KEY: process.env.MASTER_KEY || "00000000000000000000000000000000",

  // Query parameter names for encrypted mirroring (SDM)
  ENC_PICC_DATA_PARAM: process.env.ENC_PICC_DATA_PARAM || "picc_data",
  ENC_FILE_DATA_PARAM: process.env.ENC_FILE_DATA_PARAM || "enc",

  // Query parameter names for plaintext mirroring
  UID_PARAM: process.env.UID_PARAM || "uid",
  CTR_PARAM: process.env.CTR_PARAM || "ctr",

  // Always applied query parameter for MAC signature
  SDMMAC_PARAM: process.env.SDMMAC_PARAM || "cmac",

  // Require LRP (Leakage Resilient Primitive) mode - disallow standard AES if true
  REQUIRE_LRP: process.env.REQUIRE_LRP === 'true',

  // Port for Express server
  PORT: process.env.PORT || 3000
};
