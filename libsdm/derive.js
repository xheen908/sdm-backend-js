const { aesCmac, hmacSha256 } = require('./crypto_utils');

const DIV_CONST1 = Buffer.from("50494343446174614b6579", "hex");
const DIV_CONST2 = Buffer.from("536c6f744d61737465724b6579", "hex");
const DIV_CONST3 = Buffer.from("446976426173654b6579", "hex");

// Derive a tag key that is UID-diversified
function deriveTagKey(masterKey, uid, keyNo) {
  if (masterKey.equals(Buffer.alloc(16, 0))) {
    return Buffer.alloc(16, 0);
  }
  
  const cmacKey = hmacSha256(masterKey, Buffer.concat([DIV_CONST2, Buffer.from([keyNo])]));
  const innerMsg = Buffer.concat([
    Buffer.from([0x01]),
    hmacSha256(hmacSha256(masterKey, DIV_CONST3, true), uid)
  ]);
  
  return aesCmac(cmacKey, innerMsg);
}

// Derive a tag key that is not UID-diversified
function deriveUndiversifiedKey(masterKey, keyNo) {
  if (keyNo !== 1) {
    throw new Error("Only key #1 can be derived in undiversified mode.");
  }
  if (masterKey.equals(Buffer.alloc(16, 0))) {
    return Buffer.alloc(16, 0);
  }
  return hmacSha256(masterKey, DIV_CONST1);
}

module.exports = {
  deriveTagKey,
  deriveUndiversifiedKey
};
