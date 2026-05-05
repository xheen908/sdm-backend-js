const crypto = require('crypto');

// Legacy PBKDF2 key derivation (compatible with older NFC Developer configurations)
function deriveTagKey(masterKey, uid, keyNo) {
  if (masterKey.equals(Buffer.alloc(16, 0))) {
    return Buffer.alloc(16, 0);
  }
  const salt = Buffer.concat([Buffer.from("key"), uid, Buffer.from([keyNo])]);
  return crypto.pbkdf2Sync(masterKey, salt, 5000, 16, 'sha512');
}

function deriveUndiversifiedKey(masterKey, keyNo) {
  if (masterKey.equals(Buffer.alloc(16, 0))) {
    return Buffer.alloc(16, 0);
  }
  const salt = Buffer.concat([Buffer.from("key_no_uid"), Buffer.from([keyNo])]);
  return crypto.pbkdf2Sync(masterKey, salt, 5000, 16, 'sha512');
}

module.exports = {
  deriveTagKey,
  deriveUndiversifiedKey
};
