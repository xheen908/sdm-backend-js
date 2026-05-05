const crypto = require('crypto');
const { aesCmac, aes128EncryptBlock } = require('./crypto_utils');
const config = require('../config');

const EncMode = {
  AES: 'AES',
  LRP: 'LRP'
};

const ParamMode = {
  SEPARATED: 'SEPARATED',
  BULK: 'BULK'
};

class InvalidMessage extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidMessage';
  }
}

// Calculate the SDMMAC for NTAG 424 DNA (AES-128-CMAC with 8-byte truncation)
function calculateSdmmac(paramMode, sdmFileReadKey, piccData, encFileData = null, mode = EncMode.AES) {
  let inputBuf = Buffer.alloc(0);
  
  if (encFileData) {
    let sdmmacParamText = `&${config.SDMMAC_PARAM}=`;
    if (paramMode === ParamMode.BULK || !config.SDMMAC_PARAM) {
      sdmmacParamText = "";
    }
    inputBuf = Buffer.concat([
      Buffer.from(encFileData.toString('hex').toUpperCase(), 'ascii'),
      Buffer.from(sdmmacParamText, 'ascii')
    ]);
  }

  if (mode === EncMode.AES) {
    const sv2 = Buffer.concat([
      Buffer.from([0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80]),
      piccData
    ]);
    const padLength = (16 - (sv2.length % 16)) % 16;
    const sv2Padded = Buffer.concat([sv2, Buffer.alloc(padLength, 0)]);

    const c2Digest = aesCmac(sdmFileReadKey, sv2Padded);
    const macDigest = aesCmac(c2Digest, inputBuf);
    
    // NIST SP 800-38B 8-byte truncation (keeps odd-indexed bytes)
    const truncatedMac = Buffer.alloc(8);
    for (let i = 0; i < 8; i++) {
      truncatedMac[i] = macDigest[2 * i + 1];
    }
    return truncatedMac;
  } else {
    throw new InvalidMessage("LRP encryption mode is not supported by standard NTAG 424 configuration.");
  }
}

// Decrypt SDMEncFileData for NTAG 424 DNA
function decryptFileData(sdmFileReadKey, piccData, readCtr, encFileData, mode = EncMode.AES) {
  if (mode === EncMode.AES) {
    const sv1 = Buffer.concat([
      Buffer.from([0xC3, 0x3C, 0x00, 0x01, 0x00, 0x80]),
      piccData
    ]);
    const padLength = (16 - (sv1.length % 16)) % 16;
    const sv1Padded = Buffer.concat([sv1, Buffer.alloc(padLength, 0)]);

    const kSesSdmFileReadEnc = aesCmac(sdmFileReadKey, sv1Padded);
    const ivInput = Buffer.concat([readCtr, Buffer.alloc(13, 0)]);
    const ive = aes128EncryptBlock(kSesSdmFileReadEnc, ivInput);

    const decipher = crypto.createDecipheriv('aes-128-cbc', kSesSdmFileReadEnc, ive);
    decipher.setAutoPadding(false);
    return Buffer.concat([decipher.update(encFileData), decipher.final()]);
  } else {
    throw new InvalidMessage("LRP encryption mode is not supported.");
  }
}

// Validate plaintext mirroring SUN
function validatePlainSun(uid, readCtr, sdmmac, sdmFileReadKey, mode = EncMode.AES) {
  const readCtrReversed = Buffer.from(readCtr).reverse();
  const dataStream = Buffer.concat([uid, readCtrReversed]);

  const properSdmmac = calculateSdmmac(ParamMode.SEPARATED, sdmFileReadKey, dataStream, null, mode);

  if (!sdmmac.equals(properSdmmac)) {
    throw new InvalidMessage("Message is not properly signed - invalid MAC");
  }

  // Unpack big-endian 3-byte read counter
  const readCtrNum = (readCtr[0] << 16) | (readCtr[1] << 8) | readCtr[2];
  return {
    encryptionMode: mode,
    uid,
    readCtr: readCtrNum
  };
}

// Check ciphertext length to identify encryption mode
function getEncryptionMode(piccEncData) {
  if (piccEncData.length === 16) {
    return EncMode.AES;
  }
  if (piccEncData.length === 24) {
    return EncMode.LRP;
  }
  throw new InvalidMessage("Unsupported encryption mode.");
}

// Main decryption and signature verification for NTAG 424 DNA
function decryptSunMessage(paramMode, sdmMetaReadKey, sdmFileReadKeyFn, piccEncData, sdmmac, encFileData = null) {
  const mode = getEncryptionMode(piccEncData);

  let plaintext;
  if (mode === EncMode.AES) {
    const decipher = crypto.createDecipheriv('aes-128-cbc', sdmMetaReadKey, Buffer.alloc(16, 0));
    decipher.setAutoPadding(false);
    plaintext = Buffer.concat([decipher.update(piccEncData), decipher.final()]);
  } else {
    throw new InvalidMessage("LRP encryption mode is not supported by standard NTAG 424 configuration.");
  }

  const piccDataTag = plaintext.subarray(0, 1);
  const uidMirroringEn = (piccDataTag[0] & 0x80) === 0x80;
  const sdmReadCtrEn = (piccDataTag[0] & 0x40) === 0x40;
  const uidLength = piccDataTag[0] & 0x0F;

  if (uidLength !== 0x07) {
    // Timing-attack prevention fake calculation
    calculateSdmmac(paramMode, sdmFileReadKeyFn(Buffer.alloc(7, 0)), Buffer.alloc(10, 0), encFileData, mode);
    throw new InvalidMessage("Unsupported UID length");
  }

  let uid = null;
  let readCtr = null;
  let readCtrNum = null;
  let fileData = null;

  let offset = 1;
  if (uidMirroringEn) {
    uid = plaintext.subarray(offset, offset + uidLength);
    offset += uidLength;
  }

  if (sdmReadCtrEn) {
    readCtr = plaintext.subarray(offset, offset + 3);
    readCtrNum = readCtr[0] | (readCtr[1] << 8) | (readCtr[2] << 16); // Little Endian
  }

  if (!uid) {
    throw new InvalidMessage("UID cannot be None.");
  }

  const fileKey = sdmFileReadKeyFn(uid);
  const dataStream = Buffer.concat([uid, readCtr]);

  const calculatedMac = calculateSdmmac(paramMode, fileKey, dataStream, encFileData, mode);

  if (!sdmmac.equals(calculatedMac)) {
    throw new InvalidMessage("Message is not properly signed - invalid MAC");
  }

  if (encFileData) {
    if (!readCtr) {
      throw new InvalidMessage("SDMReadCtr is required to decipher SDMENCFileData.");
    }
    fileData = decryptFileData(fileKey, dataStream, readCtr, encFileData, mode);
  }

  return {
    piccDataTag,
    uid,
    readCtr: readCtrNum,
    fileData,
    encryptionMode: mode
  };
}

module.exports = {
  EncMode,
  ParamMode,
  InvalidMessage,
  calculateSdmmac,
  decryptFileData,
  validatePlainSun,
  decryptSunMessage
};
