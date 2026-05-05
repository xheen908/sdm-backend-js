const crypto = require('crypto');

// Encrypt a single 16-byte block with AES-128-ECB
function aes128EncryptBlock(key, block) {
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(block), cipher.final()]);
}

// Left shift helper for CMAC subkey derivation
function shiftLeft(buffer) {
  const result = Buffer.alloc(buffer.length);
  let overflow = 0;
  for (let i = buffer.length - 1; i >= 0; i--) {
    const current = buffer[i];
    result[i] = ((current << 1) | overflow) & 0xFF;
    overflow = (current & 0x80) ? 1 : 0;
  }
  return { result, overflow };
}

// XOR helper for buffers
function xor(buf1, buf2) {
  const result = Buffer.alloc(buf1.length);
  for (let i = 0; i < buf1.length; i++) {
    result[i] = buf1[i] ^ buf2[i];
  }
  return result;
}

// Generate CMAC Subkeys (K1, K2) as per NIST SP 800-38B
function generateSubkeys(key) {
  const zero = Buffer.alloc(16, 0);
  const L = aes128EncryptBlock(key, zero);
  
  const Rb = Buffer.from('00000000000000000000000000000087', 'hex');
  
  let { result: K1, overflow: overflow1 } = shiftLeft(L);
  if (overflow1) {
    K1 = xor(K1, Rb);
  }
  
  let { result: K2, overflow: overflow2 } = shiftLeft(K1);
  if (overflow2) {
    K2 = xor(K2, Rb);
  }
  
  return { K1, K2 };
}

// Calculate AES-128-CMAC signature over a message using NIST SP 800-38B
function aesCmac(key, message) {
  const { K1, K2 } = generateSubkeys(key);
  const blockSize = 16;
  
  let blocksCount = Math.ceil(message.length / blockSize);
  let complete = (message.length > 0) && (message.length % blockSize === 0);
  
  if (blocksCount === 0) {
    blocksCount = 1;
  }
  
  const blocks = [];
  for (let i = 0; i < blocksCount; i++) {
    blocks.push(message.subarray(i * blockSize, (i + 1) * blockSize));
  }
  
  let lastBlock = blocks[blocksCount - 1];
  if (!complete) {
    const padded = Buffer.alloc(blockSize, 0);
    lastBlock.copy(padded);
    padded[lastBlock.length] = 0x80;
    blocks[blocksCount - 1] = xor(padded, K2);
  } else {
    blocks[blocksCount - 1] = xor(lastBlock, K1);
  }
  
  let iv = Buffer.alloc(blockSize, 0);
  for (let i = 0; i < blocksCount; i++) {
    const cipherInput = xor(iv, blocks[i]);
    iv = aes128EncryptBlock(key, cipherInput);
  }
  
  return iv;
}

// Calculate HMAC-SHA256 signature
function hmacSha256(key, msg, noTrunc = false) {
  const hmac = crypto.createHmac('sha256', key);
  hmac.update(msg);
  const digest = hmac.digest();
  return noTrunc ? digest : digest.subarray(0, 16);
}

module.exports = {
  aes128EncryptBlock,
  aesCmac,
  hmacSha256,
  xor
};
