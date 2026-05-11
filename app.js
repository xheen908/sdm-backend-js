const express = require('express');
const path = require('path');
const config = require('./config');
const { ParamMode, decryptSunMessage, InvalidMessage } = require('./libsdm/sdm');

// Select legacy (PBKDF2) or standard (NIST SP 800-108) key derivation
const derive = config.DERIVE_MODE === 'legacy' 
  ? require('./libsdm/legacy_derive') 
  : require('./libsdm/derive');
const { aesCmac } = require('./libsdm/crypto_utils');

const app = express();

// Setup EJS views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.json());

// Parse parameters from query string (supporting both python names and React Native shortnames)
function parseParameters(req) {
  const encPiccData = req.query[config.ENC_PICC_DATA_PARAM] || req.query.p;
  const encFileData = req.query[config.ENC_FILE_DATA_PARAM] || req.query.enc;
  const sdmmac = req.query[config.SDMMAC_PARAM] || req.query.cmac || req.query.c;

  if (!encPiccData) {
    throw new Error(`Parameter ${config.ENC_PICC_DATA_PARAM} or p is required`);
  }
  if (!sdmmac) {
    throw new Error(`Parameter ${config.SDMMAC_PARAM} or c is required`);
  }

  return {
    paramMode: ParamMode.SEPARATED,
    encPiccDataBuf: Buffer.from(encPiccData, 'hex'),
    encFileDataBuf: encFileData ? Buffer.from(encFileData, 'hex') : null,
    sdmmacBuf: Buffer.from(sdmmac, 'hex')
  };
}

// Handle Secure Dynamic Messaging Verification
function handleSdmVerification(req, res, forceJson = false) {
  try {
    // INTERCEPT: Handle SIMULATION MOCK mode explicitly provided via direct parameters
    if (req.query.uid && req.query.ctr && req.query.cmac) {
      const uidHex = req.query.uid.toUpperCase();
      const ctrHex = req.query.ctr.toUpperCase();
      const receivedCmacHex = req.query.cmac.toUpperCase();
      
      const masterKeyBuf = Buffer.from(config.MASTER_KEY, 'hex');
      const messageBuf = Buffer.concat([
        Buffer.from(uidHex, 'hex'), 
        Buffer.from(ctrHex, 'hex')
      ]);
      
      const calculatedCmacFull = aesCmac(masterKeyBuf, messageBuf);
      const calculatedCmacTrunc = calculatedCmacFull.subarray(0, 8).toString('hex').toUpperCase();
      
      if (calculatedCmacTrunc !== receivedCmacHex) {
        throw new Error('Simulation Verification Failed: CMAC Invalid (Mismatch).');
      }
      
      const readCtr = parseInt(ctrHex, 16);
      
      if (forceJson || req.query.output === 'json') {
        return res.json({
          success: true,
          uid: uidHex,
          read_ctr: readCtr,
          enc_mode: 'SIMULATION_MOCK',
          file_data: null,
          tt_status: 'not_applicable'
        });
      }
      
      return res.render('sdm_info', {
        encryptionMode: 'SIMULATION (MOCK)',
        uid: uidHex,
        readCtrNum: readCtr,
        fileData: null,
        fileDataUtf8: '',
        ttStatus: 'Simulation Mode (No Tampering Data)',
        ttColor: '#06B6D4',
        demoMode: config.MASTER_KEY === '00000000000000000000000000000000'
      });
    }

    const { paramMode, encPiccDataBuf, encFileDataBuf, sdmmacBuf } = parseParameters(req);
    const masterKeyBuf = Buffer.from(config.MASTER_KEY, 'hex');

    // Key 1 is undiversified Meta Read Key, Key 2 is diversified File Read Key (python default)
    // If master key is all zeros, both derived keys default to all zeros
    const sdmMetaReadKey = derive.deriveUndiversifiedKey(masterKeyBuf, 1);
    const sdmFileReadKeyFn = (uid) => derive.deriveTagKey(masterKeyBuf, uid, 2);

    const result = decryptSunMessage(
      paramMode,
      sdmMetaReadKey,
      sdmFileReadKeyFn,
      encPiccDataBuf,
      sdmmacBuf,
      encFileDataBuf
    );

    const uidHex = result.uid.toString('hex').toUpperCase();
    const readCtr = result.readCtr;
    const encryptionMode = result.encryptionMode;
    const fileDataHex = result.fileData ? result.fileData.toString('hex').toUpperCase() : null;
    const fileDataUtf8 = result.fileData ? result.fileData.toString('utf8').replace(/\0/g, '') : '';

    // Handle Tamper detection if file data is present
    let ttStatus = '';
    let ttColor = '';
    let ttStatusApi = '';
    if (result.fileData && result.fileData.length >= 2) {
      const ttPermStatus = String.fromCharCode(result.fileData[0]);
      const ttCurStatus = String.fromCharCode(result.fileData[1]);

      if (ttPermStatus === 'C' && ttCurStatus === 'C') {
        ttStatusApi = 'secure';
        ttStatus = 'OK (not tampered)';
        ttColor = 'green';
      } else if (ttPermStatus === 'O' && ttCurStatus === 'C') {
        ttStatusApi = 'tampered_closed';
        ttStatus = 'Tampered! (loop closed)';
        ttColor = 'red';
      } else if (ttPermStatus === 'O' && ttCurStatus === 'O') {
        ttStatusApi = 'tampered_open';
        ttStatus = 'Tampered! (loop open)';
        ttColor = 'red';
      } else if (ttPermStatus === 'I' && ttCurStatus === 'I') {
        ttStatusApi = 'not_initialized';
        ttStatus = 'Not initialized';
        ttColor = 'orange';
      } else if (ttPermStatus === 'N' && ttCurStatus === 'T') {
        ttStatusApi = 'not_supported';
        ttStatus = 'Not supported by the tag';
        ttColor = 'orange';
      } else {
        ttStatusApi = 'unknown';
        ttStatus = 'Unknown';
        ttColor = 'orange';
      }
    }

    if (forceJson || req.query.output === 'json') {
      return res.json({
        success: true,
        uid: uidHex,
        read_ctr: readCtr,
        enc_mode: encryptionMode,
        file_data: fileDataHex,
        tt_status: ttStatusApi
      });
    }

    return res.render('sdm_info', {
      encryptionMode,
      uid: uidHex,
      readCtrNum: readCtr,
      fileData: fileDataHex,
      fileDataUtf8,
      ttStatus,
      ttColor,
      demoMode: config.MASTER_KEY === '00000000000000000000000000000000'
    });

  } catch (error) {
    console.error('Verification failed:', error);
    if (forceJson || req.query.output === 'json') {
      return res.status(400).json({ success: false, error: error.message });
    }
    return res.status(400).send(`
      <div style="background:#0F1016;color:#FF4D4D;padding:30px;font-family:sans-serif;border-radius:12px;max-width:500px;margin:50px auto;border:1px solid #2F1E1E;box-shadow:0 10px 30px rgba(0,0,0,0.5)">
        <h2 style="margin-top:0">❌ Verification Failed</h2>
        <p style="color:#8A8F9E;line-height:1.6">${error.message}</p>
        <hr style="border:0;border-top:1px solid #222;margin:20px 0">
        <div style="font-size:12px;color:#555">NFC 424 DNA Backend • Node.js Error</div>
      </div>
    `);
  }
}

// Root landing page
app.get('/', (req, res) => {
  res.render('index');
});

// Privacy Policy Endpoint
app.get('/privacy', (req, res) => {
  res.render('legal', {
    title: 'Privacy Policy',
    content: `
      <h2>1. Data Collection & Processing</h2>
      <p>The NFC SDM Validation Service processes exclusively technical cryptographic payloads generated by NTAG 424 DNA chips to verify message authenticity. Specifically, this includes:</p>
      <ul>
        <li><strong>Chip UID:</strong> The unique serial number of the hardware tag, decrypted using AES-128 directly from the secure block.</li>
        <li><strong>Scan Counter:</strong> The incremented hardware count to verify anti-replay security.</li>
        <li><strong>CMAC Signature:</strong> Cryptographic hash of the request computed locally.</li>
      </ul>
      <div class="highlight-box">
        <strong>NO PERSONAL INFORMATION (PII) IS TRACKED OR STORED.</strong><br>
        The backend evaluates the cryptographic integrity only. No user profiles, IP address logs, or behavioral trackings are engaged.
      </div>
      <h2>2. Communication Security</h2>
      <p>All traffic between the app and this backend is enforced exclusively via end-to-end encryption (TLS 1.3 via HTTPS) utilizing secure tunneling.</p>
      <h2>3. Contact</h2>
      <p>For technical questions concerning NFC protocol security implementation, reach out to support@ocpp-labs.com.</p>
    `
  });
});

// Imprint Endpoint
app.get('/imprint', (req, res) => {
  res.render('legal', {
    title: 'Imprint',
    content: `
      <h2>Developer Representation</h2>
      <p><strong>OCPP Labs Architecture</strong><br>
      <span style="font-size: 13px; color: var(--text-muted); font-style: italic;">(Part of v-ledger.com group)</span></p>
      
      <p><strong>Information according to § 5 TMG:</strong><br>
      Representative: Arndt Christoph Handschuh<br>
      Address: Albertstraße 7, 47059 Duisburg</p>
      
      <p>Web: <a href="https://ocpp-labs.com">ocpp-labs.com</a><br>
      Support: <a href="mailto:support@ocpp-labs.com">support@ocpp-labs.com</a></p>
      
      <div class="highlight-box">
        <strong>DISCLAIMER:</strong><br><br>
        The use of this backend infrastructure and associated applications is strictly at your own risk. 
        The developer shall under no circumstances be held liable for bricked NFC tags, permanent hardware-locks, or data loss resulting from improper cryptographic operations.
      </div>
      <h2>Technology</h2>
      <p>This service is powered by Node.js v22-slim, utilizing express framework and native crypto modules for highly secure symmetric decryption routines.</p>
    `
  });
});

// Verification endpoints
app.get(['/tag', '/tag/:uid'], (req, res) => {
  handleSdmVerification(req, res, false);
});

app.get('/api/tag', (req, res) => {
  handleSdmVerification(req, res, true);
});

// Start Express Server
app.listen(config.PORT, () => {
  console.log(`🚀 Server listening on http://localhost:${config.PORT}`);
});
