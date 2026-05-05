const express = require('express');
const path = require('path');
const config = require('./config');
const { ParamMode, decryptSunMessage, InvalidMessage } = require('./libsdm/sdm');

// Select legacy (PBKDF2) or standard (NIST SP 800-108) key derivation
const derive = config.DERIVE_MODE === 'legacy' 
  ? require('./libsdm/legacy_derive') 
  : require('./libsdm/derive');

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
        <div style="font-size:12px;color:#555">NFC Developer 2 Backend • Node.js Error</div>
      </div>
    `);
  }
}

// Root landing page
app.get('/', (req, res) => {
  res.send(`
    <div style="background:#0A0B10;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;color:#FFF;font-family:sans-serif;">
      <div style="background:#161822;padding:40px;border-radius:24px;max-width:600px;width:100%;border:1px solid #25293A;text-align:center;box-shadow:0 20px 40px rgba(0,0,0,0.5)">
        <span style="font-size:48px;margin-bottom:16px;display:block">📡</span>
        <h1 style="margin-bottom:10px;font-size:28px;background:linear-gradient(135deg,#FFF,#888);-webkit-background-clip:text;-webkit-text-fill-color:transparent">NFC Developer 2 Backend</h1>
        <p style="color:#8A8F9E;margin-bottom:30px;font-size:14px">Node.js Secure Dynamic Messaging (SDM) Verification Server is active.</p>
        
        <div style="background:#1F2231;padding:24px;border-radius:16px;border:1px solid #2F344D;text-align:left;font-family:monospace;font-size:13px;color:#00FF66;line-height:1.6">
          <div style="color:#8A8F9E;font-weight:bold;margin-bottom:8px">// Available Endpoints:</div>
          <div>GET /tag?p={PICC}&c={MAC}</div>
          <div style="color:#5A5E73;margin-bottom:12px">// Standard SDM verification URL</div>
          
          <div>GET /tag/:uid?p={PICC}&c={MAC}</div>
          <div style="color:#5A5E73;margin-bottom:12px">// Diversified validation matching React Native app</div>
          
          <div>GET /api/tag?p={PICC}&c={MAC}</div>
          <div style="color:#5A5E73">// JSON API Endpoint</div>
        </div>
      </div>
    </div>
  `);
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
