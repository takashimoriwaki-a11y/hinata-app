'use strict';
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();

// ===== セキュリティ設定 =====

// 1. 許可オリジン（GitHub Pages のみ）
const ALLOWED_ORIGINS = [
  'https://takashimoriwaki-a11y.github.io',
];

// /auth/* と /qr はCORSを適用しない（ブラウザ直接アクセス）
app.use((req, res, next) => {
  if (req.path.startsWith('/auth') || req.path === '/qr') return next();
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(new Error('Origin required'), false);
      if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
      callback(new Error('Not allowed by CORS'), false);
    },
    methods: ['POST', 'GET'],
    allowedHeaders: ['Content-Type', 'X-Request-Signature', 'X-Session-Token'],
    credentials: false,
  })(req, res, next);
});

// 2. セキュリティヘッダー（helmet相当を手動実装）
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.removeHeader('X-Powered-By');
  next();
});

// 3. リクエストサイズ制限
app.use(express.json({ limit: '15mb' }));  // 写真アップロード用に15MB（無制限から削減）
app.use(express.urlencoded({ limit: '1mb', extended: true }));

// 4. レート制限（メモリ内）
const rateLimitStore = new Map();
function rateLimit({ windowMs, max, keyFn }) {
  return (req, res, next) => {
    const key = keyFn ? keyFn(req) : req.ip;
    const now = Date.now();
    const record = rateLimitStore.get(key) || { count: 0, resetAt: now + windowMs };
    if (now > record.resetAt) {
      record.count = 0;
      record.resetAt = now + windowMs;
    }
    record.count++;
    rateLimitStore.set(key, record);
    if (record.count > max) {
      return res.status(429).json({ error: 'リクエスト過多です。しばらく待ってから再試行してください。' });
    }
    next();
  };
}

// ストアの定期クリーンアップ（メモリリーク防止）
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of rateLimitStore.entries()) {
    if (now > record.resetAt) rateLimitStore.delete(key);
  }
}, 60000);

// エンドポイント別レート制限
const limitOCR        = rateLimit({ windowMs: 60000, max: 20 });   // OCR: 20回/分
const limitSheets     = rateLimit({ windowMs: 60000, max: 30 });   // Sheets: 30回/分
const limitPhotos     = rateLimit({ windowMs: 60000, max: 10 });   // 写真: 10回/分

// 5. 共有秘密鍵による署名検証（HMAC-SHA256）
// Railway環境変数 APP_SECRET に設定した値と一致するか検証
function verifySignature(req, res, next) {
  const APP_SECRET = process.env.APP_SECRET;
  if (!APP_SECRET) {
    // APP_SECRETが未設定の場合は警告のみ（初期移行期間）
    console.warn('⚠️  APP_SECRET が未設定です。署名検証をスキップします。');
    return next();
  }
  const signature = req.headers['x-request-signature'];
  if (!signature) return res.status(401).json({ error: '認証が必要です' });

  // リクエストボディのHMAC-SHA256を計算
  const bodyStr = JSON.stringify(req.body);
  const expected = crypto.createHmac('sha256', APP_SECRET).update(bodyStr).digest('hex');

  // タイミング攻撃対策（timingSafeEqual）
  try {
    const sigBuf = Buffer.from(signature, 'hex');
    const expBuf = Buffer.from(expected, 'hex');
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return res.status(401).json({ error: '認証に失敗しました' });
    }
  } catch {
    return res.status(401).json({ error: '認証に失敗しました' });
  }
  next();
}

// 6. 入力サニタイズヘルパー
function sanitizeString(val, maxLength = 500) {
  if (val === null || val === undefined) return '';
  return String(val).trim().slice(0, maxLength);
}
function sanitizeBase64(val, maxBytes = 10 * 1024 * 1024) {
  if (!val || typeof val !== 'string') return null;
  if (!val.match(/^[A-Za-z0-9+/=]+$/)) return null; // Base64文字のみ許可
  if (val.length > maxBytes * 1.4) return null; // Base64は元サイズの約1.37倍
  return val;
}

// 7. 安全なエラーレスポンス（内部情報を露出しない）
function safeError(res, statusCode, userMessage, internalError) {
  if (internalError) console.error('[ERROR]', internalError.message || internalError);
  return res.status(statusCode).json({ error: userMessage });
}

// ===== エンドポイント =====

// Google Drive 写真アップロード
app.post('/api/upload-photos', verifySignature, limitPhotos, async (req, res) => {
  try {
    const { userName, photos } = req.body;
    const safeUserName = sanitizeString(userName, 100);
    if (!safeUserName) return safeError(res, 400, '利用者名が必要です');
    if (!Array.isArray(photos) || photos.length === 0) return safeError(res, 400, '写真がありません');
    if (photos.length > 20) return safeError(res, 400, '写真は20枚以内にしてください');

    const serviceAccount = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    const folderId = process.env.GOOGLE_DRIVE_FOLDER_ID;
    const webhookUrl = process.env.GOOGLE_CHAT_WEBHOOK_URL;

    const token = await getAccessToken(serviceAccount);
    const userFolderId = await getOrCreateFolder(token, folderId, safeUserName);

    const uploadedFiles = [];
    for (const photo of photos) {
      const label = sanitizeString(photo.label, 100);
      const data = sanitizeBase64(photo.data);
      const mimeType = ['image/jpeg', 'image/png', 'image/heic', 'image/webp'].includes(photo.mimeType)
        ? photo.mimeType : 'image/jpeg';
      if (!data) continue;
      const fileId = await uploadFile(token, userFolderId, label, data, mimeType);
      uploadedFiles.push({ label, url: `https://drive.google.com/file/d/${fileId}/view` });
    }

    const folderUrl = `https://drive.google.com/drive/folders/${userFolderId}`;
    if (webhookUrl) {
      await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: `📋 *${safeUserName}* さんの書類写真が届きました\n\n` + uploadedFiles.map(f => `・${f.label}`).join('\n') + `\n\n📁 ${folderUrl}` }),
      });
    }
    res.json({ success: true, folderUrl, files: uploadedFiles });
  } catch (err) {
    safeError(res, 500, '写真のアップロードに失敗しました', err);
  }
});

// Google Sheets 転記
app.post('/api/sheets-update', verifySignature, limitSheets, async (req, res) => {
  try {
    const { userName, contractData, emergencyData } = req.body;
    const safeUserName = sanitizeString(userName, 100);
    if (!safeUserName) return safeError(res, 400, '利用者名が必要です');
    if (typeof contractData !== 'object') return safeError(res, 400, '不正なデータです');

    const sheetsId = process.env.GOOGLE_SHEETS_ID;
    if (!sheetsId) return safeError(res, 500, 'サーバー設定エラーです');

    const serviceAccount = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    const token = await getAccessTokenForSheets(serviceAccount);

    const spreadsheet = await sheetsGet(token, sheetsId);
    const existingSheet = spreadsheet.sheets.find(s => s.properties.title === safeUserName);

    if (!existingSheet) {
      await sheetsAddSheet(token, sheetsId, safeUserName);
    } else {
      await sheetsClear(token, sheetsId, safeUserName);
    }

    const { rows, validations } = buildRows(contractData || {}, emergencyData || {});
    await sheetsWrite(token, sheetsId, safeUserName, rows);

    const sheetId = existingSheet
      ? existingSheet.properties.sheetId
      : await getSheetId(token, sheetsId, safeUserName);

    await sheetsFormatAndValidate(token, sheetsId, sheetId, rows, validations);

    const url = `https://docs.google.com/spreadsheets/d/${sheetsId}/edit#gid=${sheetId}`;
    res.json({ success: true, url });
  } catch (err) {
    safeError(res, 500, 'スプレッドシートへの転記に失敗しました', err);
  }
});

// 処方内容OCR
app.post('/api/ocr-prescription', verifySignature, limitOCR, async (req, res) => {
  try {
    const base64Image = sanitizeBase64(req.body.base64Image);
    if (!base64Image) return safeError(res, 400, '画像データが不正です');
    const mimeType = ['image/jpeg', 'image/png', 'image/heic', 'image/webp'].includes(req.body.mimeType)
      ? req.body.mimeType : 'image/jpeg';

    const serviceAccount = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    const token = await getAccessTokenForVision(serviceAccount);
    const rawText = await visionOCR(token, base64Image, mimeType);
    const result = parsePrescription(rawText);
    res.json({ success: true, text: result });
  } catch (err) {
    safeError(res, 500, '処方内容の読み取りに失敗しました', err);
  }
});

// 名刺OCR
app.post('/api/ocr-card', verifySignature, limitOCR, async (req, res) => {
  try {
    const base64Image = sanitizeBase64(req.body.base64Image);
    if (!base64Image) return safeError(res, 400, '画像データが不正です');
    const mimeType = ['image/jpeg', 'image/png', 'image/heic', 'image/webp'].includes(req.body.mimeType)
      ? req.body.mimeType : 'image/jpeg';

    const serviceAccount = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    const token = await getAccessTokenForVision(serviceAccount);
    const rawText = await visionOCR(token, base64Image, mimeType);
    const parsed = parseBusinessCard(rawText);
    res.json({ success: true, ...parsed });
  } catch (err) {
    safeError(res, 500, '名刺の読み取りに失敗しました', err);
  }
});

// フェイスシートOCR
app.post('/api/ocr-facesheet', verifySignature, limitOCR, async (req, res) => {
  try {
    const { images, text: supplementText } = req.body;
    if (!Array.isArray(images) && !supplementText) return safeError(res, 400, '画像またはテキストが必要です');
    if (Array.isArray(images) && images.length > 10) return safeError(res, 400, '画像は10枚以内にしてください');

    const serviceAccount = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    const token = await getAccessTokenForVision(serviceAccount);

    let allText = '';
    for (const img of (images || [])) {
      const b64 = sanitizeBase64(img.base64);
      if (!b64) continue;
      const mt = ['image/jpeg', 'image/png', 'image/heic', 'image/webp'].includes(img.mimeType)
        ? img.mimeType : 'image/jpeg';
      const t = await visionOCR(token, b64, mt);
      allText += t + '\n\n';
    }
    if (supplementText) allText += sanitizeString(supplementText, 5000);

    const parsed = parseFacesheet(allText);
    parsed.extractedAt = new Date().toISOString();
    res.json({ success: true, data: parsed });
  } catch (err) {
    safeError(res, 500, 'フェイスシートの読み取りに失敗しました', err);
  }
});

// 404ハンドラーはファイル末尾に移動

// グローバルエラーハンドラ
app.use((err, req, res, next) => {
  console.error('[UNHANDLED]', err.message);
  res.status(500).json({ error: 'サーバーエラーが発生しました' });
});


// ===== Vision API =====
async function getAccessTokenForVision(serviceAccount) {
  return _getToken(serviceAccount, 'https://www.googleapis.com/auth/cloud-platform');
}
async function getAccessTokenForSheets(serviceAccount) {
  return _getToken(serviceAccount, 'https://www.googleapis.com/auth/spreadsheets https://www.googleapis.com/auth/drive');
}
async function getAccessToken(serviceAccount) {
  return _getToken(serviceAccount, 'https://www.googleapis.com/auth/drive');
}
async function _getToken(serviceAccount, scope) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ iss: serviceAccount.client_email, scope, aud: 'https://oauth2.googleapis.com/token', exp: now + 3600, iat: now })).toString('base64url');
  const signingInput = `${header}.${payload}`;
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(signingInput);
  const jwt = `${signingInput}.${sign.sign(serviceAccount.private_key, 'base64url')}`;
  const tokenRes = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}` });
  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) throw new Error('トークン取得失敗');
  return tokenData.access_token;
}

async function visionOCR(token, base64Image, mimeType) {
  const res = await fetch('https://vision.googleapis.com/v1/images:annotate', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ requests: [{ image: { content: base64Image }, features: [{ type: 'DOCUMENT_TEXT_DETECTION', maxResults: 1 }], imageContext: { languageHints: ['ja', 'en'] } }] }),
  });
  const data = await res.json();
  if (data.error) throw new Error('Vision API エラー');
  const annotation = data.responses && data.responses[0];
  return annotation && annotation.fullTextAnnotation ? annotation.fullTextAnnotation.text : '';
}

// ===== OCRパーサー =====
function parsePrescription(text) {
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  const result = [];
  let prescriptionDate = '', hospital = '', doctor = '', pharmacy = '';
  const usageKeywords = ['朝', '昼', '夕', '夜', '食前', '食後', '食間', '就寝前', '起床時', '頓服', '毎日'];
  const drugPattern = /^(.+?(?:錠|カプセル|散|液|軟膏|クリーム|テープ|パッチ|注|mg|μg|mL|g))[\s　]+/;

  for (const line of lines) {
    if (!prescriptionDate) {
      const m = line.match(/(?:処方日|調剤日)[：:\s]*(\d{4}[年\/\-]\d{1,2}[月\/\-]\d{1,2}日?)/);
      if (m) prescriptionDate = m[1];
      const gm = line.match(/(令和|昭和|平成)(\d+)年(\d{1,2})月(\d{1,2})日/);
      if (gm) { const eraMap = {'令和':2018,'平成':1988,'昭和':1925}; prescriptionDate = `${eraMap[gm[1]]+parseInt(gm[2])}年${gm[3]}月${gm[4]}日`; }
    }
    if (!hospital && /(?:病院|クリニック|診療所|医院)/.test(line)) hospital = line.slice(0, 50);
    if (!doctor && /(?:医師|Dr\.|担当医)[：:\s]/.test(line)) doctor = line.replace(/.*(?:医師|Dr\.|担当医)[：:\s]*/, '').trim().slice(0, 20);
    if (!pharmacy && /薬局/.test(line)) pharmacy = line.slice(0, 50);
    if (drugPattern.test(line) || usageKeywords.some(k => line.includes(k))) {
      if (line.length > 3 && line.length < 100) result.push(line);
    }
  }
  const parts = [];
  if (result.length > 0) parts.push(result.join('\n'));
  if (prescriptionDate) parts.push(`【処方日】${prescriptionDate}`);
  if (hospital || doctor) parts.push(`【処方医療機関・医師】${[hospital, doctor].filter(Boolean).join('　')}`);
  if (pharmacy) parts.push(`【調剤薬局】${pharmacy}`);
  return parts.join('\n') || text.trim().slice(0, 2000);
}

function parseBusinessCard(text) {
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  let name = '', organization = '', role = '', phone = '', note = '';
  const phonePattern = /(\d{2,4}[-\s]?\d{2,4}[-\s]?\d{3,4})/;
  const orgKeywords = ['病院', 'クリニック', '薬局', 'ステーション', 'センター', '事業所', '法人', '株式会社'];
  const roleKeywords = ['所長', '副所長', 'ケアマネ', '看護師', 'PSW', '相談員', '医師', '院長'];
  for (const line of lines) {
    if (phonePattern.test(line) && !phone) { phone = (line.match(phonePattern)||[])[1] || ''; continue; }
    if (orgKeywords.some(k => line.includes(k)) && !organization) { organization = line.slice(0,50); continue; }
    if (roleKeywords.some(k => line.includes(k)) && !role) { role = line.slice(0,30); continue; }
    if (!name && line.length >= 2 && line.length <= 15 && /^[ぁ-んァ-ン一-龥\s　]+$/.test(line)) { name = line; continue; }
  }
  if (!name && lines.length > 0) name = lines[0].slice(0,20);
  note = lines.filter(l => l !== name && l !== organization && l !== role && !phonePattern.test(l)).join(' ').slice(0, 200);
  return { name, organization, role, phone, note };
}

function parseFacesheet(text) {
  const result = { userName:'', nameKana:'', gender:'', age:'', birthDate:'', address:'', phone:'', mobilePhone:'', mainDiagnosis:'', medicalHistory:'', currentCondition:'', diseaseAwareness:'', familyMembers:[], familySpecialNotes:'', patientRequest:'', familyRequest:'', referralRequest:'', otherServices:'', handoverNotes:'', bedrideLevel:'', dementiaLevel:'', relatedInstitutions:[], referralSource:'', referralPhone:'', familyContact:'', familyPhone:'', doctorHospital:'', doctorName:'', supporters:[] };
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const next = lines[i+1] || '';
    if (!result.userName && /(?:氏名|お名前|利用者名)[：:\s]/.test(line)) { const m = line.replace(/.*(?:氏名|お名前|利用者名)[：:\s]*/, '').trim(); result.userName = (m || next).slice(0,50); }
    if (!result.nameKana && /(?:ふりがな|フリガナ)[：:\s]/.test(line)) { result.nameKana = line.replace(/.*(?:ふりがな|フリガナ)[：:\s]*/, '').trim().slice(0,50); }
    if (!result.gender) { if (/男性|♂/.test(line)) result.gender = '男'; else if (/女性|♀/.test(line)) result.gender = '女'; }
    if (!result.birthDate) {
      const m = line.match(/(?:生年月日)[：:\s]*(?:(\d{4})年(\d{1,2})月(\d{1,2})日|(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2}))/);
      if (m) result.birthDate = `${m[1]||m[4]}-${(m[2]||m[5]).padStart(2,'0')}-${(m[3]||m[6]).padStart(2,'0')}`;
      const gm = line.match(/(昭和|平成|令和)(\d+)年(\d{1,2})月(\d{1,2})日/);
      if (gm && !result.birthDate) { const em={'昭和':1925,'平成':1988,'令和':2018}; result.birthDate=`${em[gm[1]]+parseInt(gm[2])}-${gm[3].padStart(2,'0')}-${gm[4].padStart(2,'0')}`; }
    }
    if (!result.address && /(?:住所|ご住所)[：:\s]/.test(line)) { const m = line.replace(/.*(?:住所|ご住所)[：:\s]*/, '').trim(); result.address = (m || (/[都道府県市区町村]/.test(next) ? next : '')).slice(0,200); }
    const tel = line.match(/(?:電話|TEL)[：:\s]*([\d\-\(\)]+)/); if (tel && !result.phone) result.phone = tel[1].slice(0,20);
    const mob = line.match(/(?:携帯|mobile)[：:\s]*([\d\-\(\)]+)/); if (mob && !result.mobilePhone) result.mobilePhone = mob[1].slice(0,20);
    if (!result.mainDiagnosis && /(?:主病名|診断名|病名)[：:\s]/.test(line)) result.mainDiagnosis = line.replace(/.*(?:主病名|診断名|病名)[：:\s]*/, '').trim().slice(0,200);
    if (!result.doctorName && /(?:主治医|担当医)[：:\s]/.test(line)) result.doctorName = line.replace(/.*(?:主治医|担当医)[：:\s]*/, '').trim().slice(0,50);
    if (!result.doctorHospital && /(?:医療機関|病院名)[：:\s]/.test(line)) result.doctorHospital = line.replace(/.*(?:医療機関|病院名)[：:\s]*/, '').trim().slice(0,100);
    const bl = line.match(/(?:障害老人|寝たきり度)[：:\s]*([J][12]|[A-C][12])/i); if (bl && !result.bedrideLevel) result.bedrideLevel = bl[1].toUpperCase();
    const dl = line.match(/(?:認知症)[：:\s]*(Ⅰ|Ⅱa|Ⅱb|Ⅲa|Ⅲb|Ⅳ|M)/); if (dl && !result.dementiaLevel) result.dementiaLevel = dl[1];
    if (/(?:申し送り|特記事項)[：:\s]/.test(line)) { const m = line.replace(/.*(?:申し送り|特記事項)[：:\s]*/, '').trim(); if (m) result.handoverNotes = (result.handoverNotes ? result.handoverNotes+'\n' : '') + m; }
    if (!result.referralSource && /(?:依頼元|紹介元)[：:\s]/.test(line)) result.referralSource = line.replace(/.*(?:依頼元|紹介元)[：:\s]*/, '').trim().slice(0,100);
  }
  if (!result.userName && !result.mainDiagnosis) result.handoverNotes = text.trim().slice(0, 2000);
  return result;
}

// ===== Google Sheets ヘルパー =====
async function sheetsGet(token, spreadsheetId) {
  const res = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}`, { headers: { Authorization: `Bearer ${token}` } });
  const data = await res.json();
  if (!data.sheets) throw new Error('スプレッドシート取得失敗');
  return data;
}
async function sheetsAddSheet(token, spreadsheetId, title) {
  const res = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}:batchUpdate`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ requests: [{ addSheet: { properties: { title } } }] }) });
  const data = await res.json();
  if (data.error) throw new Error('シート追加失敗');
}
async function sheetsClear(token, spreadsheetId, sheetName) {
  const range = encodeURIComponent(`${sheetName}!A1:Z2000`);
  await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${range}:clear`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } });
}
async function sheetsWrite(token, spreadsheetId, sheetName, rows) {
  const values = rows.map(row => row.map(cell => (typeof cell === 'object' && cell !== null ? (cell.v ?? '') : (cell ?? ''))));
  const range = encodeURIComponent(`${sheetName}!A1`);
  const res = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${range}?valueInputOption=USER_ENTERED`, { method: 'PUT', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ values }) });
  const data = await res.json();
  if (data.error) throw new Error('データ書き込み失敗');
}
async function getSheetId(token, spreadsheetId, sheetName) {
  const spreadsheet = await sheetsGet(token, spreadsheetId);
  const sheet = spreadsheet.sheets.find(s => s.properties.title === sheetName);
  if (!sheet) throw new Error('シートが見つかりません');
  return sheet.properties.sheetId;
}

// buildRows / sheetsFormatAndValidate / hexToRgb は前バージョンと同じ

// ===== 西暦・和暦変換 =====
function toWareki(dateStr) {
  if (!dateStr) return '';
  const m = dateStr.match(/(\d{4})[\-\/年](\d{1,2})[\-\/月](\d{1,2})/);
  if (!m) return dateStr;
  const y = parseInt(m[1]), mo = m[2].padStart(2,'0'), d = m[3].padStart(2,'0');
  let era = '', eraYear = 0;
  if (y >= 2019) { era = '令和'; eraYear = y - 2018; }
  else if (y >= 1989) { era = '平成'; eraYear = y - 1988; }
  else if (y >= 1926) { era = '昭和'; eraYear = y - 1925; }
  else if (y >= 1912) { era = '大正'; eraYear = y - 1911; }
  else { era = '明治'; eraYear = y - 1867; }
  return `${y}（${era}${eraYear}）年${parseInt(mo)}月${parseInt(d)}日`;
}

function formatDateBoth(dateStr) {
  if (!dateStr) return '';
  return toWareki(dateStr);
}

function buildRows(c, e) {
  const bi = c.basicInfo || {};
  const rows = [], validations = [];
  let rowIdx = 0;
  const SEC = (label) => { rows.push([{ v: label, bold: true, bg: '#1e3a5f', color: '#ffffff', merge: true }]); rowIdx++; };
  const SUB = (label) => { rows.push([{ v: label, bold: true, bg: '#e3f2fd', merge: true }]); rowIdx++; };
  const B   = ()       => { rows.push(['']); rowIdx++; };
  const R   = (label, value, dropdown) => {
    const valCell = dropdown ? { v: value ?? '', dropdown } : (value ?? '');
    rows.push([{ v: label, label: true }, valCell]);
    if (dropdown) validations.push({ row: rowIdx, col: 1, values: dropdown });
    rowIdx++;
  };

  // ■ 基本情報
  SEC('■ 基本情報');
  R('氏名', bi.userName);
  R('契約日', formatDateBoth(bi.contractDate));
  R('生年月日', formatDateBoth(bi.birthDate));
  R('郵便番号', bi.postalCode);
  R('住所', bi.address);
  R('訪問先住所', bi.visitAddress);
  R('電話番号（固定）', bi.phone);
  if (bi.ibowPhone) R('　ibow登録（固定）', '登録済');
  R('電話番号（携帯）', bi.mobilePhone);
  if (bi.ibowMobile) R('　ibow登録（携帯）', '登録済');
  B();

  // ■ 訪問看護（保険種別）
  SEC('■ 訪問看護（保険種別）');
  R('保険種別', c.visitType, ['医療保険','介護保険','自費']);
  B();

  // ■ 生活保護
  SEC('■ 生活保護');
  R('生活保護', c.welfare, ['該当','非該当']);
  B();

  // ■ 訪問先
  SEC('■ 訪問先');
  R('訪問先', c.visitPlace, ['自宅','施設','その他']);
  if (c.visitPlace === 'その他') R('　その他詳細', c.visitPlaceOther);
  B();

  // ■ 担当チームとスタッフ
  SEC('■ 担当チームとスタッフ');
  R('担当チーム', c.team, ['身体チーム','天理チーム','北部チーム','南部チーム']);
  R('担当スタッフ', c.staff);
  B();

  // ■ 交通費
  SEC('■ 交通費');
  R('交通費', c.transport, ['有','無']);
  B();

  // ■ 加算
  SEC('■ 加算');
  R('重要事項説明書', c.importantDoc, ['済','未']);
  R('24時間対応体制加算', c.addition24h, ['有','無']);
  R('複数名訪問加算', c.additionMultiple, ['有','無']);
  if (c.additionMultiple === '有') {
    R('　複数名加算理由', c.additionMultipleReason, ['暴力行為や著しい不穏がある','身体的ケアの補助が必要','家族への指導や複雑な相談支援が必要','精神科訪問看護以外']);
    R('　複数名加算詳細', c.additionMultipleDetail);
  }
  R('特別管理加算', c.additionSpecial, ['有','無']);
  if (c.additionSpecial === '有') R('　特別管理疾患', c.additionSpecialDisease);
  B();

  // ■ 書類
  SEC('■ 書類');
  R('医療保険証', c.insuranceCard, ['有','無','不要']);
  R('介護保険証', c.careInsurance, ['有','無']);
  R('負担割合証', c.burdenRatio, ['有','無']);
  R('限度額認定証', c.limitAmount, ['有','無']);
  const handbookCount = Math.max((c.handbooks||[]).length, 1);
  for (let i = 0; i < handbookCount; i++) {
    const hb = (c.handbooks||[])[i] || {};
    R(`手帳${i+1}`, hb.status, ['有','無','未']);
  }
  // その他公費
  if (c.otherPublicFunds && c.otherPublicFunds.length > 0) {
    c.otherPublicFunds.forEach((opf, i) => {
      R(`公費${i+1}`, opf.status, ['有','無','未']);
    });
  }
  B();

  // ■ 自立支援医療
  SEC('■ 自立支援医療');
  R('自立支援', c.selfSupport, ['有','無']);
  R('種別', c.selfSupportMode, ['新規','追加']);
  SUB('【新規】');
  R('　申請者', c.ssApplicant, ['本人','家族','ひなた','その他']);
  if (c.ssApplicant === 'その他') R('　申請者（その他）', c.ssSubmitterOther);
  R('　提出者', c.ssSubmitter, ['本人','家族','ひなた','その他']);
  R('　提出予定日', c.ssSubmitDate);
  R('　書類の場所', c.ssDocLocation, ['本人','家族','ひなた','その他']);
  if (c.ssDocLocation === 'その他') R('　書類の場所（その他）', c.ssDocLocationOther);
  R('　診断書の説明', c.ssDiagExplain, ['済','未']);
  R('　診断書の依頼先', c.ssDiagRequest);
  R('　診断書の依頼状況', c.ssDiagRequestStatus, ['済','予定','未確定']);
  R('　薬局確認', c.ssPharmacyCheck, ['済','未']);
  R('　備考', c.ssNote);
  SUB('【追加】');
  R('　申請者', c.ssAddApplicant, ['本人','家族','ひなた','その他']);
  R('　提出者', c.ssAddSubmitter, ['本人','家族','ひなた','その他']);
  R('　提出予定日', c.ssAddSubmitDate);
  R('　書類の場所', c.ssAddDocLocation, ['本人','家族','ひなた','その他']);
  if (c.ssAddDocLocation === 'その他') R('　書類の場所（その他）', c.ssAddDocLocationOther);
  R('　備考', c.ssAddNote);
  B();

  // ■ アプラス用紙
  SEC('■ アプラス用紙');
  R('アプラス用紙', c.aplus, ['未','済','生活保護']);
  if (c.aplusNote) R('　備考', c.aplusNote);
  B();

  // ■ 訪問看護指示書の依頼
  SEC('■ 訪問看護指示書の依頼');
  R('指示書', c.instruction, ['済','未']);
  R('依頼先（医療機関）', c.instructionDest);
  R('主治医', c.instructionDoctor);
  R('口頭で依頼した日', formatDateBoth(c.instructionVerbalDate));
  R('文書依頼', c.instructionDocNeed, ['必要','不必要']);
  if (c.instructionDocNeed === '必要') {
    const docDateVal = c.instructionDocDateUndecided ? 'いつでも可' : formatDateBoth(c.instructionDocDate);
    R('　文書で依頼する日', docDateVal);
  }
  R('指示書開始日', formatDateBoth(c.instructionStart));
  R('依頼理由', c.instructionReason, ['本人の希望で','家族の希望で','ケアマネからの依頼で','相談支援専門員からの依頼で','その他']);
  if (c.instructionReason === 'その他') R('　依頼理由（その他）', c.instructionReasonOther);
  if (c.instructionNote) R('　備考', c.instructionNote);
  B();

  // ■ 正式な名前の書体
  SEC('■ 正式な名前の書体');
  R('書体確認', c.namestyle, ['必要','不必要']);
  if (c.namestyle === '必要') R('漢字', c.namestyleKanji);
  B();

  // ■ 各病院の次回受診日
  SEC('■ 各病院の次回受診日');
  const visits = (c.nextVisits && c.nextVisits.length > 0) ? c.nextVisits : [{ hospital:'', doctor:'', date:'', undecided:false }];
  visits.forEach((v, i) => {
    if (v.hospital || v.doctor || v.date || v.undecided) {
      SUB(`病院${i+1}`);
      R('　医療機関名', v.hospital);
      R('　主治医', v.doctor);
      R('　次回受診日', v.undecided ? '未定' : formatDateBoth(v.date));
    }
  });
  B();

  // ■ 申し送り事項
  SEC('■ 申し送り事項');
  R('申し送り', c.handover);
  B();

  // ■ 初回訪問日
  SEC('■ 初回訪問日');
  R('初回訪問日', c.initialVisitUndecided ? '未定' : formatDateBoth(c.initialVisitDate));
  B();

  // ■ 注意事項
  SEC('■ 注意事項');
  if (c.cautionVisitTime)      R('訪問時間指定あり', '有');
  if (c.cautionTeam)           R('チーム指定あり', '有');
  if (c.cautionStayTime)       R('滞在時間指定あり', '有');
  if (c.cautionCareInsNurse)   R('介護保険看護師同行', '有');
  if (c.cautionCareInsReport)  R('介護保険帳票記載', '有');
  if (!c.cautionVisitTime && !c.cautionTeam && !c.cautionStayTime && !c.cautionCareInsNurse && !c.cautionCareInsReport) {
    R('注意事項', 'なし');
  }
  B();

  // ■ 緊急連絡先
  SEC('■ 緊急連絡先');
  SUB('【家族】');
  R('家族連絡先', e.familyMode, ['有','無']);
  const families = (e.family && e.family.length > 0) ? e.family : [{ name:'', relation:'', relationOther:'', phone:'', mobilePhone:'', note:'' }];
  families.forEach((f, i) => {
    if (f.name || f.phone || f.mobilePhone) {
      SUB(`家族${i+1}`);
      R('　氏名', f.name);
      R('　続柄', f.relation, ['父','母','兄弟','姉妹','長男','次男','三男','長女','次女','三女','祖父','祖母','その他']);
      if (f.relation === 'その他') R('　続柄（その他）', f.relationOther);
      R('　電話', f.phone);
      if (f.ibowPhone) R('　　ibow登録', '登録済');
      R('　携帯', f.mobilePhone);
      if (f.ibowMobile) R('　　ibow登録', '登録済');
      if (f.note) R('　備考', f.note);
    }
  });

  SUB('【その他連絡先】');
  R('その他連絡先', e.otherContactMode, ['有','無']);
  const others = (e.otherContacts && e.otherContacts.length > 0) ? e.otherContacts : [{ name:'', relation:'', relationOther:'', phone:'', mobilePhone:'', note:'' }];
  others.forEach((f, i) => {
    if (f.name || f.phone || f.mobilePhone) {
      SUB(`連絡先${i+1}`);
      R('　氏名', f.name);
      R('　続柄', f.relation, ['父','母','兄弟','姉妹','長男','次男','三男','長女','次女','三女','祖父','祖母','その他']);
      if (f.relation === 'その他') R('　続柄（その他）', f.relationOther);
      R('　電話', f.phone);
      if (f.ibowPhone) R('　　ibow登録', '登録済');
      R('　携帯', f.mobilePhone);
      if (f.ibowMobile) R('　　ibow登録', '登録済');
      if (f.note) R('　備考', f.note);
    }
  });

  SUB('【主治医】');
  const doc = e.doctor || {};
  R('医療機関', doc.hospital);
  R('主治医名', doc.doctorName);

  SUB('【支援者】');
  const supporters = (e.supporters && e.supporters.length > 0) ? e.supporters : [{ role:'', roleOther:'', name:'', phone:'', note:'' }];
  supporters.forEach((s, i) => {
    if (s.name || s.role) {
      SUB(`支援者${i+1}`);
      R('　役割', s.role, ['PSW','ケアマネ','地域包括','ヘルパー','作業所（職場）','デイサービス・デイケア','その他']);
      if (s.role === 'その他') R('　役割（その他）', s.roleOther);
      R('　氏名', s.name);
      R('　電話', s.phone);
      if (s.note) R('　備考', s.note);
    }
  });

  return { rows, validations };
}


// ===== Google OAuth 認証 =====
const ALLOWED_DOMAIN = 'kokoronohinata.com';
const RAILWAY_URL = 'https://hinata-app-production.up.railway.app';
const FRONTEND_URL = 'https://takashimoriwaki-a11y.github.io/hinata-app/';

function generateSessionToken(payload) {
  const secret = process.env.APP_SECRET || 'hinata-fallback-secret';
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Math.floor(Date.now()/1000) + 86400 * 7 })).toString('base64url');
  const sig = require('crypto').createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifySessionToken(token) {
  try {
    const secret = process.env.APP_SECRET || 'hinata-fallback-secret';
    const [header, body, sig] = token.split('.');
    const expected = require('crypto').createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp < Math.floor(Date.now()/1000)) return null;
    return payload;
  } catch { return null; }
}

// Googleログイン開始
app.get('/auth/login', (req, res) => {
  const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
  if (!CLIENT_ID) return res.status(500).send('GOOGLE_CLIENT_ID が未設定です');
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: RAILWAY_URL + '/auth/callback',
    response_type: 'code',
    scope: 'openid email profile',
    hd: ALLOWED_DOMAIN,
    state: require('crypto').randomBytes(16).toString('hex'),
    access_type: 'online',
    prompt: 'select_account',
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

// Googleコールバック
app.get('/auth/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect(FRONTEND_URL + '?auth=error&msg=' + encodeURIComponent(error || 'no_code'));
  try {
    const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
    const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code, client_id: CLIENT_ID, client_secret: CLIENT_SECRET, redirect_uri: RAILWAY_URL + '/auth/callback', grant_type: 'authorization_code' }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('token error');
    const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', { headers: { Authorization: `Bearer ${tokenData.access_token}` } });
    const user = await userRes.json();
    const email = user.email || '';
    if (!email.endsWith('@' + ALLOWED_DOMAIN)) {
      return res.redirect(FRONTEND_URL + '?auth=denied&email=' + encodeURIComponent(email));
    }
    const sessionToken = generateSessionToken({ email: user.email, name: user.name, picture: user.picture });
    res.redirect(FRONTEND_URL + '?auth=ok&token=' + encodeURIComponent(sessionToken));
  } catch (err) {
    console.error('Auth error:', err.message);
    res.redirect(FRONTEND_URL + '?auth=error&msg=server_error');
  }
});

// トークン検証
app.get('/auth/verify', (req, res) => {
  const token = req.headers['x-session-token'];
  if (!token) return res.status(401).json({ ok: false });
  const payload = verifySessionToken(token);
  if (!payload) return res.status(401).json({ ok: false });
  res.json({ ok: true, email: payload.email, name: payload.name, picture: payload.picture });
});

// ログアウト
app.post('/auth/logout', (req, res) => { res.json({ ok: true }); });

// ===== Google Drive/Sheets ヘルパー =====

// QRコードページ（SVGをインライン埋め込み）
app.get('/qr', (req, res) => {
  const svgB64 = 'PD94bWwgdmVyc2lvbj0iMS4wIj8+PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI0MTAiIGhlaWdodD0iNDEwIiB2aWV3Qm94PSIwIDAgNDEwIDQxMCIgc2hhcGUtcmVuZGVyaW5nPSJjcmlzcEVkZ2VzIj48cmVjdCB3aWR0aD0iNDEwIiBoZWlnaHQ9IjQxMCIgZmlsbD0id2hpdGUiLz48ZyBmaWxsPSJibGFjayI+PHJlY3QgeD0iNDAiIHk9IjQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI1MCIgeT0iNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjYwIiB5PSI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iNzAiIHk9IjQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI4MCIgeT0iNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjkwIiB5PSI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTAwIiB5PSI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTQwIiB5PSI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTYwIiB5PSI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTgwIiB5PSI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjMwIiB5PSI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjUwIiB5PSI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjcwIiB5PSI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzAwIiB5PSI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzEwIiB5PSI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzIwIiB5PSI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzMwIiB5PSI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzQwIiB5PSI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzUwIiB5PSI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzYwIiB5PSI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iNDAiIHk9IjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMDAiIHk9IjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMzAiIHk9IjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNDAiIHk9IjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNjAiIHk9IjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMTAiIHk9IjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMjAiIHk9IjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMzAiIHk9IjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNDAiIHk9IjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNTAiIHk9IjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNzAiIHk9IjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyODAiIHk9IjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMDAiIHk9IjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzNjAiIHk9IjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI0MCIgeT0iNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjYwIiB5PSI2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iNzAiIHk9IjYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI4MCIgeT0iNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjEwMCIgeT0iNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjEyMCIgeT0iNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE0MCIgeT0iNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE2MCIgeT0iNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE4MCIgeT0iNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE5MCIgeT0iNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIyMCIgeT0iNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI0MCIgeT0iNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI4MCIgeT0iNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMwMCIgeT0iNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMyMCIgeT0iNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMzMCIgeT0iNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjM0MCIgeT0iNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjM2MCIgeT0iNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjQwIiB5PSI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iNjAiIHk9IjcwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI3MCIgeT0iNzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjgwIiB5PSI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTAwIiB5PSI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTQwIiB5PSI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTcwIiB5PSI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjAwIiB5PSI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjIwIiB5PSI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjMwIiB5PSI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjcwIiB5PSI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjgwIiB5PSI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzAwIiB5PSI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzIwIiB5PSI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzMwIiB5PSI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzQwIiB5PSI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzYwIiB5PSI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iNDAiIHk9IjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI2MCIgeT0iODAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjcwIiB5PSI4MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iODAiIHk9IjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMDAiIHk9IjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMzAiIHk9IjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNzAiIHk9IjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMDAiIHk9IjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMjAiIHk9IjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMzAiIHk9IjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNTAiIHk9IjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNjAiIHk9IjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNzAiIHk9IjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyODAiIHk9IjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMDAiIHk9IjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMjAiIHk9IjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMzAiIHk9IjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzNDAiIHk9IjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzNjAiIHk9IjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI0MCIgeT0iOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjEwMCIgeT0iOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE0MCIgeT0iOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE3MCIgeT0iOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE4MCIgeT0iOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE5MCIgeT0iOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIwMCIgeT0iOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIxMCIgeT0iOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIzMCIgeT0iOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI2MCIgeT0iOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI3MCIgeT0iOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI4MCIgeT0iOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMwMCIgeT0iOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjM2MCIgeT0iOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjQwIiB5PSIxMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjUwIiB5PSIxMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjYwIiB5PSIxMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjcwIiB5PSIxMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjgwIiB5PSIxMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjkwIiB5PSIxMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjEwMCIgeT0iMTAwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMjAiIHk9IjEwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTQwIiB5PSIxMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE2MCIgeT0iMTAwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxODAiIHk9IjEwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjAwIiB5PSIxMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIyMCIgeT0iMTAwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNDAiIHk9IjEwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjYwIiB5PSIxMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI4MCIgeT0iMTAwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMDAiIHk9IjEwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzEwIiB5PSIxMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMyMCIgeT0iMTAwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMzAiIHk9IjEwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzQwIiB5PSIxMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjM1MCIgeT0iMTAwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzNjAiIHk9IjEwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTIwIiB5PSIxMTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE0MCIgeT0iMTEwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNTAiIHk9IjExMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTYwIiB5PSIxMTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE3MCIgeT0iMTEwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxOTAiIHk9IjExMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjEwIiB5PSIxMTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIyMCIgeT0iMTEwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNDAiIHk9IjExMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjUwIiB5PSIxMTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI3MCIgeT0iMTEwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI0MCIgeT0iMTIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI1MCIgeT0iMTIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI2MCIgeT0iMTIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI4MCIgeT0iMTIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI5MCIgeT0iMTIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMDAiIHk9IjEyMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTEwIiB5PSIxMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjEyMCIgeT0iMTIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMzAiIHk9IjEyMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTQwIiB5PSIxMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE1MCIgeT0iMTIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNjAiIHk9IjEyMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjAwIiB5PSIxMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIxMCIgeT0iMTIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMjAiIHk9IjEyMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjMwIiB5PSIxMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI0MCIgeT0iMTIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNTAiIHk9IjEyMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjkwIiB5PSIxMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMwMCIgeT0iMTIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMTAiIHk9IjEyMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzIwIiB5PSIxMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjM0MCIgeT0iMTIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzNTAiIHk9IjEyMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzYwIiB5PSIxMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjUwIiB5PSIxMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjcwIiB5PSIxMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjkwIiB5PSIxMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjExMCIgeT0iMTMwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMzAiIHk9IjEzMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTcwIiB5PSIxMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE4MCIgeT0iMTMwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxOTAiIHk9IjEzMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjAwIiB5PSIxMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI0MCIgeT0iMTMwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNTAiIHk9IjEzMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjkwIiB5PSIxMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMwMCIgeT0iMTMwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMzAiIHk9IjEzMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzYwIiB5PSIxMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjQwIiB5PSIxNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjYwIiB5PSIxNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjgwIiB5PSIxNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjEwMCIgeT0iMTQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMjAiIHk9IjE0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTUwIiB5PSIxNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE2MCIgeT0iMTQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNzAiIHk9IjE0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTgwIiB5PSIxNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE5MCIgeT0iMTQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMDAiIHk9IjE0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjUwIiB5PSIxNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI5MCIgeT0iMTQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMTAiIHk9IjE0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzIwIiB5PSIxNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMzMCIgeT0iMTQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzNTAiIHk9IjE0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzYwIiB5PSIxNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjUwIiB5PSIxNTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjcwIiB5PSIxNTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjkwIiB5PSIxNTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjExMCIgeT0iMTUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNzAiIHk9IjE1MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjAwIiB5PSIxNTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIxMCIgeT0iMTUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMjAiIHk9IjE1MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjMwIiB5PSIxNTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI1MCIgeT0iMTUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNjAiIHk9IjE1MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjcwIiB5PSIxNTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMxMCIgeT0iMTUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMjAiIHk9IjE1MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzMwIiB5PSIxNTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjM1MCIgeT0iMTUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI0MCIgeT0iMTYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI2MCIgeT0iMTYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI4MCIgeT0iMTYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMDAiIHk9IjE2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTIwIiB5PSIxNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjEzMCIgeT0iMTYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNjAiIHk9IjE2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTkwIiB5PSIxNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIxMCIgeT0iMTYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMzAiIHk9IjE2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjQwIiB5PSIxNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI1MCIgeT0iMTYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyODAiIHk9IjE2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjkwIiB5PSIxNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMwMCIgeT0iMTYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMzAiIHk9IjE2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzYwIiB5PSIxNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjUwIiB5PSIxNzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjcwIiB5PSIxNzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjkwIiB5PSIxNzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjExMCIgeT0iMTcwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMzAiIHk9IjE3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTQwIiB5PSIxNzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE2MCIgeT0iMTcwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNzAiIHk9IjE3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTkwIiB5PSIxNzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIxMCIgeT0iMTcwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNDAiIHk9IjE3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjgwIiB5PSIxNzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI5MCIgeT0iMTcwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMDAiIHk9IjE3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzMwIiB5PSIxNzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjM0MCIgeT0iMTcwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzNjAiIHk9IjE3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iNDAiIHk9IjE4MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iNjAiIHk9IjE4MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iODAiIHk9IjE4MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTAwIiB5PSIxODAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjEyMCIgeT0iMTgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNDAiIHk9IjE4MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTgwIiB5PSIxODAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIyMCIgeT0iMTgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNDAiIHk9IjE4MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjYwIiB5PSIxODAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI5MCIgeT0iMTgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMjAiIHk9IjE4MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzUwIiB5PSIxODAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjM2MCIgeT0iMTgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI1MCIgeT0iMTkwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI3MCIgeT0iMTkwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI5MCIgeT0iMTkwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMTAiIHk9IjE5MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTMwIiB5PSIxOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE1MCIgeT0iMTkwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNjAiIHk9IjE5MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTcwIiB5PSIxOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE4MCIgeT0iMTkwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxOTAiIHk9IjE5MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjEwIiB5PSIxOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIyMCIgeT0iMTkwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMzAiIHk9IjE5MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjUwIiB5PSIxOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI2MCIgeT0iMTkwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNzAiIHk9IjE5MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjgwIiB5PSIxOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMwMCIgeT0iMTkwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMTAiIHk9IjE5MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzIwIiB5PSIxOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMzMCIgeT0iMTkwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzNTAiIHk9IjE5MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iNDAiIHk9IjIwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iNjAiIHk9IjIwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iODAiIHk9IjIwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTAwIiB5PSIyMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjEyMCIgeT0iMjAwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNDAiIHk9IjIwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTUwIiB5PSIyMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE3MCIgeT0iMjAwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMDAiIHk9IjIwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjEwIiB5PSIyMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIzMCIgeT0iMjAwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNDAiIHk9IjIwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjUwIiB5PSIyMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI3MCIgeT0iMjAwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyODAiIHk9IjIwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjkwIiB5PSIyMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMwMCIgeT0iMjAwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzNTAiIHk9IjIwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzYwIiB5PSIyMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjUwIiB5PSIyMTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjcwIiB5PSIyMTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjkwIiB5PSIyMTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjExMCIgeT0iMjEwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMzAiIHk9IjIxMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTUwIiB5PSIyMTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE2MCIgeT0iMjEwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNzAiIHk9IjIxMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTkwIiB5PSIyMTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIwMCIgeT0iMjEwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMTAiIHk9IjIxMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjIwIiB5PSIyMTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI0MCIgeT0iMjEwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNTAiIHk9IjIxMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjYwIiB5PSIyMTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMwMCIgeT0iMjEwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzNDAiIHk9IjIxMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzYwIiB5PSIyMTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjQwIiB5PSIyMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjYwIiB5PSIyMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjgwIiB5PSIyMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjEwMCIgeT0iMjIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMjAiIHk9IjIyMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTQwIiB5PSIyMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE1MCIgeT0iMjIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxOTAiIHk9IjIyMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjAwIiB5PSIyMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIyMCIgeT0iMjIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMDAiIHk9IjIyMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzEwIiB5PSIyMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMzMCIgeT0iMjIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzNTAiIHk9IjIyMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzYwIiB5PSIyMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjUwIiB5PSIyMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjcwIiB5PSIyMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjkwIiB5PSIyMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjExMCIgeT0iMjMwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMzAiIHk9IjIzMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTUwIiB5PSIyMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE2MCIgeT0iMjMwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNzAiIHk9IjIzMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjAwIiB5PSIyMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIxMCIgeT0iMjMwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNDAiIHk9IjIzMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjUwIiB5PSIyMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI3MCIgeT0iMjMwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyOTAiIHk9IjIzMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzAwIiB5PSIyMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMxMCIgeT0iMjMwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMzAiIHk9IjIzMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzUwIiB5PSIyMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjQwIiB5PSIyNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjYwIiB5PSIyNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjgwIiB5PSIyNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjEwMCIgeT0iMjQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMjAiIHk9IjI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTQwIiB5PSIyNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE1MCIgeT0iMjQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxODAiIHk9IjI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTkwIiB5PSIyNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIxMCIgeT0iMjQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMzAiIHk9IjI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjQwIiB5PSIyNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI1MCIgeT0iMjQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNzAiIHk9IjI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjgwIiB5PSIyNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI5MCIgeT0iMjQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMDAiIHk9IjI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzEwIiB5PSIyNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjM1MCIgeT0iMjQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzNjAiIHk9IjI0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iNTAiIHk9IjI1MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iNzAiIHk9IjI1MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iOTAiIHk9IjI1MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTEwIiB5PSIyNTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjEzMCIgeT0iMjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNTAiIHk9IjI1MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTYwIiB5PSIyNTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE3MCIgeT0iMjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxODAiIHk9IjI1MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTkwIiB5PSIyNTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIxMCIgeT0iMjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMjAiIHk9IjI1MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjgwIiB5PSIyNTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI5MCIgeT0iMjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMDAiIHk9IjI1MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzQwIiB5PSIyNTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjM2MCIgeT0iMjUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI0MCIgeT0iMjYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI2MCIgeT0iMjYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI4MCIgeT0iMjYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMDAiIHk9IjI2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTIwIiB5PSIyNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE0MCIgeT0iMjYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNTAiIHk9IjI2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTgwIiB5PSIyNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIyMCIgeT0iMjYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNjAiIHk9IjI2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzEwIiB5PSIyNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMyMCIgeT0iMjYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMzAiIHk9IjI2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzUwIiB5PSIyNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjM2MCIgeT0iMjYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI1MCIgeT0iMjcwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI3MCIgeT0iMjcwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI5MCIgeT0iMjcwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMTAiIHk9IjI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTMwIiB5PSIyNzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE1MCIgeT0iMjcwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNjAiIHk9IjI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTcwIiB5PSIyNzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE4MCIgeT0iMjcwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxOTAiIHk9IjI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjEwIiB5PSIyNzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI0MCIgeT0iMjcwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNTAiIHk9IjI3MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzEwIiB5PSIyNzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjM1MCIgeT0iMjcwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI0MCIgeT0iMjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI2MCIgeT0iMjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI4MCIgeT0iMjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMDAiIHk9IjI4MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTIwIiB5PSIyODAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE0MCIgeT0iMjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMDAiIHk9IjI4MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjEwIiB5PSIyODAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIyMCIgeT0iMjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMzAiIHk9IjI4MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjQwIiB5PSIyODAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI1MCIgeT0iMjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNzAiIHk9IjI4MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjgwIiB5PSIyODAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI5MCIgeT0iMjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMDAiIHk9IjI4MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzEwIiB5PSIyODAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMyMCIgeT0iMjgwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMzAiIHk9IjI4MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTIwIiB5PSIyOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjEzMCIgeT0iMjkwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNTAiIHk9IjI5MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTkwIiB5PSIyOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIwMCIgeT0iMjkwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNDAiIHk9IjI5MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjUwIiB5PSIyOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI2MCIgeT0iMjkwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNzAiIHk9IjI5MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjgwIiB5PSIyOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMyMCIgeT0iMjkwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzNTAiIHk9IjI5MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzYwIiB5PSIyOTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjQwIiB5PSIzMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjUwIiB5PSIzMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjYwIiB5PSIzMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjcwIiB5PSIzMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjgwIiB5PSIzMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjkwIiB5PSIzMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjEwMCIgeT0iMzAwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMjAiIHk9IjMwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTQwIiB5PSIzMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE3MCIgeT0iMzAwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxODAiIHk9IjMwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTkwIiB5PSIzMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIwMCIgeT0iMzAwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMTAiIHk9IjMwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjcwIiB5PSIzMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI4MCIgeT0iMzAwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMDAiIHk9IjMwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzIwIiB5PSIzMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjM0MCIgeT0iMzAwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzNTAiIHk9IjMwMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzYwIiB5PSIzMDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjQwIiB5PSIzMTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjEwMCIgeT0iMzEwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMzAiIHk9IjMxMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTUwIiB5PSIzMTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE2MCIgeT0iMzEwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNzAiIHk9IjMxMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTgwIiB5PSIzMTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIwMCIgeT0iMzEwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMTAiIHk9IjMxMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjIwIiB5PSIzMTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjIzMCIgeT0iMzEwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNTAiIHk9IjMxMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjYwIiB5PSIzMTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI4MCIgeT0iMzEwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMjAiIHk9IjMxMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzUwIiB5PSIzMTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjM2MCIgeT0iMzEwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI0MCIgeT0iMzIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI2MCIgeT0iMzIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI3MCIgeT0iMzIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSI4MCIgeT0iMzIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMDAiIHk9IjMyMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTQwIiB5PSIzMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE1MCIgeT0iMzIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNjAiIHk9IjMyMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTgwIiB5PSIzMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE5MCIgeT0iMzIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMjAiIHk9IjMyMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjMwIiB5PSIzMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI0MCIgeT0iMzIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNTAiIHk9IjMyMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjgwIiB5PSIzMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI5MCIgeT0iMzIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMDAiIHk9IjMyMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzEwIiB5PSIzMjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMyMCIgeT0iMzIwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzNjAiIHk9IjMyMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iNDAiIHk9IjMzMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iNjAiIHk9IjMzMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iNzAiIHk9IjMzMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iODAiIHk9IjMzMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTAwIiB5PSIzMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjEzMCIgeT0iMzMwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNzAiIHk9IjMzMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTkwIiB5PSIzMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI0MCIgeT0iMzMwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNTAiIHk9IjMzMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzEwIiB5PSIzMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMyMCIgeT0iMzMwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMzAiIHk9IjMzMCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzYwIiB5PSIzMzAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjQwIiB5PSIzNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjYwIiB5PSIzNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjcwIiB5PSIzNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjgwIiB5PSIzNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjEwMCIgeT0iMzQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMjAiIHk9IjM0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTQwIiB5PSIzNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE1MCIgeT0iMzQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNjAiIHk9IjM0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTcwIiB5PSIzNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE4MCIgeT0iMzQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMTAiIHk9IjM0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjQwIiB5PSIzNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI1MCIgeT0iMzQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNjAiIHk9IjM0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjgwIiB5PSIzNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI5MCIgeT0iMzQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzMTAiIHk9IjM0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzIwIiB5PSIzNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMzMCIgeT0iMzQwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzNDAiIHk9IjM0MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMzYwIiB5PSIzNDAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjQwIiB5PSIzNTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjEwMCIgeT0iMzUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxMzAiIHk9IjM1MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTUwIiB5PSIzNTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE4MCIgeT0iMzUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxOTAiIHk9IjM1MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjQwIiB5PSIzNTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI1MCIgeT0iMzUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNzAiIHk9IjM1MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjgwIiB5PSIzNTAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjMyMCIgeT0iMzUwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzNTAiIHk9IjM1MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iNDAiIHk9IjM2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iNTAiIHk9IjM2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iNjAiIHk9IjM2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iNzAiIHk9IjM2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iODAiIHk9IjM2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iOTAiIHk9IjM2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTAwIiB5PSIzNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE0MCIgeT0iMzYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIxNTAiIHk9IjM2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMTYwIiB5PSIzNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjE4MCIgeT0iMzYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyMDAiIHk9IjM2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjMwIiB5PSIzNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI0MCIgeT0iMzYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyNTAiIHk9IjM2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjYwIiB5PSIzNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjI3MCIgeT0iMzYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIyODAiIHk9IjM2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PHJlY3QgeD0iMjkwIiB5PSIzNjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIvPjxyZWN0IHg9IjM1MCIgeT0iMzYwIiB3aWR0aD0iMTAiIGhlaWdodD0iMTAiLz48cmVjdCB4PSIzNjAiIHk9IjM2MCIgd2lkdGg9IjEwIiBoZWlnaHQ9IjEwIi8+PC9nPjwvc3ZnPg==';
  const appUrl = 'https://takashimoriwaki-a11y.github.io/hinata-app/';
  const html = `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ひなたアプリ QRコード</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{background:#ffe0b2;font-family:'Hiragino Sans',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}
.card{background:white;border-radius:24px;padding:32px 28px;max-width:420px;width:100%;text-align:center;box-shadow:0 4px 24px rgba(0,0,0,0.12);}
.badge{background:#92400e;color:white;font-size:12px;font-weight:bold;padding:5px 14px;border-radius:20px;display:inline-block;margin-bottom:10px;}
h1{font-size:18px;color:#92400e;font-weight:bold;margin-bottom:4px;}
.sub{font-size:12px;color:#78716c;margin-bottom:20px;}
.qr-wrap{display:flex;justify-content:center;margin-bottom:18px;padding:12px;border:3px solid #d97706;border-radius:12px;background:white;}
.qr-wrap img{width:100%;max-width:300px;height:auto;display:block;}
.url-box{background:#fef3c7;border:1px solid #f59e0b;border-radius:12px;padding:12px;margin-bottom:14px;font-size:13px;color:#1d4ed8;word-break:break-all;text-decoration:none;display:block;}
.note{font-size:12px;color:#78716c;line-height:1.8;}
</style>
</head>
<body>
<div class="card">
  <div class="badge">こころのひなた</div>
  <h1>契約・看護記録Ⅰアプリ</h1>
  <p class="sub">職員専用アクセス</p>
  <div class="qr-wrap">
    <img src="data:image/svg+xml;base64,${svgB64}" alt="QRコード">
  </div>
  <a href="${appUrl}" class="url-box">${appUrl}</a>
  <p class="note">
    📱 iPhoneはカメラでQRを読み取るか上のURLをタップ<br>
    💻 PCは上のURLをブラウザにコピー<br>
    🔑 @kokoronohinata.com アカウントのみログイン可
  </p>
</div>
</body>
</html>`;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

// 未定義ルートは404
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// ===== QRコード生成エンドポイント =====
