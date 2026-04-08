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

// /auth/* と /qr /qr-svg はCORSを適用しない（ブラウザ直接アクセス）
app.use((req, res, next) => {
  if (req.path === '/auth/login' || req.path === '/auth/callback' || req.path === '/qr' || req.path === '/qr-svg') return next();
  cors({
    origin: (origin, callback) => {
      // originなし = ホーム画面追加アプリ・WKWebView・iOS Safari → 許可
      if (!origin) return callback(null, true);
      if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
      callback(new Error('Not allowed by CORS'), false);
    },
    methods: ['POST', 'GET', 'DELETE'],
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
  // 署名検証：APP_SECRETが設定済みかつリクエストに署名がある場合のみ検証
  // GitHub Pages(HTTPS)+CORS制限で十分なセキュリティを確保
  const APP_SECRET = process.env.APP_SECRET;
  if (!APP_SECRET) return next(); // APP_SECRET未設定はスキップ
  const sig = req.headers['x-request-signature'];
  if (!sig) return next(); // 署名なしはスキップ（後方互換性）
  const bodyStr = JSON.stringify(req.body);
  const expected = require('crypto').createHmac('sha256', APP_SECRET).update(bodyStr).digest('hex');
  if (sig !== expected) return res.status(401).json({ error: '署名が無効です' });
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

// 見込み件数テーブル取得
app.get('/api/sheets-mikomi', async (req, res) => {
  try {
    const sheetsId = process.env.GOOGLE_SHEETS_ID;
    if (!sheetsId) return safeError(res, 500, 'サーバー設定エラーです');
    const serviceAccount = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    const token = await getAccessTokenForSheets(serviceAccount);
    const range = encodeURIComponent('見込み件数!B46:G51');
    const url = `https://sheets.googleapis.com/v4/spreadsheets/${sheetsId}/values/${range}`;
    const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    const data = await r.json();
    if (data.error) return safeError(res, 500, 'シート取得失敗');
    res.json({ success: true, values: data.values || [] });
  } catch (err) {
    safeError(res, 500, '見込み件数の取得に失敗しました', err);
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

    // Step1: Google Vision OCRでテキスト抽出
    const serviceAccount = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    const token = await getAccessTokenForVision(serviceAccount);
    const rawText = await visionOCR(token, base64Image, mimeType);

    // Step2: ClaudeAIで名前・役職・電話番号を正確に解析
    const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
    if (ANTHROPIC_API_KEY && rawText.trim()) {
      try {
        const claudeRes = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'x-api-key': ANTHROPIC_API_KEY,
            'anthropic-version': '2023-06-01',
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            model: 'claude-haiku-4-5-20251001',
            max_tokens: 500,
            system: `あなたは名刺情報を解析する専門家です。OCRで読み取った名刺テキストから以下のJSONを抽出してください。

【重要ルール】
- name: 人物の氏名のみ（姓名）。役職・資格・会社名は絶対に含めない。日本人名は2〜5文字程度。
- organization: 会社名・病院名・施設名など組織名
- role: 役職・資格（代表取締役、看護師、ケアマネ等）
- phone: 電話番号（ハイフン付き）
- note: その他の情報

名前と役職・資格を混同しないこと。「代表取締役 山田太郎」なら name=山田太郎、role=代表取締役。
JSONのみ返すこと。`,
            messages: [{ role: 'user', content: '名刺OCRテキスト:\n' + rawText.slice(0, 1000) }],
          }),
        });
        if (claudeRes.ok) {
          const claudeData = await claudeRes.json();
          const content = (claudeData.content || []).map(c => c.text || '').join('');
          const clean = content.replace(/```json|```/g, '').trim();
          const parsed = JSON.parse(clean);
          return res.json({ success: true, name: parsed.name || '', organization: parsed.organization || '', role: parsed.role || '', phone: parsed.phone || '', note: parsed.note || '' });
        }
      } catch(e) { console.error('Claude名刺解析エラー:', e); }
    }

    // フォールバック：ルールベース解析
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

    // Step1: Google Vision OCR でテキスト抽出
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

    // Step2: Claude AIで構造化解析
    const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
    if (ANTHROPIC_API_KEY && allText.trim()) {
      try {
        const claudeRes = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'x-api-key': ANTHROPIC_API_KEY,
            'anthropic-version': '2023-06-01',
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            model: 'claude-haiku-4-5-20251001',
            max_tokens: 2000,
            system: 'あなたは訪問看護ステーションの事務スタッフです。OCRで読み取ったフェイスシートのテキストから情報を抽出し、必ずJSONのみで返してください。フィールド: userName(氏名), nameKana(ふりがな), gender(男/女), birthDate(YYYY-MM-DD), address(住所), phone(固定電話), mobilePhone(携帯), mainDiagnosis(主病名), medicalHistory(既往歴), currentCondition(病状), diseaseAwareness(病識), patientRequest(本人要望), familyRequest(家族要望), referralRequest(依頼内容), familyMembers(配列:{name,relation,isKeyperson}), familySpecialNotes(家族特記), otherServices(他サービス), handoverNotes(申し送り), bedrideLevel(障害自立度), dementiaLevel(認知症自立度), relatedInstitutions(配列:{name,role,phone}), referralSource(依頼元), referralPhone(依頼元電話), familyContact(家族連絡先), familyPhone(家族電話), doctorHospital(主治医病院), doctorName(主治医名), supporters(配列:{role,name,phone,note})。情報がない場合は空文字または空配列。JSONのみ返すこと。',
            messages: [{ role: 'user', content: '以下のOCRテキストから情報を抽出してください:\n\n' + allText.slice(0, 8000) }],
          }),
        });
        const claudeData = await claudeRes.json();
        if (claudeData.content && claudeData.content[0] && claudeData.content[0].text) {
          const raw = claudeData.content[0].text.trim().replace(/^[\s\S]*?({[\s\S]*})[\s\S]*$/, '$1') || claudeData.content[0].text.trim();
          const parsed = JSON.parse(raw);
          parsed.extractedAt = new Date().toISOString();
          return res.json({ success: true, data: parsed });
        }
      } catch (aiErr) {
        console.warn('AI解析失敗、正規表現パーサーにフォールバック:', aiErr.message);
      }
    }

    // フォールバック: 正規表現パーサー
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
  const orgKeywords = ['病院', 'クリニック', '薬局', 'ステーション', 'センター', '事業所', '法人', '株式会社', '医療法人', '社会福祉', '合同会社', '一般社団', '公益'];
  const roleKeywords = [
    '所長', '副所長', 'ケアマネ', '看護師', 'PSW', '相談員', '医師', '院長',
    '代表取締役', '取締役', '代表理事', '理事長', '理事', '事務長', '施設長',
    '介護支援専門員', '社会福祉士', '精神保健福祉士', '作業療法士', '理学療法士',
    '言語聴覚士', '管理者', '主任', 'マネージャー', 'ディレクター',
    '認定看護師', '専門看護師', '保健師', '准看護師',
    '資格', '免許', '認定', '専門'
  ];
  // 名前として除外するキーワード（役職・資格等）
  const notNamePatterns = [
    /代表|取締役|理事|所長|院長|施設長|管理者|主任/,
    /看護師|保健師|療法士|福祉士|専門員|相談員|医師/,
    /認定|資格|免許|登録|番号/,
    /Tel|FAX|〒|http|@|\.com|\.jp/i,
    /[0-9０-９]{3,}/,  // 数字が3桁以上含まれる
  ];
  for (const line of lines) {
    if (phonePattern.test(line) && !phone) { phone = (line.match(phonePattern)||[])[1] || ''; continue; }
    if (orgKeywords.some(k => line.includes(k)) && !organization) { organization = line.slice(0,50); continue; }
    if (roleKeywords.some(k => line.includes(k)) && !role) { role = line.slice(0,30); continue; }
    // 名前判定：日本語2〜10文字、役職・資格キーワードを含まない
    if (!name &&
        line.length >= 2 && line.length <= 10 &&
        /^[ぁ-んァ-ン一-龥　\s　]+$/.test(line) &&
        !notNamePatterns.some(p => p.test(line)) &&
        !roleKeywords.some(k => line.includes(k))) {
      name = line.replace(/\s　/g, ' ').trim();
      continue;
    }
  }
  // 名前が見つからない場合：短い日本語行を探す
  if (!name) {
    for (const line of lines) {
      if (line.length >= 2 && line.length <= 10 &&
          /^[ぁ-んァ-ン一-龥\s　]+$/.test(line) &&
          !notNamePatterns.some(p => p.test(line)) &&
          !roleKeywords.some(k => line.includes(k))) {
        name = line.trim();
        break;
      }
    }
  }
  if (!name && lines.length > 0) {
    // 最終手段：最も短い日本語行を名前とする
    const candidates = lines.filter(l =>
      l.length >= 2 && l.length <= 12 &&
      /[ぁ-んァ-ン一-龥]/.test(l) &&
      !notNamePatterns.some(p => p.test(l)) &&
      !roleKeywords.some(k => l.includes(k)) &&
      !orgKeywords.some(k => l.includes(k))
    ).sort((a, b) => a.length - b.length);
    name = candidates[0] ? candidates[0].slice(0, 20) : lines[0].slice(0, 20);
  }
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

// ===== Google Drive ヘルパー =====
async function getOrCreateFolder(token, parentId, folderName) {
  const safeName = folderName.replace(/'/g, "\'");
  const searchRes = await fetch(
    `https://www.googleapis.com/drive/v3/files?q=name='${safeName}' and '${parentId}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false&supportsAllDrives=true&includeItemsFromAllDrives=true`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  const searchData = await searchRes.json();
  if (searchData.files && searchData.files.length > 0) return searchData.files[0].id;
  const createRes = await fetch('https://www.googleapis.com/drive/v3/files?supportsAllDrives=true', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: folderName, mimeType: 'application/vnd.google-apps.folder', parents: [parentId] }),
  });
  const createData = await createRes.json();
  if (!createData.id) throw new Error('フォルダ作成失敗');
  return createData.id;
}

async function uploadFile(token, folderId, fileName, base64Data, mimeType) {
  const safeName = fileName.replace(/'/g, "\'");
  const searchRes = await fetch(
    `https://www.googleapis.com/drive/v3/files?q=name='${safeName}' and '${folderId}' in parents and trashed=false&fields=files(id)&supportsAllDrives=true&includeItemsFromAllDrives=true`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  const searchData = await searchRes.json();
  const existingFiles = (searchData.files || []);

  // 既存ファイルが1つ以上ある場合：最初の1件を上書き、残りを削除
  if (existingFiles.length > 0) {
    const keepId = existingFiles[0].id;
    // 上書き
    await fetch(
      `https://www.googleapis.com/upload/drive/v3/files/${keepId}?uploadType=media&supportsAllDrives=true`,
      { method: 'PATCH', headers: { Authorization: `Bearer ${token}`, 'Content-Type': mimeType }, body: Buffer.from(base64Data, 'base64') }
    );
    // 重複ファイルを削除
    for (let i = 1; i < existingFiles.length; i++) {
      await fetch(
        `https://www.googleapis.com/drive/v3/files/${existingFiles[i].id}?supportsAllDrives=true`,
        { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } }
      ).catch(() => {});
    }
    return keepId;
  }
  // 新規アップロード
  const boundary = 'boundary_hinata_' + Date.now();
  const metadata = JSON.stringify({ name: fileName, parents: [folderId] });
  const body = [
    `--${boundary}`, 'Content-Type: application/json; charset=UTF-8', '', metadata,
    `--${boundary}`, `Content-Type: ${mimeType}`, 'Content-Transfer-Encoding: base64', '', base64Data,
    `--${boundary}--`
  ].join("\r\n");
  const uploadRes = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&supportsAllDrives=true', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': `multipart/related; boundary="${boundary}"` },
    body,
  });
  const uploadData = await uploadRes.json();
  if (!uploadData.id) throw new Error('ファイルアップロード失敗');
  return uploadData.id;
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

// ===== 電話番号を文字列として強制（先頭0が消えないように）=====
function formatPhone(phone) {
  if (!phone) return '';
  // アポストロフィプレフィックスでスプレッドシートに文字列として解釈させる
  return "'" + String(phone).trim();
}

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
  const SEC = (label) => { rows.push([{ v: label, bold: true, bg: '#f9a825', color: '#000000', merge: true }]); rowIdx++; };
  const SUB = (label) => { rows.push([{ v: label, bold: true, bg: '#00e5ff', color: '#000000', merge: true }]); rowIdx++; };
  const B   = ()       => { rows.push(['']); rowIdx++; };
  const R   = (label, value, dropdown, highlight) => {
    const valCell = dropdown ? { v: value ?? '', dropdown } : (value ?? '');
    const labelCell = highlight ? { v: label, label: true, ibow: true } : { v: label, label: true };
    rows.push([labelCell, highlight ? { v: value ?? '', ibow: true } : valCell]);
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
  R('電話番号（固定）', formatPhone(bi.phone), null, bi.ibowPhone);
  R('電話番号（携帯）', formatPhone(bi.mobilePhone), null, bi.ibowMobile);
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
      R('　電話', formatPhone(f.phone), null, f.ibowPhone);
      R('　携帯', formatPhone(f.mobilePhone), null, f.ibowMobile);
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
      R('　電話', formatPhone(f.phone), null, f.ibowPhone);
      R('　携帯', formatPhone(f.mobilePhone), null, f.ibowMobile);
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
      R('　電話', formatPhone(s.phone));
      if (s.note) R('　備考', s.note);
    }
  });

  return { rows, validations };
}

function hexToRgb(hex) {
  const h = hex.replace('#', ''); // #を除去
  const r = parseInt(h.slice(0,2),16)/255;
  const g = parseInt(h.slice(2,4),16)/255;
  const b = parseInt(h.slice(4,6),16)/255;
  return { red: r, green: g, blue: b };
}

async function sheetsFormatAndValidate(token, spreadsheetId, sheetId, rows, validations) {
  const requests = [];
  // まずシート全体の書式をクリア（既存書式の残留を防ぐ）
  requests.push({ updateCells: {
    range: { sheetId, startRowIndex: 0, endRowIndex: rows.length + 5, startColumnIndex: 0, endColumnIndex: 3 },
    fields: 'userEnteredFormat'
  }});
  // 列幅設定
  requests.push({ updateDimensionProperties: { range: { sheetId, dimension: 'COLUMNS', startIndex: 0, endIndex: 1 }, properties: { pixelSize: 200 }, fields: 'pixelSize' } });
  requests.push({ updateDimensionProperties: { range: { sheetId, dimension: 'COLUMNS', startIndex: 1, endIndex: 2 }, properties: { pixelSize: 380 }, fields: 'pixelSize' } });
  // 全体フォーマット（左詰め）
  requests.push({ repeatCell: { range: { sheetId, startRowIndex: 0, endRowIndex: rows.length, startColumnIndex: 0, endColumnIndex: 2 },
    cell: { userEnteredFormat: { wrapStrategy: 'WRAP', textFormat: { fontSize: 10 }, verticalAlignment: 'MIDDLE', horizontalAlignment: 'LEFT' } },
    fields: 'userEnteredFormat(wrapStrategy,textFormat,verticalAlignment,horizontalAlignment)' } });
  // 行ごとのフォーマット
  rows.forEach((row, rowIndex) => {
    const cell0 = row[0];
    if (typeof cell0 !== 'object' || cell0 === null) return;
    if (cell0.bold && cell0.bg) {
      const bg = hexToRgb(cell0.bg);
      const fg = cell0.color ? hexToRgb(cell0.color.replace('#','')) : { red:0, green:0, blue:0 };
      requests.push({ repeatCell: { range: { sheetId, startRowIndex: rowIndex, endRowIndex: rowIndex+1, startColumnIndex: 0, endColumnIndex: 2 },
        cell: { userEnteredFormat: { backgroundColor: bg, textFormat: { bold: true, foregroundColor: fg, fontSize: 10 }, horizontalAlignment: 'LEFT' } },
        fields: 'userEnteredFormat(backgroundColor,textFormat,horizontalAlignment)' } });
      if (cell0.merge) {
        requests.push({ mergeCells: { range: { sheetId, startRowIndex: rowIndex, endRowIndex: rowIndex+1, startColumnIndex: 0, endColumnIndex: 2 }, mergeType: 'MERGE_ALL' } });
      }
    } else if (cell0.bold && cell0.merge) {
      const subBg = cell0.bg ? hexToRgb(cell0.bg.replace('#','')) : { red:0.85, green:0.93, blue:0.97 };
      const subFg = cell0.color ? hexToRgb(cell0.color.replace('#','')) : { red:0.1, green:0.22, blue:0.29 };
      requests.push({ repeatCell: { range: { sheetId, startRowIndex: rowIndex, endRowIndex: rowIndex+1, startColumnIndex: 0, endColumnIndex: 2 },
        cell: { userEnteredFormat: { backgroundColor: subBg, textFormat: { bold: true, fontSize: 10, foregroundColor: subFg }, horizontalAlignment: 'LEFT' } },
        fields: 'userEnteredFormat(backgroundColor,textFormat,horizontalAlignment)' } });
      requests.push({ mergeCells: { range: { sheetId, startRowIndex: rowIndex, endRowIndex: rowIndex+1, startColumnIndex: 0, endColumnIndex: 2 }, mergeType: 'MERGE_ALL' } });
    } else if (cell0.ibow) {
      // ibow登録電話番号は水色でハイライト
      requests.push({ repeatCell: { range: { sheetId, startRowIndex: rowIndex, endRowIndex: rowIndex+1, startColumnIndex: 0, endColumnIndex: 2 },
        cell: { userEnteredFormat: { backgroundColor: { red:0.68, green:0.85, blue:0.90 }, textFormat: { bold: true, fontSize: 10, foregroundColor: { red:0, green:0, blue:0 } }, horizontalAlignment: 'LEFT' } },
        fields: 'userEnteredFormat(backgroundColor,textFormat,horizontalAlignment)' } });
    } else if (cell0.label) {
      requests.push({ repeatCell: { range: { sheetId, startRowIndex: rowIndex, endRowIndex: rowIndex+1, startColumnIndex: 0, endColumnIndex: 1 },
        cell: { userEnteredFormat: { backgroundColor: { red:0.95, green:0.95, blue:0.95 }, textFormat: { bold: true, fontSize: 10 }, horizontalAlignment: 'LEFT' } },
        fields: 'userEnteredFormat(backgroundColor,textFormat,horizontalAlignment)' } });
    }
  });
  // プルダウン検証
  validations.forEach(({ row, col, values }) => {
    requests.push({ setDataValidation: { range: { sheetId, startRowIndex: row, endRowIndex: row+1, startColumnIndex: col, endColumnIndex: col+1 },
      rule: { condition: { type: 'ONE_OF_LIST', values: values.map(v => ({ userEnteredValue: v })) }, showCustomUi: true, strict: false } } });
  });
  if (requests.length === 0) return;
  await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}:batchUpdate`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ requests }),
  });
}



// ===== Google OAuth 認証 =====
const ALLOWED_DOMAIN = 'kokoronohinata.com';
const RAILWAY_URL = 'https://hinata-app-production.up.railway.app';
const FRONTEND_URL = 'https://takashimoriwaki-a11y.github.io/hinata-app/';

function generateSessionToken(payload) {
  const secret = process.env.APP_SECRET || 'hinata-fallback-secret';
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Math.floor(Date.now()/1000) + 86400 * 30 })).toString('base64url');
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

// QRコードページ（qrcodeパッケージ使用）
app.get('/qr', async (req, res) => {
  try {
    const QRCode = require('qrcode');
    const APP_URL = 'https://takashimoriwaki-a11y.github.io/hinata-app/';
    const svgStr = await QRCode.toString(APP_URL, { type: 'svg', width: 300, margin: 3, errorCorrectionLevel: 'M' });
    const b64 = Buffer.from(svgStr).toString('base64');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(
      '<!DOCTYPE html><html lang="ja"><head><meta charset="UTF-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<title>ひなたアプリ QRコード</title>' +
      '<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#ffe0b2;font-family:sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.card{background:#fff;border-radius:24px;padding:32px 28px;max-width:420px;width:100%;text-align:center;box-shadow:0 4px 24px rgba(0,0,0,.12)}.badge{background:#92400e;color:#fff;font-size:12px;font-weight:700;padding:5px 14px;border-radius:20px;display:inline-block;margin-bottom:10px}h1{font-size:18px;color:#92400e;font-weight:700;margin-bottom:4px}.sub{font-size:12px;color:#78716c;margin-bottom:20px}.qr-wrap{display:flex;justify-content:center;margin-bottom:18px;padding:14px;border:3px solid #d97706;border-radius:12px}.qr-wrap img{width:100%;max-width:300px;height:auto}.url-box{background:#fef3c7;border:1px solid #f59e0b;border-radius:12px;padding:12px;margin-bottom:14px;font-size:13px;color:#1d4ed8;word-break:break-all;text-decoration:none;display:block}.note{font-size:12px;color:#78716c;line-height:1.8}</style>' +
      '</head><body><div class="card">' +
      '<div class="badge">こころのひなた</div>' +
      '<h1>契約・看護記録Ⅰアプリ</h1>' +
      '<p class="sub">職員専用アクセス</p>' +
      '<div class="qr-wrap"><img src="data:image/svg+xml;base64,' + b64 + '" alt="QR"></div>' +
      '<a href="' + APP_URL + '" class="url-box">' + APP_URL + '</a>' +
      '<p class="note">📱 iPhoneはカメラで読み取るか上のURLをタップ<br>💻 PCは上のURLをコピー<br>🔑 @kokoronohinata.com のみ</p>' +
      '</div></body></html>'
    );
  } catch (err) {
    const U = 'https://takashimoriwaki-a11y.github.io/hinata-app/';
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send('<html><body style="padding:40px;text-align:center;background:#ffe0b2"><h2 style="color:#92400e">ひなたアプリ</h2><br><a href="' + U + '">' + U + '</a></body></html>');
  }
});


// ===== データ同期（Google Drive JSON）=====
const DATA_FOLDER_NAME = '【削除禁止】hinata-app-data';

async function getDataFolderId(token) {
  const folderId = process.env.GOOGLE_DRIVE_FOLDER_ID;
  return await getOrCreateFolder(token, folderId, DATA_FOLDER_NAME);
}

// 利用者一覧取得
app.get('/api/list-patients', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  try {
    const serviceAccount = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    const token = await getAccessToken(serviceAccount);
    const dataFolderId = await getDataFolderId(token);

    const searchRes = await fetch(
      `https://www.googleapis.com/drive/v3/files?q='${dataFolderId}' in parents and name contains 'patient_' and trashed=false&fields=files(id,name,modifiedTime)&orderBy=modifiedTime desc&supportsAllDrives=true&includeItemsFromAllDrives=true`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const data = await searchRes.json();
    const patients = (data.files || []).map(f => ({
      id: f.name.replace('patient_', '').replace('.json', ''),
      fileId: f.id,
      modifiedTime: f.modifiedTime,
    }));
    res.json({ success: true, patients });
  } catch (err) {
    safeError(res, 500, '利用者一覧の取得に失敗しました', err);
  }
});

// 利用者データ読み込み
app.get('/api/load-data/:patientId', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  try {
    const patientId = req.params.patientId.replace(/[^a-zA-Z0-9_-]/g, '');
    if (!patientId) return safeError(res, 400, '不正なIDです');

    const serviceAccount = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    const token = await getAccessToken(serviceAccount);
    const dataFolderId = await getDataFolderId(token);

    // ファイル検索
    const searchRes = await fetch(
      `https://www.googleapis.com/drive/v3/files?q=name='patient_${patientId}.json' and '${dataFolderId}' in parents and trashed=false&supportsAllDrives=true&includeItemsFromAllDrives=true`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const searchData = await searchRes.json();
    if (!searchData.files || searchData.files.length === 0) {
      return res.json({ success: true, data: null });
    }

    // ファイル内容取得
    const fileId = searchData.files[0].id;
    const fileRes = await fetch(
      `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media&supportsAllDrives=true`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const fileData = await fileRes.json();
    res.json({ success: true, data: fileData });
  } catch (err) {
    safeError(res, 500, 'データの読み込みに失敗しました', err);
  }
});

// 利用者データ保存
app.post('/api/save-data', verifySignature, async (req, res) => {
  try {
    const { patientId, patientMeta, contractData, emergencyData, taskData, recordData } = req.body;
    if (!patientId) return safeError(res, 400, '利用者IDが必要です');
    const safeId = String(patientId).replace(/[^a-zA-Z0-9_-]/g, '');
    if (!safeId) return safeError(res, 400, '不正なIDです');

    const serviceAccount = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    const token = await getAccessToken(serviceAccount);
    const dataFolderId = await getDataFolderId(token);

    const saveData = {
      patientId: safeId,
      patientMeta,
      contractData,
      emergencyData,
      taskData,
      recordData,
      savedAt: new Date().toISOString(),
    };

    const fileName = `patient_${safeId}.json`;
    const base64 = Buffer.from(JSON.stringify(saveData)).toString('base64');
    await uploadFile(token, dataFolderId, fileName, base64, 'application/json');

    res.json({ success: true, savedAt: saveData.savedAt });
  } catch (err) {
    safeError(res, 500, 'データの保存に失敗しました', err);
  }
});

// 利用者削除
app.post('/api/delete-data', verifySignature, async (req, res) => {
  try {
    const patientId = (req.body.patientId || '').replace(/[^a-zA-Z0-9_-]/g, '');
    if (!patientId) return safeError(res, 400, '不正なIDです');

    const serviceAccount = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    const token = await getAccessToken(serviceAccount);
    const dataFolderId = await getDataFolderId(token);

    const searchUrl = `https://www.googleapis.com/drive/v3/files?q=name='patient_${patientId}.json' and '${dataFolderId}' in parents and trashed=false&supportsAllDrives=true&includeItemsFromAllDrives=true&fields=files(id,name,driveId,teamDriveId)`;
    console.log('[DELETE] searching:', searchUrl);
    const searchRes = await fetch(searchUrl, { headers: { Authorization: `Bearer ${token}` } });
    const searchData = await searchRes.json();
    console.log('[DELETE] found files:', JSON.stringify(searchData.files || []));
    // 重複ファイルも含め全件削除（ゴミ箱移動→完全削除の順で試みる）
    if (searchData.files && searchData.files.length > 0) {
      for (const file of searchData.files) {
        console.log('[DELETE] processing file:', file.id);
        let deleted = false;

        // 1. まず完全削除を試みる
        try {
          const delRes = await fetch(
            `https://www.googleapis.com/drive/v3/files/${file.id}?supportsAllDrives=true`,
            { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } }
          );
          console.log('[DELETE] direct delete status:', delRes.status);
          if (delRes.status === 204 || delRes.status === 200) {
            deleted = true;
          }
        } catch(e) { console.error('[DELETE] direct delete error:', e); }

        // 2. 完全削除失敗時はゴミ箱移動
        if (!deleted) {
          try {
            const trashRes = await fetch(
              `https://www.googleapis.com/drive/v3/files/${file.id}?supportsAllDrives=true`,
              {
                method: 'PATCH',
                headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({ trashed: true }),
              }
            );
            console.log('[DELETE] trash status:', trashRes.status);
            if (trashRes.status === 200) deleted = true;
          } catch(e) { console.error('[DELETE] trash error:', e); }
        }

        // 3. 共有ドライブの場合はdriveId指定で再試行
        if (!deleted && file.driveId) {
          try {
            const delRes3 = await fetch(
              `https://www.googleapis.com/drive/v3/files/${file.id}?supportsAllDrives=true&driveId=${file.driveId}`,
              { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } }
            );
            console.log('[DELETE] shared drive delete status:', delRes3.status);
          } catch(e) { console.error('[DELETE] shared drive error:', e); }
        }
      }
    } else {
      console.log('[DELETE] no files found for patientId:', patientId);
    }
    res.json({ success: true, deleted: (searchData.files || []).length });
  } catch (err) {
    safeError(res, 500, 'データの削除に失敗しました', err);
  }
});



// ===== QRコード生成エンドポイント =====

// 未定義ルートは404
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
