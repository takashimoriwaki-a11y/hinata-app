const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));

// ===== Anthropic API プロキシ =====
app.post('/api/claude', async (req, res) => {
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(req.body),
    });
    const text = await response.text();
    console.log('API response status:', response.status);
    res.status(response.status).set('Content-Type', 'application/json').send(text);
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ===== Google Drive アップロード ＋ Chat通知 =====
app.post('/api/upload-photos', async (req, res) => {
  try {
    const { userName, photos } = req.body;
    if (!photos || photos.length === 0) return res.status(400).json({ error: '写真がありません' });

    const serviceAccount = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    const folderId = process.env.GOOGLE_DRIVE_FOLDER_ID;
    const webhookUrl = process.env.GOOGLE_CHAT_WEBHOOK_URL;

    const token = await getAccessToken(serviceAccount);
    const userFolderId = await getOrCreateFolder(token, folderId, userName || '不明');

    const uploadedFiles = [];
    for (const photo of photos) {
      const fileId = await uploadFile(token, userFolderId, photo.label, photo.data, photo.mimeType);
      uploadedFiles.push({ label: photo.label, url: `https://drive.google.com/file/d/${fileId}/view` });
      console.log(`アップロード完了: ${photo.label}`);
    }

    const folderUrl = `https://drive.google.com/drive/folders/${userFolderId}`;

    if (webhookUrl) {
      const message = {
        text: `📋 *${userName || '利用者'}* さんの書類写真が届きました\n\n` +
          uploadedFiles.map(f => `・${f.label}`).join('\n') +
          `\n\n📁 フォルダを開く: ${folderUrl}`
      };
      await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(message),
      });
      console.log('Chat通知送信完了');
    }

    res.json({ success: true, folderUrl, files: uploadedFiles });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ===== ヘルパー関数 =====
async function getAccessToken(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: serviceAccount.client_email,
    scope: 'https://www.googleapis.com/auth/drive',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now,
  })).toString('base64url');

  const signingInput = `${header}.${payload}`;
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(signingInput);
  const signature = sign.sign(serviceAccount.private_key, 'base64url');
  const jwt = `${signingInput}.${signature}`;

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });
  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) throw new Error('アクセストークン取得失敗: ' + JSON.stringify(tokenData));
  return tokenData.access_token;
}

async function getOrCreateFolder(token, parentId, folderName) {
  // 共有ドライブ対応: supportsAllDrives=true を追加
  const safeName = folderName.replace(/'/g, "\\'");
  const searchRes = await fetch(
    `https://www.googleapis.com/drive/v3/files?q=name='${safeName}' and '${parentId}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false&supportsAllDrives=true&includeItemsFromAllDrives=true`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  const searchData = await searchRes.json();
  if (searchData.files && searchData.files.length > 0) {
    return searchData.files[0].id;
  }

  const createRes = await fetch('https://www.googleapis.com/drive/v3/files?supportsAllDrives=true', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: folderName,
      mimeType: 'application/vnd.google-apps.folder',
      parents: [parentId],
    }),
  });
  const createData = await createRes.json();
  if (!createData.id) throw new Error('フォルダ作成失敗: ' + JSON.stringify(createData));
  return createData.id;
}

async function uploadFile(token, folderId, fileName, base64Data, mimeType) {
  const boundary = 'boundary_hinata_' + Date.now();
  const metadata = JSON.stringify({ name: fileName, parents: [folderId] });

  const body = [
    `--${boundary}`,
    'Content-Type: application/json; charset=UTF-8',
    '',
    metadata,
    `--${boundary}`,
    `Content-Type: ${mimeType}`,
    'Content-Transfer-Encoding: base64',
    '',
    base64Data,
    `--${boundary}--`,
  ].join('\r\n');

  const uploadRes = await fetch(
    'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&supportsAllDrives=true',
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': `multipart/related; boundary="${boundary}"`,
      },
      body,
    }
  );
  const uploadData = await uploadRes.json();
  if (!uploadData.id) throw new Error('ファイルアップロード失敗: ' + JSON.stringify(uploadData));
  return uploadData.id;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
