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
    res.status(response.status).set('Content-Type', 'application/json').send(text);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== Google Drive アップロード =====
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
    }

    const folderUrl = `https://drive.google.com/drive/folders/${userFolderId}`;
    if (webhookUrl) {
      await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: `📋 *${userName || '利用者'}* さんの書類写真が届きました\n\n` + uploadedFiles.map(f => `・${f.label}`).join('\n') + `\n\n📁 ${folderUrl}` }),
      });
    }
    res.json({ success: true, folderUrl, files: uploadedFiles });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== Google Sheets 転記 =====
app.post('/api/sheets-update', async (req, res) => {
  try {
    const { userName, contractData, emergencyData } = req.body;
    if (!userName) return res.status(400).json({ error: '利用者名が必要です' });

    const sheetsId = process.env.GOOGLE_SHEETS_ID;
    if (!sheetsId) return res.status(500).json({ error: 'GOOGLE_SHEETS_ID が未設定です' });

    const serviceAccount = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    const token = await getAccessTokenForSheets(serviceAccount);

    const spreadsheet = await sheetsGet(token, sheetsId);
    const existingSheet = spreadsheet.sheets.find(s => s.properties.title === userName);

    if (!existingSheet) {
      await sheetsAddSheet(token, sheetsId, userName);
    } else {
      await sheetsClear(token, sheetsId, userName);
    }

    const { rows, validations } = buildRows(contractData || {}, emergencyData || {});
    await sheetsWrite(token, sheetsId, userName, rows);

    const sheetId = existingSheet
      ? existingSheet.properties.sheetId
      : await getSheetId(token, sheetsId, userName);

    await sheetsFormatAndValidate(token, sheetsId, sheetId, rows, validations);

    const url = `https://docs.google.com/spreadsheets/d/${sheetsId}/edit#gid=${sheetId}`;
    res.json({ success: true, url });
  } catch (err) {
    console.error('Sheets error:', err);
    res.status(500).json({ error: err.message });
  }
});


// ===== 転記データ構築 =====
function buildRows(c, e) {
  const bi = c.basicInfo || {};
  const rows = [];
  const validations = [];
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

  // 1. 基本情報
  SEC('■ 基本情報');
  R('氏名', bi.userName);
  R('契約日', bi.contractDate);
  R('生年月日', bi.birthDate);
  R('電話番号', bi.phone);
  R('携帯電話', bi.mobilePhone);
  R('住所', bi.address);
  R('訪問先住所', bi.visitAddress);
  B();

  // 2. 訪問看護（保険種別）
  SEC('■ 訪問看護（保険種別）');
  R('保険種別', c.visitType, ['自立支援', '医療保険', '介護保険', '自費']);
  B();

  // 3. 生活保護
  SEC('■ 生活保護');
  R('生活保護', c.welfare, ['該当', '非該当']);
  B();

  // 4. 訪問先
  SEC('■ 訪問先');
  R('訪問先', c.visitPlace, ['自宅', '施設', 'その他']);
  R('訪問先（その他詳細）', c.visitPlaceOther);
  B();

  // 5. 担当チームとスタッフ
  SEC('■ 担当チームとスタッフ');
  R('担当チーム', c.team, ['身体チーム', '天理チーム', '北部チーム', '南部チーム']);
  R('担当スタッフ', c.staff);
  B();

  // 6. 交通費
  SEC('■ 交通費');
  R('交通費', c.transport, ['有', '無']);
  B();

  // 7. 加算・書類
  SEC('■ 加算・書類');
  R('重要事項説明書', c.importantDoc, ['済', '未']);
  R('24時間対応体制加算', c.addition24h, ['有', '無']);
  R('複数名訪問加算', c.additionMultiple, ['有', '無']);
  R('特別管理加算', c.additionSpecial, ['有', '無']);
  R('　特別管理疾患（有の場合）', c.additionSpecialDisease);
  R('医療保険証', c.insuranceCard, ['有', '無', '不要']);
  R('介護保険証', c.careInsurance, ['有', '無']);
  R('負担割合証', c.burdenRatio, ['有', '無']);
  R('限度額認定証', c.limitAmount, ['有', '無']);
  const handbookCount = Math.max((c.handbooks || []).length, 1);
  for (let i = 0; i < handbookCount; i++) {
    const hb = (c.handbooks || [])[i] || {};
    R(`手帳${i + 1}`, hb.status, ['有', '無', '未']);
  }
  B();

  // 自立支援医療
  SEC('■ 自立支援医療');
  R('自立支援', c.selfSupport, ['有', '無']);
  R('種別', c.selfSupportMode, ['新規', '追加']);
  SUB('【新規】');
  R('　申請者', c.ssApplicant, ['本人', '家族', 'ひなた', 'その他']);
  R('　申請者（その他）', c.ssSubmitterOther);
  R('　提出者', c.ssSubmitter, ['本人', '家族', 'ひなた', 'その他']);
  R('　提出予定日', c.ssSubmitDate);
  R('　書類の場所', c.ssDocLocation, ['本人', '家族', 'ひなた', 'その他']);
  R('　書類の場所（その他）', c.ssDocLocationOther);
  R('　診断書の説明', c.ssDiagExplain, ['済', '未']);
  R('　診断書の依頼先', c.ssDiagRequest);
  R('　診断書の依頼状況', c.ssDiagRequestStatus, ['済', '予定', '未確定']);
  R('　薬局確認', c.ssPharmacyCheck, ['済', '未']);
  R('　備考', c.ssNote);
  SUB('【追加】');
  R('　申請者', c.ssAddApplicant, ['本人', '家族', 'ひなた', 'その他']);
  R('　提出者', c.ssAddSubmitter, ['本人', '家族', 'ひなた', 'その他']);
  R('　提出予定日', c.ssAddSubmitDate);
  R('　書類の場所', c.ssAddDocLocation, ['本人', '家族', 'ひなた', 'その他']);
  R('　書類の場所（その他）', c.ssAddDocLocationOther);
  R('　備考', c.ssAddNote);
  B();

  // 8. アプラス用紙
  SEC('■ アプラス用紙');
  R('アプラス用紙', c.aplus, ['未', '済', '生活保護']);
  R('　備考', c.aplusNote);
  B();

  // 9. 訪問看護指示書
  SEC('■ 訪問看護指示書の依頼');
  R('指示書', c.instruction, ['済', '未']);
  R('依頼先（医療機関）', c.instructionDest);
  R('主治医', c.instructionDoctor);
  R('依頼日', c.instructionDate);
  R('指示書開始日', c.instructionStart);
  R('依頼理由', c.instructionReason);
  B();

  // 10. 正式な名前の書体
  SEC('■ 正式な名前の書体');
  R('書体確認', c.namestyle, ['必要', '不必要']);
  R('漢字', c.namestyleKanji);
  B();

  // 11. 次回受診日
  SEC('■ 各病院の次回受診日');
  const visits = (c.nextVisits && c.nextVisits.length > 0) ? c.nextVisits : [{ hospital: '', doctor: '', date: '', undecided: false }];
  visits.forEach((v, i) => {
    SUB(`病院${i + 1}`);
    R('　医療機関名', v.hospital);
    R('　主治医', v.doctor);
    R('　次回受診日', v.undecided ? '未定' : (v.date || ''));
    R('　未定フラグ', v.undecided ? '未定' : '', ['未定', '']);
  });
  B();

  // 12. 申し送り事項
  SEC('■ 申し送り事項');
  R('申し送り', c.handover);
  B();

  // 注意事項
  SEC('■ 注意事項');
  R('訪問時間指定あり', c.cautionVisitTime ? '有' : '', ['有', '']);
  R('チーム指定あり', c.cautionTeam ? '有' : '', ['有', '']);
  R('滞在時間指定あり', c.cautionStayTime ? '有' : '', ['有', '']);
  R('介護保険看護師同行', c.cautionCareInsNurse ? '有' : '', ['有', '']);
  R('介護保険帳票記載', c.cautionCareInsReport ? '有' : '', ['有', '']);
  B();

  // 13. 緊急連絡先
  SEC('■ 緊急連絡先');

  SUB('【家族】');
  R('家族連絡先', e.familyMode, ['有', '無']);
  const families = (e.family && e.family.length > 0) ? e.family : [{ name: '', relation: '', relationOther: '', phone: '', mobilePhone: '', note: '' }];
  families.forEach((f, i) => {
    SUB(`家族${i + 1}`);
    R('　氏名', f.name);
    R('　続柄', f.relation, ['父', '母', '兄弟', '姉妹', '長男', '次男', '三男', '長女', '次女', '三女', '祖父', '祖母', 'その他']);
    R('　続柄（その他）', f.relationOther);
    R('　電話', f.phone);
    R('　携帯', f.mobilePhone);
    R('　備考', f.note);
  });

  SUB('【その他連絡先】');
  R('その他連絡先', e.otherContactMode, ['有', '無']);
  const others = (e.otherContacts && e.otherContacts.length > 0) ? e.otherContacts : [{ name: '', relation: '', relationOther: '', phone: '', mobilePhone: '', note: '' }];
  others.forEach((f, i) => {
    SUB(`連絡先${i + 1}`);
    R('　氏名', f.name);
    R('　続柄', f.relation, ['父', '母', '兄弟', '姉妹', '長男', '次男', '三男', '長女', '次女', '三女', '祖父', '祖母', 'その他']);
    R('　続柄（その他）', f.relationOther);
    R('　電話', f.phone);
    R('　携帯', f.mobilePhone);
    R('　備考', f.note);
  });

  SUB('【主治医】');
  const doc = e.doctor || {};
  R('医療機関', doc.hospital);
  R('主治医名', doc.doctorName);

  SUB('【支援者】');
  const supporters = (e.supporters && e.supporters.length > 0) ? e.supporters : [{ role: '', roleOther: '', name: '', phone: '', note: '' }];
  supporters.forEach((s, i) => {
    SUB(`支援者${i + 1}`);
    R('　役割', s.role, ['PSW', 'ケアマネ', '地域包括', 'ヘルパー', '作業所（職場）', 'デイサービス・デイケア', 'その他']);
    R('　役割（その他）', s.roleOther);
    R('　氏名', s.name);
    R('　電話', s.phone);
    R('　備考', s.note);
  });

  return { rows, validations };
}

// ===== Sheets API ヘルパー =====
async function getAccessTokenForSheets(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: serviceAccount.client_email,
    scope: 'https://www.googleapis.com/auth/spreadsheets https://www.googleapis.com/auth/drive',
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
  if (!tokenData.access_token) throw new Error('トークン取得失敗: ' + JSON.stringify(tokenData));
  return tokenData.access_token;
}

async function sheetsGet(token, spreadsheetId) {
  const res = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const data = await res.json();
  if (!data.sheets) throw new Error('スプレッドシート取得失敗: ' + JSON.stringify(data));
  return data;
}

async function sheetsAddSheet(token, spreadsheetId, title) {
  const res = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}:batchUpdate`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ requests: [{ addSheet: { properties: { title } } }] }),
  });
  const data = await res.json();
  if (data.error) throw new Error('シート追加失敗: ' + JSON.stringify(data.error));
}

async function sheetsClear(token, spreadsheetId, sheetName) {
  const range = encodeURIComponent(`${sheetName}!A1:Z2000`);
  await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${range}:clear`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  });
}

async function sheetsWrite(token, spreadsheetId, sheetName, rows) {
  const values = rows.map(row =>
    row.map(cell => (typeof cell === 'object' && cell !== null ? (cell.v ?? '') : (cell ?? '')))
  );
  const range = encodeURIComponent(`${sheetName}!A1`);
  const res = await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${range}?valueInputOption=USER_ENTERED`,
    {
      method: 'PUT',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ values }),
    }
  );
  const data = await res.json();
  if (data.error) throw new Error('データ書き込み失敗: ' + JSON.stringify(data.error));
}

async function getSheetId(token, spreadsheetId, sheetName) {
  const spreadsheet = await sheetsGet(token, spreadsheetId);
  const sheet = spreadsheet.sheets.find(s => s.properties.title === sheetName);
  if (!sheet) throw new Error('シートが見つかりません: ' + sheetName);
  return sheet.properties.sheetId;
}

async function sheetsFormatAndValidate(token, spreadsheetId, sheetId, rows, validations) {
  const requests = [];

  // 列幅
  requests.push({ updateDimensionProperties: { range: { sheetId, dimension: 'COLUMNS', startIndex: 0, endIndex: 1 }, properties: { pixelSize: 200 }, fields: 'pixelSize' } });
  requests.push({ updateDimensionProperties: { range: { sheetId, dimension: 'COLUMNS', startIndex: 1, endIndex: 2 }, properties: { pixelSize: 380 }, fields: 'pixelSize' } });

  // 全体: 折り返し + フォント
  requests.push({
    repeatCell: {
      range: { sheetId, startRowIndex: 0, endRowIndex: rows.length, startColumnIndex: 0, endColumnIndex: 2 },
      cell: { userEnteredFormat: { wrapStrategy: 'WRAP', textFormat: { fontSize: 10 }, verticalAlignment: 'MIDDLE' } },
      fields: 'userEnteredFormat(wrapStrategy,textFormat,verticalAlignment)',
    },
  });

  rows.forEach((row, rowIndex) => {
    const cell0 = row[0];
    if (typeof cell0 !== 'object' || cell0 === null) return;

    // セクションヘッダー（濃紺・結合）
    if (cell0.merge && cell0.bg === '#1e3a5f') {
      requests.push({ mergeCells: { range: { sheetId, startRowIndex: rowIndex, endRowIndex: rowIndex + 1, startColumnIndex: 0, endColumnIndex: 2 }, mergeType: 'MERGE_ALL' } });
      requests.push({ repeatCell: { range: { sheetId, startRowIndex: rowIndex, endRowIndex: rowIndex + 1, startColumnIndex: 0, endColumnIndex: 2 }, cell: { userEnteredFormat: { backgroundColor: hexToRgb('#1e3a5f'), textFormat: { bold: true, foregroundColor: hexToRgb('#ffffff'), fontSize: 11 }, wrapStrategy: 'WRAP' } }, fields: 'userEnteredFormat(backgroundColor,textFormat,wrapStrategy)' } });
    }

    // サブヘッダー（水色・結合）
    if (cell0.merge && cell0.bg === '#e3f2fd') {
      requests.push({ mergeCells: { range: { sheetId, startRowIndex: rowIndex, endRowIndex: rowIndex + 1, startColumnIndex: 0, endColumnIndex: 2 }, mergeType: 'MERGE_ALL' } });
      requests.push({ repeatCell: { range: { sheetId, startRowIndex: rowIndex, endRowIndex: rowIndex + 1, startColumnIndex: 0, endColumnIndex: 2 }, cell: { userEnteredFormat: { backgroundColor: hexToRgb('#e3f2fd'), textFormat: { bold: true, foregroundColor: hexToRgb('#1565c0'), fontSize: 10 }, wrapStrategy: 'WRAP' } }, fields: 'userEnteredFormat(backgroundColor,textFormat,wrapStrategy)' } });
    }

    // ラベルセル
    if (cell0.label) {
      requests.push({ repeatCell: { range: { sheetId, startRowIndex: rowIndex, endRowIndex: rowIndex + 1, startColumnIndex: 0, endColumnIndex: 1 }, cell: { userEnteredFormat: { backgroundColor: hexToRgb('#f5f5f5'), textFormat: { foregroundColor: hexToRgb('#424242') } } }, fields: 'userEnteredFormat(backgroundColor,textFormat)' } });
      requests.push({ repeatCell: { range: { sheetId, startRowIndex: rowIndex, endRowIndex: rowIndex + 1, startColumnIndex: 1, endColumnIndex: 2 }, cell: { userEnteredFormat: { backgroundColor: hexToRgb('#ffffff') } }, fields: 'userEnteredFormat.backgroundColor' } });
    }
  });

  // プルダウン設定
  validations.forEach(({ row, col, values }) => {
    requests.push({
      setDataValidation: {
        range: { sheetId, startRowIndex: row, endRowIndex: row + 1, startColumnIndex: col, endColumnIndex: col + 1 },
        rule: {
          condition: { type: 'ONE_OF_LIST', values: values.map(v => ({ userEnteredValue: v })) },
          showCustomUi: true,
          strict: false,
        },
      },
    });
  });

  // 枠線
  requests.push({
    updateBorders: {
      range: { sheetId, startRowIndex: 0, endRowIndex: rows.length, startColumnIndex: 0, endColumnIndex: 2 },
      top:    { style: 'SOLID', width: 1, color: hexToRgb('#bdbdbd') },
      bottom: { style: 'SOLID', width: 1, color: hexToRgb('#bdbdbd') },
      left:   { style: 'SOLID', width: 1, color: hexToRgb('#bdbdbd') },
      right:  { style: 'SOLID', width: 1, color: hexToRgb('#bdbdbd') },
      innerHorizontal: { style: 'SOLID', width: 1, color: hexToRgb('#e0e0e0') },
      innerVertical:   { style: 'SOLID', width: 2, color: hexToRgb('#9e9e9e') },
    },
  });

  if (requests.length === 0) return;
  const res = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}:batchUpdate`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ requests }),
  });
  const data = await res.json();
  if (data.error) console.error('書式設定エラー:', JSON.stringify(data.error));
}

function hexToRgb(hex) {
  const c = hex.replace('#', '');
  return { red: parseInt(c.substring(0,2),16)/255, green: parseInt(c.substring(2,4),16)/255, blue: parseInt(c.substring(4,6),16)/255 };
}

// ===== Drive ヘルパー =====
async function getAccessToken(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ iss: serviceAccount.client_email, scope: 'https://www.googleapis.com/auth/drive', aud: 'https://oauth2.googleapis.com/token', exp: now + 3600, iat: now })).toString('base64url');
  const signingInput = `${header}.${payload}`;
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(signingInput);
  const jwt = `${signingInput}.${sign.sign(serviceAccount.private_key, 'base64url')}`;
  const tokenRes = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}` });
  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) throw new Error('アクセストークン取得失敗: ' + JSON.stringify(tokenData));
  return tokenData.access_token;
}

async function getOrCreateFolder(token, parentId, folderName) {
  const safeName = folderName.replace(/'/g, "\\'");
  const searchRes = await fetch(`https://www.googleapis.com/drive/v3/files?q=name='${safeName}' and '${parentId}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false&supportsAllDrives=true&includeItemsFromAllDrives=true`, { headers: { Authorization: `Bearer ${token}` } });
  const searchData = await searchRes.json();
  if (searchData.files && searchData.files.length > 0) return searchData.files[0].id;
  const createRes = await fetch('https://www.googleapis.com/drive/v3/files?supportsAllDrives=true', { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ name: folderName, mimeType: 'application/vnd.google-apps.folder', parents: [parentId] }) });
  const createData = await createRes.json();
  if (!createData.id) throw new Error('フォルダ作成失敗');
  return createData.id;
}

async function uploadFile(token, folderId, fileName, base64Data, mimeType) {
  const boundary = 'boundary_hinata_' + Date.now();
  const metadata = JSON.stringify({ name: fileName, parents: [folderId] });
  const body = [`--${boundary}`, 'Content-Type: application/json; charset=UTF-8', '', metadata, `--${boundary}`, `Content-Type: ${mimeType}`, 'Content-Transfer-Encoding: base64', '', base64Data, `--${boundary}--`].join('\r\n');
  const uploadRes = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&supportsAllDrives=true', { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': `multipart/related; boundary="${boundary}"` }, body });
  const uploadData = await uploadRes.json();
  if (!uploadData.id) throw new Error('ファイルアップロード失敗');
  return uploadData.id;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
