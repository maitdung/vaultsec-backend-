// server.js
// Backend đơn giản: nhận file upload -> gửi lên VirusTotal -> trả kết quả quét.
// Không lưu file lâu dài, không log nội dung file.

require('dotenv').config();
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const VT_API_KEY = process.env.VT_API_KEY;

if (!VT_API_KEY) {
  console.error('LỖI: Thiếu VT_API_KEY trong file .env — vào VirusTotal lấy API key rồi điền vào .env');
  process.exit(1);
}

app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Giới hạn file 32MB (mức public API của VirusTotal cho upload trực tiếp)
const upload = multer({
  dest: path.join(__dirname, 'tmp_uploads'),
  limits: { fileSize: 32 * 1024 * 1024 },
});

if (!fs.existsSync(path.join(__dirname, 'tmp_uploads'))) {
  fs.mkdirSync(path.join(__dirname, 'tmp_uploads'));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Gửi file lên VirusTotal, trả về analysis id
async function submitFileToVT(filePath, fileName) {
  const fileBuffer = fs.readFileSync(filePath);
  const form = new FormData();
  form.append('file', new Blob([fileBuffer]), fileName);

  const res = await fetch('https://www.virustotal.com/api/v3/files', {
    method: 'POST',
    headers: { 'x-apikey': VT_API_KEY },
    body: form,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`VirusTotal từ chối upload (${res.status}): ${text}`);
  }

  const data = await res.json();
  return data.data.id; // analysis id
}

// Hỏi liên tục cho tới khi VirusTotal quét xong (poll)
async function pollAnalysis(analysisId, maxTries = 20, intervalMs = 4000) {
  for (let i = 0; i < maxTries; i++) {
    const res = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { 'x-apikey': VT_API_KEY },
    });
    const data = await res.json();
    const status = data.data.attributes.status;

    if (status === 'completed') {
      return data.data.attributes;
    }
    await sleep(intervalMs);
  }
  throw new Error('Quét quá lâu, VirusTotal chưa trả kết quả kịp thời gian chờ.');
}

app.post('/api/scan', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Không nhận được file nào.' });
  }

  const filePath = req.file.path;
  const originalName = req.file.originalname;

  try {
    const analysisId = await submitFileToVT(filePath, originalName);
    const result = await pollAnalysis(analysisId);

    const stats = result.stats; // { malicious, suspicious, harmless, undetected, ... }
    const engines = result.results || {};

    // Lấy danh sách engine nào báo độc hại, để hiển thị cho người dùng
    const flaggedBy = Object.entries(engines)
      .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
      .map(([engineName, v]) => ({ engine: engineName, verdict: v.result }));

    const totalEngines = Object.keys(engines).length;
    const maliciousCount = stats.malicious || 0;
    const suspiciousCount = stats.suspicious || 0;
    const isSafe = maliciousCount === 0 && suspiciousCount === 0;

    res.json({
      fileName: originalName,
      safe: isSafe,
      maliciousCount,
      suspiciousCount,
      totalEngines,
      flaggedBy,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'Có lỗi xảy ra khi quét file.' });
  } finally {
    // Luôn xoá file tạm sau khi xong, dù thành công hay lỗi
    fs.unlink(filePath, () => {});
  }
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`VAULT.SEC backend đang chạy tại http://localhost:${PORT}`);
});
