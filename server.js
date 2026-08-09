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

// Mức tối đa VirusTotal public API cho phép (theo tài liệu VT): 650MB
const MAX_FILE_SIZE = 650 * 1024 * 1024;
// Ngưỡng cần dùng "đường upload riêng" thay vì upload thẳng
const DIRECT_UPLOAD_LIMIT = 32 * 1024 * 1024;

if (!VT_API_KEY) {
  console.error('LỖI: Thiếu VT_API_KEY trong file .env — vào VirusTotal lấy API key rồi điền vào .env');
  process.exit(1);
}

app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({
  dest: path.join(__dirname, 'tmp_uploads'),
  limits: { fileSize: MAX_FILE_SIZE },
});

if (!fs.existsSync(path.join(__dirname, 'tmp_uploads'))) {
  fs.mkdirSync(path.join(__dirname, 'tmp_uploads'));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Lấy URL upload dành riêng cho file lớn (>32MB, tối đa 650MB)
async function getLargeFileUploadUrl() {
  const res = await fetch('https://www.virustotal.com/api/v3/files/upload_url', {
    headers: { 'x-apikey': VT_API_KEY },
  });
  if (!res.ok) {
    throw new Error(`Không lấy được đường upload cho file lớn (mã lỗi ${res.status}).`);
  }
  const data = await res.json();
  return data.data; // URL upload riêng, dùng 1 lần
}

// Gửi file lên VirusTotal, trả về analysis id
async function submitFileToVT(filePath, fileName, fileSize) {
  const fileBuffer = fs.readFileSync(filePath);
  const form = new FormData();
  form.append('file', new Blob([fileBuffer]), fileName);

  // File > 32MB bắt buộc phải xin URL upload riêng trước, theo quy định của VirusTotal
  const targetUrl = fileSize > DIRECT_UPLOAD_LIMIT
    ? await getLargeFileUploadUrl()
    : 'https://www.virustotal.com/api/v3/files';

  const res = await fetch(targetUrl, {
    method: 'POST',
    headers: { 'x-apikey': VT_API_KEY },
    body: form,
  });

  if (!res.ok) {
    let detail = '';
    try { detail = (await res.json()).error?.message || ''; } catch (_) { /* bỏ qua */ }
    throw new Error(`VirusTotal từ chối upload (mã ${res.status}).${detail ? ' ' + detail : ''}`);
  }

  const data = await res.json();
  return data.data.id; // analysis id
}

// Hỏi liên tục cho tới khi VirusTotal quét xong (poll)
async function pollAnalysis(analysisId, maxTries = 25, intervalMs = 5000) {
  for (let i = 0; i < maxTries; i++) {
    const res = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { 'x-apikey': VT_API_KEY },
    });
    if (!res.ok) {
      throw new Error(`Không lấy được kết quả phân tích (mã ${res.status}).`);
    }
    const data = await res.json();
    const status = data.data.attributes.status;

    if (status === 'completed') {
      return data.data.attributes;
    }
    await sleep(intervalMs);
  }
  throw new Error('File lớn nên VirusTotal quét lâu hơn dự kiến. Vui lòng thử lại sau ít phút.');
}

app.post('/api/scan', (req, res) => {
  upload.single('file')(req, res, async (multerErr) => {
    // Bắt lỗi ngay từ bước upload (ví dụ file vượt 650MB) và LUÔN trả JSON,
    // không bao giờ để lọt ra trang lỗi HTML mặc định.
    if (multerErr) {
      const msg = multerErr.code === 'LIMIT_FILE_SIZE'
        ? `File vượt quá giới hạn ${(MAX_FILE_SIZE / (1024 * 1024)).toFixed(0)}MB cho phép.`
        : 'Không thể nhận file: ' + multerErr.message;
      return res.status(400).json({ error: msg });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'Không nhận được file nào.' });
    }

    const filePath = req.file.path;
    const originalName = req.file.originalname;
    const fileSize = req.file.size;

    try {
      const analysisId = await submitFileToVT(filePath, originalName, fileSize);
      const result = await pollAnalysis(analysisId);

      const stats = result.stats; // { malicious, suspicious, harmless, undetected, ... }
      const engines = result.results || {};

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
      fs.unlink(filePath, () => {});
    }
  });
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Lưới an toàn cuối cùng: nếu có lỗi nào lọt qua (ví dụ request quá lớn ở tầng mạng),
// vẫn trả JSON thay vì trang lỗi HTML mặc định của Express.
app.use((err, req, res, next) => {
  console.error('Lỗi không mong muốn:', err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Có lỗi hệ thống xảy ra, vui lòng thử lại.' });
});

app.listen(PORT, () => {
  console.log(`VAULT.SEC backend đang chạy tại http://localhost:${PORT}`);
});
