// server.js
// Backend VAULT.SEC:
// 1) Nhận file upload -> gửi lên VirusTotal + quét thêm bằng rule "kiểu YARA" tự viết.
// 2) Nhận link GitHub repo -> quét tìm secret lộ bằng rule "kiểu Gitleaks" tự viết.
// 3) Giới hạn số lượt gọi mỗi IP để chống spam / bảo vệ quota VirusTotal miễn phí.
// Không lưu file người dùng lâu dài, không log nội dung file.

require('dotenv').config();
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');

const { scanBufferWithRules } = require('./rules/yaraStyleRules');
const { scanTextForSecrets } = require('./rules/secretPatterns');

const app = express();
const PORT = process.env.PORT || 3000;
const VT_API_KEY = process.env.VT_API_KEY;

const MAX_FILE_SIZE = 650 * 1024 * 1024; // giới hạn VirusTotal public API
const DIRECT_UPLOAD_LIMIT = 32 * 1024 * 1024; // ngưỡng cần dùng đường upload riêng

if (!VT_API_KEY) {
  console.error('LỖI: Thiếu VT_API_KEY trong file .env — vào VirusTotal lấy API key rồi điền vào .env');
  process.exit(1);
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('trust proxy', 1); // Render đứng sau proxy, cần bật để rate-limit nhận đúng IP thật

const upload = multer({
  dest: path.join(__dirname, 'tmp_uploads'),
  limits: { fileSize: MAX_FILE_SIZE },
});

if (!fs.existsSync(path.join(__dirname, 'tmp_uploads'))) {
  fs.mkdirSync(path.join(__dirname, 'tmp_uploads'));
}

// ---------- Giới hạn lượt gọi (chống spam) ----------
function rateLimitHandler(req, res) {
  res.status(429).json({
    error: 'Bạn đã gửi quá nhiều yêu cầu trong thời gian ngắn. Vui lòng thử lại sau ít phút.',
  });
}

const scanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 phút
  max: 8, // tối đa 8 lượt quét file / IP / 15 phút
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler,
});

const repoScanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // tối đa 5 lượt quét repo / IP / 15 phút (API GitHub công khai giới hạn thấp)
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler,
});

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ================== PHẦN 1: QUÉT FILE (VirusTotal + YARA-style) ==================

async function getLargeFileUploadUrl() {
  const res = await fetch('https://www.virustotal.com/api/v3/files/upload_url', {
    headers: { 'x-apikey': VT_API_KEY },
  });
  if (!res.ok) throw new Error(`Không lấy được đường upload cho file lớn (mã lỗi ${res.status}).`);
  const data = await res.json();
  return data.data;
}

async function submitFileToVT(fileBuffer, fileName, fileSize) {
  const form = new FormData();
  form.append('file', new Blob([fileBuffer]), fileName);

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
  return data.data.id;
}

async function pollAnalysis(analysisId, maxTries = 25, intervalMs = 5000) {
  for (let i = 0; i < maxTries; i++) {
    const res = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { 'x-apikey': VT_API_KEY },
    });
    if (!res.ok) throw new Error(`Không lấy được kết quả phân tích (mã ${res.status}).`);
    const data = await res.json();
    if (data.data.attributes.status === 'completed') return data.data.attributes;
    await sleep(intervalMs);
  }
  throw new Error('File lớn nên VirusTotal quét lâu hơn dự kiến. Vui lòng thử lại sau ít phút.');
}

app.post('/api/scan', scanLimiter, (req, res) => {
  upload.single('file')(req, res, async (multerErr) => {
    if (multerErr) {
      const msg = multerErr.code === 'LIMIT_FILE_SIZE'
        ? `File vượt quá giới hạn ${(MAX_FILE_SIZE / (1024 * 1024)).toFixed(0)}MB cho phép.`
        : 'Không thể nhận file: ' + multerErr.message;
      return res.status(400).json({ error: msg });
    }
    if (!req.file) return res.status(400).json({ error: 'Không nhận được file nào.' });

    const filePath = req.file.path;
    const originalName = req.file.originalname;
    const fileSize = req.file.size;

    try {
      const fileBuffer = fs.readFileSync(filePath);

      // Chạy song song: quét rule cục bộ (nhanh, không tốn quota) + gửi VirusTotal
      const localMatches = scanBufferWithRules(fileBuffer);

      const analysisId = await submitFileToVT(fileBuffer, originalName, fileSize);
      const result = await pollAnalysis(analysisId);

      const stats = result.stats;
      const engines = result.results || {};

      const flaggedBy = Object.entries(engines)
        .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
        .map(([engineName, v]) => ({ engine: engineName, verdict: v.result }));

      const totalEngines = Object.keys(engines).length;
      const maliciousCount = stats.malicious || 0;
      const suspiciousCount = stats.suspicious || 0;
      const localFlagged = localMatches.some(m => m.severity === 'malicious' || m.severity === 'suspicious');
      const isSafe = maliciousCount === 0 && suspiciousCount === 0 && !localFlagged;

      res.json({
        fileName: originalName,
        safe: isSafe,
        maliciousCount,
        suspiciousCount,
        totalEngines,
        flaggedBy,
        localRuleMatches: localMatches, // kết quả từ lớp quét "kiểu YARA" tự viết
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: err.message || 'Có lỗi xảy ra khi quét file.' });
    } finally {
      fs.unlink(filePath, () => {});
    }
  });
});

// ================== PHẦN 2: QUÉT REPO GITHUB TÌM SECRET (kiểu Gitleaks) ==================

const TEXT_FILE_EXTENSIONS = [
  '.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.go', '.java', '.php', '.env',
  '.json', '.yml', '.yaml', '.txt', '.md', '.sh', '.config', '.xml', '.properties', '.ini',
];
const MAX_FILES_TO_SCAN = 40;
const MAX_FILE_BYTES_TO_SCAN = 300 * 1024; // 300KB/file, tránh quét file quá lớn

function parseGithubRepoUrl(input) {
  const cleaned = input.trim().replace(/\.git$/, '').replace(/\/+$/, '');
  const match = cleaned.match(/github\.com[/:]([^/]+)\/([^/]+)/i);
  if (!match) return null;
  return { owner: match[1], repo: match[2] };
}

async function ghFetch(url) {
  const res = await fetch(url, {
    headers: {
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'vaultsec-repo-scanner',
    },
  });
  if (res.status === 403) {
    throw new Error('GitHub tạm giới hạn số lượt gọi API công khai (giới hạn thấp khi không đăng nhập). Vui lòng thử lại sau khoảng 1 giờ.');
  }
  if (!res.ok) throw new Error(`Không truy cập được GitHub (mã ${res.status}). Repo có tồn tại và ở chế độ public không?`);
  return res.json();
}

app.post('/api/repo-scan', repoScanLimiter, async (req, res) => {
  const { repoUrl } = req.body || {};
  if (!repoUrl) return res.status(400).json({ error: 'Thiếu đường link repo.' });

  const parsed = parseGithubRepoUrl(repoUrl);
  if (!parsed) return res.status(400).json({ error: 'Link không đúng định dạng GitHub (ví dụ: https://github.com/owner/repo).' });

  try {
    const repoInfo = await ghFetch(`https://api.github.com/repos/${parsed.owner}/${parsed.repo}`);
    const defaultBranch = repoInfo.default_branch || 'main';

    const branchData = await ghFetch(
      `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/branches/${defaultBranch}`
    );
    const treeSha = branchData.commit.sha;

    const treeData = await ghFetch(
      `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/git/trees/${treeSha}?recursive=1`
    );

    const candidateFiles = (treeData.tree || [])
      .filter(item => item.type === 'blob')
      .filter(item => TEXT_FILE_EXTENSIONS.some(ext => item.path.toLowerCase().endsWith(ext)))
      .filter(item => (item.size || 0) <= MAX_FILE_BYTES_TO_SCAN)
      .slice(0, MAX_FILES_TO_SCAN);

    const allFindings = [];
    let scannedCount = 0;

    for (const file of candidateFiles) {
      try {
        const blobData = await ghFetch(
          `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/git/blobs/${file.sha}`
        );
        if (blobData.encoding !== 'base64') continue;
        const content = Buffer.from(blobData.content, 'base64').toString('utf-8');
        const findings = scanTextForSecrets(content, file.path);
        allFindings.push(...findings);
        scannedCount++;
      } catch (_) {
        // bỏ qua file lỗi, tiếp tục quét file khác
      }
    }

    res.json({
      repo: `${parsed.owner}/${parsed.repo}`,
      filesScanned: scannedCount,
      totalFilesInRepo: (treeData.tree || []).filter(i => i.type === 'blob').length,
      findings: allFindings.slice(0, 100),
      truncatedFileList: candidateFiles.length < (treeData.tree || []).filter(i => i.type === 'blob' && TEXT_FILE_EXTENSIONS.some(ext => i.path.toLowerCase().endsWith(ext))).length,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'Có lỗi khi quét repo.' });
  }
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.use((err, req, res, next) => {
  console.error('Lỗi không mong muốn:', err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Có lỗi hệ thống xảy ra, vui lòng thử lại.' });
});

app.listen(PORT, () => {
  console.log(`VAULT.SEC backend đang chạy tại http://localhost:${PORT}`);
});
