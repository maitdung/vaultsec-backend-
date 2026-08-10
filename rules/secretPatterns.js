// rules/secretPatterns.js
// Bộ regex "kiểu Gitleaks": dò các dạng secret/API key phổ biến bị lộ trong mã nguồn.
// Đây KHÔNG phải bản chạy binary Gitleaks gốc — là bộ regex tự viết bằng JS thuần,
// lấy cảm hứng từ danh sách rule công khai của Gitleaks, chạy trực tiếp không cần cài thêm gì.

const SECRET_PATTERNS = [
  { name: 'AWS Access Key ID', regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'AWS Secret Access Key', regex: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g, lowConfidence: true },
  { name: 'GitHub Personal Access Token', regex: /gh[pousr]_[A-Za-z0-9]{36,}/g },
  { name: 'Slack Token', regex: /xox[baprs]-[A-Za-z0-9-]{10,}/g },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/g },
  { name: 'Generic Private Key Block', regex: /-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)?\s?PRIVATE KEY-----/g },
  { name: 'Stripe API Key', regex: /sk_(live|test)_[0-9a-zA-Z]{24,}/g },
  { name: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  {
    name: 'Hardcoded Password Assignment',
    regex: /(password|passwd|pwd)\s*[:=]\s*["'][^"'\s]{6,}["']/gi,
    lowConfidence: true,
  },
  {
    name: 'Generic API Key Assignment',
    regex: /(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']/gi,
    lowConfidence: true,
  },
];

/**
 * Quét nội dung text (nội dung 1 file mã nguồn) tìm secret bị lộ.
 * @param {string} content nội dung file dạng text
 * @param {string} filePath đường dẫn file (để báo cáo)
 * @returns {Array<{rule:string, filePath:string, line:number, maskedMatch:string, lowConfidence:boolean}>}
 */
function scanTextForSecrets(content, filePath) {
  const findings = [];
  const lines = content.split('\n');

  for (const { name, regex, lowConfidence } of SECRET_PATTERNS) {
    lines.forEach((lineText, idx) => {
      const re = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g');
      let match;
      while ((match = re.exec(lineText)) !== null) {
        const raw = match[0];
        // Che bớt giá trị thật, chỉ hiện vài ký tự đầu/cuối — KHÔNG hiển thị secret đầy đủ
        // để tránh chính công cụ này lại làm lộ thêm secret cho người xem màn hình.
        const masked = raw.length > 10
          ? raw.slice(0, 4) + '••••••••' + raw.slice(-4)
          : '••••••••';
        findings.push({
          rule: name,
          filePath,
          line: idx + 1,
          maskedMatch: masked,
          lowConfidence: !!lowConfidence,
        });
        if (findings.length > 200) return; // an toàn, tránh vòng lặp quá lâu trên file lạ
      }
    });
  }

  return findings;
}

module.exports = { scanTextForSecrets, SECRET_PATTERNS };
