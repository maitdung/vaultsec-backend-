// rules/yaraStyleRules.js
// Bộ rule "kiểu YARA": mỗi rule gồm tên + các mẫu chuỗi/byte cần tìm trong file.
// Đây KHÔNG phải bản chạy libyara gốc — là bộ dò mẫu tự viết bằng JS thuần,
// lấy cảm hứng từ cách YARA hoạt động (so khớp chuỗi/byte để gắn cờ nghi vấn),
// giúp bắt thêm vài dấu hiệu mà việc chỉ dựa vào VirusTotal có thể bỏ sót.
// Đây là lớp bổ sung, không thay thế kết quả từ VirusTotal.

const RULES = [
  {
    name: 'EICAR_Test_File',
    severity: 'malicious',
    description: 'Trùng khớp chuỗi test chuẩn của ngành antivirus (file test EICAR).',
    patterns: ['X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'],
  },
  {
    name: 'Suspicious_PowerShell_Obfuscation',
    severity: 'suspicious',
    description: 'Chứa lệnh PowerShell thường dùng để chạy mã ẩn/mã hoá base64 (kỹ thuật phổ biến trong mã độc).',
    patterns: ['-enc ', '-EncodedCommand', 'FromBase64String', 'IEX(New-Object', 'DownloadString('],
  },
  {
    name: 'Suspicious_Reverse_Shell',
    severity: 'suspicious',
    description: 'Chứa cụm lệnh thường dùng để mở kết nối điều khiển từ xa (reverse shell).',
    patterns: ['/bin/sh -i', 'nc -e /bin/sh', 'bash -i >&', 'sh -i >&', '0>&1'],
  },
  {
    name: 'Suspicious_Macro_AutoOpen',
    severity: 'suspicious',
    description: 'Chứa macro tự động chạy khi mở file văn phòng — kỹ thuật phổ biến để phát tán mã độc qua file Word/Excel.',
    patterns: ['Auto_Open', 'AutoOpen', 'Document_Open', 'Workbook_Open', 'Shell(', 'CreateObject("WScript.Shell")'],
  },
  {
    name: 'Suspicious_Ransom_Note_Language',
    severity: 'suspicious',
    description: 'Chứa cụm từ thường xuất hiện trong ghi chú đòi tiền chuộc (ransomware note).',
    patterns: ['your files have been encrypted', 'decrypt your files', 'send bitcoin to', 'restore your files pay'],
  },
  {
    name: 'Suspicious_Packed_Binary_Marker',
    severity: 'info',
    description: 'Chứa dấu hiệu file đã bị nén/đóng gói bằng công cụ thường dùng để né antivirus (không tự nó là bằng chứng độc hại).',
    patterns: ['UPX0', 'UPX1', 'UPX!', 'This program cannot be run in DOS mode'],
  },
];

/**
 * Quét 1 buffer nhị phân theo các rule ở trên.
 * @param {Buffer} buffer nội dung file cần quét
 * @returns {Array<{name:string, severity:string, description:string, matchedPattern:string}>}
 */
function scanBufferWithRules(buffer) {
  // Đọc dưới dạng latin1 để giữ nguyên byte-for-byte khi so khớp chuỗi,
  // tránh lỗi encoding làm sai lệch kết quả so khớp trên file nhị phân.
  const text = buffer.toString('latin1');
  const matches = [];

  for (const rule of RULES) {
    for (const pattern of rule.patterns) {
      if (text.includes(pattern)) {
        matches.push({
          name: rule.name,
          severity: rule.severity,
          description: rule.description,
          matchedPattern: pattern.length > 40 ? pattern.slice(0, 40) + '…' : pattern,
        });
        break; // 1 rule chỉ cần báo 1 lần dù khớp nhiều pattern
      }
    }
  }

  return matches;
}

module.exports = { scanBufferWithRules, RULES };
