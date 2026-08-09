# VAULT.SEC — Hướng dẫn đưa web lên mạng (không cần biết code)

Bộ file này gồm:
- `server.js`, `package.json` — phần "backend" (bộ não xử lý, gọi VirusTotal)
- `public/index.html` — giao diện VAULT.SEC (đã có sẵn khung upload file)
- `.env.example` — nơi bạn dán API key (KHÔNG dùng trực tiếp, xem bước 3)

## Cách 1 — Nhanh nhất: Render.com (miễn phí, không cần cài gì trên máy)

1. **Tạo tài khoản GitHub** (nếu chưa có): vào github.com → Sign up.
2. **Đưa toàn bộ thư mục này lên GitHub:**
   - Vào github.com → bấm dấu "+" góc trên → "New repository"
   - Đặt tên ví dụ `vaultsec-backend` → Create repository
   - Trên trang repo mới, bấm "uploading an existing file" → kéo thả TOÀN BỘ
     file trong thư mục này vào (trừ file `.env` nếu bạn có tạo, không đưa lên)
   - Bấm "Commit changes"
3. **Tạo tài khoản Render:** vào render.com → Sign up (có thể đăng nhập bằng GitHub luôn cho nhanh).
4. **Tạo Web Service mới:**
   - Trong Render, bấm "New +" → "Web Service"
   - Chọn repo `vaultsec-backend` bạn vừa tạo ở bước 2
   - Ở mục cấu hình:
     - Build Command: `npm install`
     - Start Command: `npm start`
   - Kéo xuống phần **"Environment Variables"** → bấm "Add Environment Variable"
     - Key: `VT_API_KEY`
     - Value: *dán API key thật của bạn vào đây* (đây là nơi AN TOÀN để đặt key,
       không ai xem được ngoài bạn)
   - Bấm "Create Web Service"
5. Chờ khoảng 2–3 phút để Render dựng xong. Nó sẽ cho bạn 1 đường link dạng
   `https://vaultsec-backend-xxxx.onrender.com` — đó chính là web của bạn, đã
   có sẵn tính năng quét file, chạy được luôn.

**Lưu ý về gói miễn phí của Render:** server sẽ "ngủ" sau ~15 phút không ai
truy cập, và mất khoảng 30–50 giây để "thức dậy" ở lượt truy cập đầu tiên sau
đó. Đây là đánh đổi bình thường của gói free, không phải lỗi.

## Cách 2 — Nếu bạn muốn tự chạy thử trên máy tính trước

Cần cài **Node.js** (vào nodejs.org tải bản LTS, cài như cài phần mềm bình thường).

Sau đó mở "Command Prompt" (Windows) hoặc "Terminal" (Mac), di chuyển vào
thư mục này rồi gõ lần lượt:

```
npm install
```

Đổi tên file `.env.example` thành `.env`, mở bằng Notepad, dán API key thật
vào chỗ `dan_api_key_cua_ban_vao_day`, lưu lại.

Rồi gõ:

```
npm start
```

Mở trình duyệt vào `http://localhost:3000` để xem thử.

## Câu hỏi thường gặp

**"Tôi thấy báo lỗi khi quét file, phải làm sao?"**
Thường do: (1) API key sai/hết hạn — kiểm tra lại trong Render → Environment,
(2) file lớn hơn 32MB — VirusTotal API công khai giới hạn size này,
(3) đã dùng hết 500 lượt quét miễn phí trong ngày — chờ qua ngày hôm sau.

**"Tôi có cần mua gì không?"**
Không. VirusTotal free tier (500 lượt/ngày) + Render free tier là đủ cho
nhu cầu cá nhân/thử nghiệm. Nếu web có nhiều người dùng thật, khi đó mới cần
tính đến gói trả phí.

**"File người dùng tải lên có bị lưu lại không?"**
Không. `server.js` xoá file tạm ngay sau khi quét xong (dòng `fs.unlink`),
dù quét thành công hay lỗi.
# vaultsec-backend-
