# Mô Hình Mối Đe Dọa (Threat Model) — Cổng Tài Khoản Học Viên FPT Aptech

Tài liệu này mô tả các mối đe dọa bảo mật (attack vectors) đã được phân tích trong quá trình thiết kế hệ thống xác thực & phân quyền Cổng tài khoản FPT Aptech và cơ chế phòng vệ tương ứng ở tầng ứng dụng, cơ sở dữ liệu và giao thức HTTP.

---

## 1. Dò mật khẩu (Brute-Force) & Nhồi thông tin xác thực (Credential Stuffing)

- **Mối đe dọa**: Kẻ tấn công thử hàng loạt mật khẩu trên một tài khoản hoặc gửi số lượng lớn yêu cầu đăng ký / khôi phục mật khẩu từ một địa chỉ IP.
- **Biện pháp chặn**:
  1. **Khóa tạm thời theo tài khoản (F5)**: Trong cửa sổ 15 phút, nếu tài khoản `ACTIVE` nhập sai mật khẩu 5 lần liên tiếp, trạng thái tài khoản chuyển sang `LOCKED` trong 15 phút (`locked_until`). Mọi nỗ lực đăng nhập trong thời gian khóa đều bị từ chối ngay cả khi nhập đúng mật khẩu, đồng thời ghi sự kiện `ACCOUNT_LOCKED` vào nhật ký kiểm toán.
  2. **Giới hạn tần suất theo IP (Rate Limiting - Mục 11.4 & F2)**:
     - Tối đa **10 lần đăng ký / giờ / IP** (`RateLimitService`).
     - Tối đa **20 lần yêu cầu quên mật khẩu / giờ / IP**.
     - Tối đa **3 lần gửi lại email xác minh / giờ / tài khoản**.
  3. **Chính sách mật khẩu mạnh (F4)**: Bắt buộc tối thiểu 12 ký tự, không chứa `username` hoặc `email`, chặn danh sách mật khẩu phổ biến (`common-passwords.txt`) và cấm tái sử dụng 5 mật khẩu gần nhất (`password_history`).

---

## 2. Dò tìm sự tồn tại của tài khoản (Username / Email Enumeration & Timing Attack)

- **Mối đe dọa**: Kẻ tấn công phân biệt tài khoản tồn tại hay không dựa vào nội dung thông báo lỗi hoặc độ trễ thời gian phản hồi của `POST /login` và `POST /password/forgot`.
- **Biện pháp chặn**:
  1. **Thông báo đồng nhất**:
     - Khi đăng nhập thất bại (do không tồn tại user, sai mật khẩu, hoặc tài khoản ở trạng thái `PENDING`, `INVITED`, `LOCKED`, `DISABLED`), hệ thống luôn chuyển hướng về `/login?error` với duy nhất một thông báo chung.
     - Khi yêu cầu quên mật khẩu (`POST /password/forgot`), hệ thống luôn trả về cùng một thông báo xác nhận dù email có tồn tại trong hệ thống hay không.
  2. **Chống tấn công kênh kề theo thời gian (Timing Attack Mitigation - Mục 11.4)**:
     - `DaoAuthenticationProvider` của Spring Security kết hợp với `CustomAuthenticationFailureHandler` luôn thực hiện phép băm `passwordEncoder.matches(rawPassword, dummyHash)` bằng BCrypt ngay cả khi tài khoản không tồn tại hoặc bị từ chối ở bước kiểm tra trạng thái (`DisabledException`, `LockedException`), đảm bảo độ lệch thời gian phản hồi giữa tài khoản không tồn tại và sai mật khẩu luôn nằm trong ngưỡng `< 50 ms`.

---

## 3. Đánh cắp cơ sở dữ liệu (Database Breach / Offline Cracking)

- **Mối đe dọa**: Kẻ tấn công đọc trộm dữ liệu bảng `users`, `security_tokens`, `totp_recovery_codes` thông qua bản sao lưu hoặc lỗi lộ dữ liệu.
- **Biện pháp chặn**:
  1. **Mật khẩu băm thích ứng (`DelegatingPasswordEncoder`)**: Lưu ở định dạng `{bcrypt}$2a$10$...` với salt ngẫu nhiên. Các tài khoản cũ dùng thuật toán yếu hơn (như `{noop}`) được tự động nâng cấp lên `{bcrypt}` ngay khi đăng nhập thành công qua `UserDetailsPasswordService`.
  2. **Băm một chiều SHA-256 cho mọi Token & Mã khôi phục (F2, F3, F6)**:
     - Token xác minh email (24h), token đặt lại mật khẩu (30 phút), token mời giảng viên/quản trị viên (24h) và 10 mã khôi phục 2FA đều chỉ lưu giá trị băm `SHA-256` (`token_hash`, `code_hash`) trong database. Kể cả khi lộ DB, kẻ tấn công không thể suy ngược ra token gốc để kích hoạt hoặc đặt lại mật khẩu.
  3. **Mã hóa đối xứng xác thực AES-GCM cho khóa bí mật TOTP (Mục 11.4)**:
     - Khóa Base32 TOTP của người dùng không lưu dạng rõ mà được mã hóa bằng `AES/GCM/NoPadding` (IV ngẫu nhiên 96-bit + Authentication Tag 128-bit) với khóa lấy từ biến môi trường `TOTP_AES_KEY` (`AesGcmCryptoService`).

---

## 4. Chiếm quyền phiên (Session Hijacking, Session Fixation & Stolen Remember-Me)

- **Mối đe dọa**: Kẻ tấn công cố định `JSESSIONID` trước khi nạn nhân đăng nhập, đánh cắp cookie qua XSS/mạng, hoặc duy trì truy cập trái phép sau khi nạn nhân đổi mật khẩu.
- **Biện pháp chặn**:
  1. **Chống Session Fixation**: Đổi Session ID (`request.changeSessionId()`) ngay khi đăng nhập hoặc tự động đăng nhập (`AutoLogin`).
  2. **Bảo vệ Cookie phiên**: Cấu hình `HttpOnly=true`, `SameSite=Lax` (và `Secure=true` trên môi trường production qua `application-prod.yaml`).
  3. **Giới hạn phiên đồng thời & Thu hồi từ xa (F8)**:
     - Mỗi tài khoản chỉ được phép có tối đa **2 phiên hoạt động đồng thời** trong bảng `user_sessions`. Khi đăng nhập trên thiết bị thứ 3, phiên cũ nhất tự động bị đánh dấu `revoked = true` và bị `SessionTrackingFilter` hủy ngay ở request kế tiếp.
     - Người dùng có thể xem IP, User-Agent và đăng xuất từ xa từng thiết bị tại `/sessions`.
  4. **Thu hồi tức thời khi có biến động bảo mật (F3, F7, F9, F10, 11.2)**:
     - Đổi mật khẩu (F9) tự động hủy mọi phiên khác và xóa toàn bộ token `persistent_logins` (Remember-Me), chỉ giữ lại phiên hiện tại.
     - Đặt lại mật khẩu qua email (F3), vô hiệu hóa tài khoản (`ACTIVE -> DISABLED`) hoặc lệnh "Buộc đăng xuất" của ADMIN (F10) lập tức thu hồi **mọi phiên** và **mọi token Remember-Me** của tài khoản đó.

---

## 5. Vượt qua xác thực đơn yếu tố & Leo thang đặc quyền (Privilege Escalation & Account Takeover)

- **Mối đe dọa**: Lộ mật khẩu của tài khoản đặc quyền (`LECTURER`, `ADMIN`), tấn công CSRF để thay đổi quyền, hoặc xóa/vô hiệu hóa toàn bộ quản trị viên gây khóa hệ thống (Denial of Administration).
- **Biện pháp chặn**:
  1. **Xác thực 2 bước TOTP (RFC 6238 - F6)**:
     - Bắt buộc đối với `ROLE_LECTURER` và `ROLE_ADMIN`: `TwoFactorEnforcementFilter` chặn mọi truy cập vào nghiệp vụ và buộc chuyển hướng về `/2fa/setup` nếu chưa bật 2FA, hoặc `/2fa/verify` nếu chưa nhập mã TOTP sau khi đăng nhập.
  2. **Chống giả mạo yêu cầu liên trang (CSRF) & XSS (CSP)**:
     - Bật CSRF mặc định cho mọi phương thức thay đổi trạng thái (`POST`), bao gồm cả `/logout`.
     - Header `Content-Security-Policy` chỉ cho phép tải tài nguyên từ `'self'` và Bootstrap CDN, chặn toàn bộ inline script và inline style. Bật `Strict-Transport-Security (HSTS)` với `max-age=31536000; includeSubDomains`.
  3. **Bảo vệ toàn vẹn quản trị viên (F10) & Nhật ký kiểm toán (F11)**:
     - Chặn `ADMIN` tự gỡ quyền `ADMIN`, tự khóa hoặc tự xóa chính mình; đảm bảo hệ thống luôn còn ít nhất 1 `ADMIN` ở trạng thái `ACTIVE`.
     - Mọi sự kiện nhạy cảm được ghi nhận độc lập (`REQUIRES_NEW`) vào bảng `audit_logs` kèm thời điểm, tài khoản, IP và User-Agent; tuyệt đối không ghi mật khẩu, token hay mã TOTP vào log hệ thống.
