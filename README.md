# Cổng Tài Khoản Học Viên FPT Aptech (Spring Security 7 + Spring Boot 4.1 + Spring Data JPA)

Ứng dụng quản lý xác thực, phân quyền và vòng đời tài khoản học viên, giảng viên, quản trị viên theo chuẩn bảo mật với **Spring Boot 4.1.1**, **Spring Security 7.1**, **Spring Data JPA**, **Flyway**, **Thymeleaf + Bootstrap 5** và **MySQL 8.4**.

---

## 1. Yêu cầu môi trường

| Thành phần      | Phiên bản | Ghi chú                                                                   |
| --------------- | --------- | ------------------------------------------------------------------------- |
| JDK             | 17+ (LTS) | Tối thiểu Java 17 theo đặc tả Spring Boot                                 |
| Spring Boot     | 4.1.1     | Quản lý phiên bản cho toàn bộ starter                                     |
| Spring Security | 7.1.x     | Lambda DSL, `DelegatingPasswordEncoder`, CSRF, CSP, HSTS                  |
| MySQL           | 8.4 LTS   | Tự động khởi chạy qua `spring-boot-docker-compose`                        |
| Mailpit         | latest    | SMTP dev server (`localhost:1025`, giao diện web `http://localhost:8025`) |

---

## 2. Chạy ứng dụng bằng một lệnh

Đảm bảo Docker Desktop / Docker Engine đang chạy, sau đó tại thư mục gốc dự án chạy:

```bash
./mvnw spring-boot:run
```

Spring Boot Docker Compose support sẽ tự động khởi động container **MySQL 8.4** và **Mailpit** từ file `compose.yaml`, thực thi các migration Flyway (`V1__init_schema.sql`, `V2__fpt_aptech_portal.sql`) và khởi chạy ứng dụng tại:

- **Ứng dụng web**: `http://localhost:8080`
- **Giao diện xem email (Mailpit)**: `http://localhost:8025`

---

## 3. Chạy bộ kiểm thử tự động

Bộ test tích hợp sử dụng `spring-security-test`, `MockMvc` và H2 ở chế độ tương thích MySQL (`MODE=MySQL;DATABASE_TO_LOWER=TRUE`), chạy độc lập không cần Docker:

```bash
./mvnw test
```

- `AuthFlowTest`: Kiểm thử toàn bộ luồng cơ bản của Tutorial (Mục 1–10).
- `PortalSecurityFlowTest`: Kiểm thử tự động toàn bộ các yêu cầu mở rộng **F1–F11** và **11.4** (xác minh email, token hết hạn, token dùng lại, quên mật khẩu, chính sách mật khẩu F4, khóa tạm thời 15 phút khi sai 5 lần, TOTP 2FA + 10 mã khôi phục + mã hóa AES-GCM, giới hạn 2 phiên đồng thời, bảo vệ ADMIN cuối cùng, tự nâng cấp mật khẩu yếu `{noop}` lên `{bcrypt}`, giới hạn tần suất theo IP và nhật ký kiểm toán).

---

## 4. Các đường dẫn (Endpoints) chính

| URL                                   | Quyền truy cập      | Chức năng                                                                               |
| ------------------------------------- | ------------------- | --------------------------------------------------------------------------------------- |
| `/registration`                       | Mọi người           | Đăng ký tài khoản (cơ bản & đăng ký bằng email F1)                                      |
| `/verify-email?token=...`             | Mọi người           | Xác minh email bằng token dùng 1 lần (F2)                                               |
| `/login`                              | Mọi người           | Đăng nhập (hỗ trợ Remember-Me 14 ngày F7)                                               |
| `/password/forgot`, `/password/reset` | Mọi người           | Quên mật khẩu & đặt lại mật khẩu (F3)                                                   |
| `/invite/accept?token=...`            | Mọi người           | Kích hoạt tài khoản Giảng viên / Quản trị viên được mời                                 |
| `/`                                   | Đã đăng nhập        | Trang chào mừng & điều hướng theo vai trò                                               |
| `/profile`                            | Đã đăng nhập        | Xem và cập nhật hồ sơ cá nhân                                                           |
| `/password/change`                    | Đã đăng nhập        | Đổi mật khẩu, hủy mọi phiên đăng nhập khác (F9)                                         |
| `/sessions`                           | Đã đăng nhập        | Quản lý thiết bị đăng nhập (tối đa 2 phiên) & đăng xuất từ xa (F8)                      |
| `/2fa/setup`, `/2fa/verify`           | Đã đăng nhập        | Thiết lập & xác thực 2 bước TOTP RFC 6238 (F6)                                          |
| `/lecturer/students`                  | `LECTURER`, `ADMIN` | Xem danh sách học viên (chỉ đọc)                                                        |
| `/admin/users`                        | `ADMIN`             | Quản trị tài khoản, mời LECTURER/ADMIN, khóa/mở khóa, gán vai trò, buộc đăng xuất (F10) |
| `/admin/audit-logs`                   | `ADMIN`             | Xem và lọc nhật ký kiểm toán bảo mật (F11)                                              |

---

## 5. Tài liệu mô hình mối đe dọa (Threat Model)

Xem chi tiết tại file [`THREAT_MODEL.md`](./THREAT_MODEL.md).
