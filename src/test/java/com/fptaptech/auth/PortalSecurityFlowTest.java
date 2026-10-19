package com.fptaptech.auth;

import com.fptaptech.auth.controller.PasswordController;
import com.fptaptech.auth.entity.AccountStatus;
import com.fptaptech.auth.entity.AppUser;
import com.fptaptech.auth.entity.AuditEventType;
import com.fptaptech.auth.entity.Role;
import com.fptaptech.auth.entity.SecurityToken;
import com.fptaptech.auth.entity.SecurityTokenType;
import com.fptaptech.auth.entity.UserSession;
import com.fptaptech.auth.repository.AuditLogRepository;
import com.fptaptech.auth.repository.SecurityTokenRepository;
import com.fptaptech.auth.repository.UserRepository;
import com.fptaptech.auth.service.AesGcmCryptoService;
import com.fptaptech.auth.service.PasswordPolicyException;
import com.fptaptech.auth.service.RateLimitService;
import com.fptaptech.auth.service.SessionManagementService;
import com.fptaptech.auth.service.TotpService;
import com.fptaptech.auth.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PortalSecurityFlowTest {

        private static final String STRONG_PW = "Str0ng#Pass!2026";

        @Autowired
        MockMvc mvc;
        @Autowired
        UserService userService;
        @Autowired
        UserRepository userRepository;
        @Autowired
        SecurityTokenRepository tokenRepository;
        @Autowired
        TotpService totpService;
        @Autowired
        AesGcmCryptoService cryptoService;
        @Autowired
        SessionManagementService sessionManagementService;
        @Autowired
        RateLimitService rateLimitService;
        @Autowired
        AuditLogRepository auditLogRepository;

        @BeforeEach
        void resetRateLimit() {
                rateLimitService.resetAll();
        }

        // =========================================================================
        // F1 & F2: Đăng ký bằng email (PENDING), xác minh email, token hết hạn, token
        // dùng lại, giới hạn gửi lại
        // =========================================================================
        @Test
        void f1_f2_studentEmailRegistrationPendingThenVerifySuccessAndRejectReuse() throws Exception {
                String rawToken = userService.registerStudent("student_f1", "student_f1@fpt.edu.vn", STRONG_PW);

                AppUser pendingUser = userRepository.findByUsername("student_f1").orElseThrow();
                assertThat(pendingUser.getStatus()).isEqualTo(AccountStatus.PENDING);

                // Chưa xác minh email -> không đăng nhập được
                mvc.perform(formLogin("/login").user("student_f1").password(STRONG_PW))
                                .andExpect(redirectedUrl("/login?error"))
                                .andExpect(unauthenticated());

                // Token lưu dạng băm SHA-256 trong DB (không lưu dạng rõ)
                String expectedHash = AesGcmCryptoService.sha256Hex(rawToken);
                SecurityToken storedToken = tokenRepository
                                .findByTokenHashAndTokenType(expectedHash, SecurityTokenType.EMAIL_VERIFICATION)
                                .orElseThrow();
                assertThat(storedToken.getTokenHash()).isNotEqualTo(rawToken);

                // Xác minh email thành công -> chuyển sang ACTIVE
                mvc.perform(get("/verify-email").param("token", rawToken))
                                .andExpect(redirectedUrl("/login?verified"));

                AppUser activeUser = userRepository.findByUsername("student_f1").orElseThrow();
                assertThat(activeUser.getStatus()).isEqualTo(AccountStatus.ACTIVE);

                // Dùng lại token lần 2 -> bị từ chối
                assertThatThrownBy(() -> userService.verifyEmailToken(rawToken))
                                .isInstanceOf(IllegalStateException.class)
                                .hasMessageContaining("đã được sử dụng");

                // Sau khi ACTIVE -> đăng nhập thành công
                mvc.perform(formLogin("/login").user("student_f1").password(STRONG_PW))
                                .andExpect(authenticated().withUsername("student_f1"));
        }

        @Test
        void f2_expiredEmailVerificationTokenIsRejectedAndResendLimitEnforced() {
                String rawToken = userService.registerStudent("student_exp", "student_exp@fpt.edu.vn", STRONG_PW);
                String tokenHash = AesGcmCryptoService.sha256Hex(rawToken);
                SecurityToken token = tokenRepository
                                .findByTokenHashAndTokenType(tokenHash, SecurityTokenType.EMAIL_VERIFICATION)
                                .orElseThrow();
                token.setExpiresAt(Instant.now().minusSeconds(60));
                tokenRepository.saveAndFlush(token);

                assertThatThrownBy(() -> userService.verifyEmailToken(rawToken))
                                .isInstanceOf(IllegalStateException.class)
                                .hasMessageContaining("hết hạn");

                // Gửi lại tối đa 3 lần mỗi giờ
                userService.resendVerificationEmail("student_exp@fpt.edu.vn");
                userService.resendVerificationEmail("student_exp@fpt.edu.vn");
                userService.resendVerificationEmail("student_exp@fpt.edu.vn");

                assertThatThrownBy(() -> userService.resendVerificationEmail("student_exp@fpt.edu.vn"))
                                .isInstanceOf(IllegalStateException.class)
                                .hasMessageContaining("tối đa 3 lần");
        }

        // =========================================================================
        // F3: Quên mật khẩu (phản hồi giống nhau, hết hạn 30p, dùng 1 lần, hủy phiên
        // cũ)
        // =========================================================================
        @Test
        void f3_forgotPasswordUniformResponseSingleUseAndRevokesOldSessions() throws Exception {
                String verifyToken = userService.registerStudent("student_f3", "student_f3@fpt.edu.vn", STRONG_PW);
                userService.verifyEmailToken(verifyToken);

                // Phản hồi giống hệt nhau dù email tồn tại hay không
                mvc.perform(post("/password/forgot").with(csrf()).param("email", "nonexistent@fpt.edu.vn"))
                                .andExpect(status().isOk())
                                .andExpect(model().attribute("message",
                                                PasswordController.UNIFIED_FORGOT_PASSWORD_MESSAGE));

                mvc.perform(post("/password/forgot").with(csrf()).param("email", "student_f3@fpt.edu.vn"))
                                .andExpect(status().isOk())
                                .andExpect(model().attribute("message",
                                                PasswordController.UNIFIED_FORGOT_PASSWORD_MESSAGE));

                // Tạo 1 phiên đăng nhập đang hoạt động
                AppUser user = userRepository.findByUsername("student_f3").orElseThrow();
                MockHttpServletRequest req = new MockHttpServletRequest();
                req.setSession(new MockHttpSession(null, "session-before-reset"));
                sessionManagementService.registerLoginSession(user, req);
                assertThat(sessionManagementService.isSessionRevoked("session-before-reset")).isFalse();

                // Đặt lại mật khẩu bằng token
                String resetToken = userService.requestPasswordReset("student_f3@fpt.edu.vn").orElseThrow();
                String newPassword = "NewStrong#Pass2027!";
                userService.resetPasswordWithToken(resetToken, newPassword);

                // Phiên cũ bị hủy ngay lập tức
                assertThat(sessionManagementService.isSessionRevoked("session-before-reset")).isTrue();

                // Dùng lại token đặt lại mật khẩu -> bị từ chối
                assertThatThrownBy(() -> userService.resetPasswordWithToken(resetToken, "AnotherStrong#2028!"))
                                .isInstanceOf(IllegalStateException.class)
                                .hasMessageContaining("đã được sử dụng");
        }

        // =========================================================================
        // F4 & F9: Chính sách mật khẩu (12 ký tự, không chứa username/email, không phổ
        // biến, không trùng 5 mật khẩu gần nhất)
        // và Đổi mật khẩu hủy phiên khác nhưng giữ nguyên phiên hiện tại
        // =========================================================================
        @Test
        void f4_f9_passwordPolicyAndChangePasswordKeepsCurrentSessionOnly() {
                String verifyToken = userService.registerStudent("student_f4", "student_f4@fpt.edu.vn", STRONG_PW);
                userService.verifyEmailToken(verifyToken);

                // Ngắn hơn 12 ký tự
                assertThatThrownBy(() -> userService.changePassword("student_f4", STRONG_PW, "Short#123", null))
                                .isInstanceOf(PasswordPolicyException.class);

                // Chứa username
                assertThatThrownBy(
                                () -> userService.changePassword("student_f4", STRONG_PW, "My_student_f4_Pass#1", null))
                                .isInstanceOf(PasswordPolicyException.class);

                // Mật khẩu phổ biến trong danh sách
                assertThatThrownBy(() -> userService.changePassword("student_f4", STRONG_PW, "password123456", null))
                                .isInstanceOf(PasswordPolicyException.class);

                // Đổi qua 4 mật khẩu hợp lệ liên tiếp (tổng cộng 5 mật khẩu trong lịch sử gồm
                // cả mật khẩu ban đầu)
                String pw2 = "ValidPass#Number202";
                String pw3 = "ValidPass#Number303";
                String pw4 = "ValidPass#Number404";
                String pw5 = "ValidPass#Number505";

                userService.changePassword("student_f4", STRONG_PW, pw2, null);
                userService.changePassword("student_f4", pw2, pw3, null);
                userService.changePassword("student_f4", pw3, pw4, null);

                // Tạo 2 phiên thiết bị trước khi đổi sang pw5
                AppUser user = userRepository.findByUsername("student_f4").orElseThrow();
                MockHttpServletRequest req1 = new MockHttpServletRequest();
                req1.setSession(new MockHttpSession(null, "curr-session-1"));
                sessionManagementService.registerLoginSession(user, req1);

                MockHttpServletRequest req2 = new MockHttpServletRequest();
                req2.setSession(new MockHttpSession(null, "other-session-2"));
                sessionManagementService.registerLoginSession(user, req2);

                userService.changePassword("student_f4", pw4, pw5, "curr-session-1");

                // Phiên hiện tại giữ nguyên, phiên khác bị hủy (F9)
                assertThat(sessionManagementService.isSessionRevoked("curr-session-1")).isFalse();
                assertThat(sessionManagementService.isSessionRevoked("other-session-2")).isTrue();

                // Trùng mật khẩu đầu tiên trong 5 mật khẩu gần nhất -> bị từ chối (F4)
                assertThatThrownBy(() -> userService.changePassword("student_f4", pw5, STRONG_PW, "curr-session-1"))
                                .isInstanceOf(PasswordPolicyException.class)
                                .hasMessageContaining("5 mật khẩu gần nhất");
        }

        // =========================================================================
        // F5: Khóa tạm thời 15 phút khi sai mật khẩu 5 lần trong 15 phút
        // =========================================================================
        @Test
        void f5_fiveFailedLoginsLockAccountForFifteenMinutes() throws Exception {
                userService.register("lock_target", STRONG_PW);

                for (int i = 0; i < 5; i++) {
                        mvc.perform(formLogin("/login").user("lock_target").password("WrongPass#" + i))
                                        .andExpect(redirectedUrl("/login?error"))
                                        .andExpect(unauthenticated());
                }

                AppUser lockedUser = userRepository.findByUsername("lock_target").orElseThrow();
                assertThat(lockedUser.getStatus()).isEqualTo(AccountStatus.LOCKED);
                assertThat(lockedUser.getLockedUntil()).isAfter(Instant.now());

                // Đang bị khóa -> nhập đúng mật khẩu vẫn bị từ chối với cùng thông báo lỗi
                // chung
                mvc.perform(formLogin("/login").user("lock_target").password(STRONG_PW))
                                .andExpect(redirectedUrl("/login?error"))
                                .andExpect(unauthenticated());
        }

        // =========================================================================
        // F6: Xác thực 2 bước (TOTP, mã hóa AES-GCM, 10 mã khôi phục, bắt buộc cho
        // LECTURER/ADMIN)
        // =========================================================================
        @Test
        void f6_totpSetupEncryptedSecretVerificationAndMandatoryForLecturer() throws Exception {
                // Admin mời tài khoản LECTURER -> kích hoạt
                String inviteToken = userService.inviteStaffAccount(
                                "lecturer_totp", "lecturer_totp@fpt.edu.vn", "Giảng Viên A", Role.LECTURER);
                userService.acceptInvitation(inviteToken, STRONG_PW);

                // LECTURER chưa bật 2FA -> đăng nhập bị buộc chuyển hướng vào /2fa/setup
                mvc.perform(formLogin("/login").user("lecturer_totp").password(STRONG_PW))
                                .andExpect(redirectedUrl("/2fa/setup"));

                // Thử kích hoạt với mã TOTP sai -> thất bại
                String base32Secret = totpService.generateBase32Secret();
                assertThatThrownBy(() -> userService.enableTotp("lecturer_totp", base32Secret, "000000"))
                                .isInstanceOf(IllegalArgumentException.class);

                // Kích hoạt với mã TOTP đúng -> nhận 10 mã khôi phục
                String validCode = totpService.generateCurrentCode(base32Secret);
                List<String> recoveryCodes = userService.enableTotp("lecturer_totp", base32Secret, validCode);
                assertThat(recoveryCodes).hasSize(10);

                // Bí mật TOTP trong DB phải được mã hóa AES-GCM (không lưu dạng rõ)
                AppUser updated = userRepository.findByUsername("lecturer_totp").orElseThrow();
                assertThat(updated.isTotpEnabled()).isTrue();
                assertThat(updated.getTotpSecretEnc()).isNotEqualTo(base32Secret);
                assertThat(cryptoService.decrypt(updated.getTotpSecretEnc())).isEqualTo(base32Secret);

                // Xác thực bằng mã TOTP sai -> thất bại
                assertThat(userService.verifyTotpOrRecoveryCode("lecturer_totp", "999999")).isFalse();

                // Xác thực bằng mã TOTP đúng -> thành công
                assertThat(userService.verifyTotpOrRecoveryCode("lecturer_totp",
                                totpService.generateCurrentCode(base32Secret))).isTrue();

                // Xác thực bằng mã khôi phục dùng 1 lần -> lần 1 thành công, lần 2 thất bại
                String firstRecovery = recoveryCodes.get(0);
                assertThat(userService.verifyTotpOrRecoveryCode("lecturer_totp", firstRecovery)).isTrue();
                assertThat(userService.verifyTotpOrRecoveryCode("lecturer_totp", firstRecovery)).isFalse();

                // LECTURER không được phép tắt 2FA
                assertThatThrownBy(() -> userService.disableTotp("lecturer_totp", STRONG_PW))
                                .isInstanceOf(IllegalStateException.class)
                                .hasMessageContaining("bắt buộc");
        }

        // =========================================================================
        // F8: Quản lý phiên — Tối đa 2 phiên đồng thời mỗi tài khoản
        // =========================================================================
        @Test
        void f8_maxTwoConcurrentSessionsEvictsOldestSession() {
                AppUser user = userService.register("session_user", STRONG_PW);

                MockHttpServletRequest req1 = new MockHttpServletRequest();
                req1.setSession(new MockHttpSession(null, "sess-1"));
                req1.setRemoteAddr("10.0.0.1");
                req1.addHeader("User-Agent", "Browser-1");
                sessionManagementService.registerLoginSession(user, req1);

                MockHttpServletRequest req2 = new MockHttpServletRequest();
                req2.setSession(new MockHttpSession(null, "sess-2"));
                req2.setRemoteAddr("10.0.0.2");
                req2.addHeader("User-Agent", "Browser-2");
                sessionManagementService.registerLoginSession(user, req2);

                MockHttpServletRequest req3 = new MockHttpServletRequest();
                req3.setSession(new MockHttpSession(null, "sess-3"));
                req3.setRemoteAddr("10.0.0.3");
                req3.addHeader("User-Agent", "Browser-3");
                sessionManagementService.registerLoginSession(user, req3);

                List<UserSession> active = sessionManagementService.getActiveSessions("session_user");
                assertThat(active).hasSize(2);
                assertThat(sessionManagementService.isSessionRevoked("sess-1")).isTrue();
                assertThat(sessionManagementService.isSessionRevoked("sess-2")).isFalse();
                assertThat(sessionManagementService.isSessionRevoked("sess-3")).isFalse();
        }

        // =========================================================================
        // F10 & F11: Quản trị tài khoản — Bảo vệ ADMIN cuối cùng, không tự gỡ quyền
        // ADMIN, nhật ký kiểm toán
        // =========================================================================
        @Test
        void f10_f11_cannotDeleteOrDemoteLastAdminAndAuditLogsAreRecorded() throws Exception {
                String inviteAdmin = userService.inviteStaffAccount(
                                "root_admin", "root_admin@fpt.edu.vn", "Root Admin", Role.ADMIN);
                AppUser admin = userService.acceptInvitation(inviteAdmin, STRONG_PW);
                String secret = totpService.generateBase32Secret();
                userService.enableTotp("root_admin", secret, totpService.generateCurrentCode(secret));

                // Tạo thêm 1 học viên để quản trị
                AppUser student = userService.register("student_target", STRONG_PW);

                // Không thể tự xóa hoặc xóa ADMIN cuối cùng
                assertThatThrownBy(() -> userService.adminDeleteUser(admin.getId(), "root_admin"))
                                .isInstanceOf(IllegalStateException.class);

                // Không thể tự gỡ quyền ADMIN của mình
                assertThatThrownBy(
                                () -> userService.adminUpdateRoles(admin.getId(), Set.of(Role.STUDENT), "root_admin"))
                                .isInstanceOf(IllegalStateException.class)
                                .hasMessageContaining("tự gỡ quyền ADMIN");

                // Chuyển ACTIVE -> DISABLED qua AdminController sẽ hủy ngay phiên của học viên
                // đó và ghi AuditLog
                MockHttpServletRequest studentReq = new MockHttpServletRequest();
                studentReq.setSession(new MockHttpSession(null, "student-sess-active"));
                sessionManagementService.registerLoginSession(student, studentReq);

                mvc.perform(post("/admin/users/" + student.getId() + "/status")
                                .with(csrf())
                                .with(user("root_admin").roles("ADMIN"))
                                .param("status", "DISABLED"))
                                .andExpect(redirectedUrl("/admin/users?statusChanged"));

                assertThat(sessionManagementService.isSessionRevoked("student-sess-active")).isTrue();

                // Kiểm tra trang quản trị và nhật ký kiểm toán bằng quyền ADMIN
                mvc.perform(get("/admin/audit-logs").with(user("root_admin").roles("ADMIN")))
                                .andExpect(status().isOk())
                                .andExpect(model().attributeExists("logPage"));

                assertThat(auditLogRepository.findAll())
                                .extracting(l -> l.getEventType())
                                .contains(AuditEventType.ACCOUNT_DISABLED);
        }

        // =========================================================================
        // 11.4: Tự động nâng cấp mật khẩu băm yếu ({noop}) sang {bcrypt} khi đăng nhập
        // thành công
        // & Giới hạn tần suất theo IP (10 đăng ký/giờ)
        // =========================================================================
        @Test
        void section11_4_weakPasswordHashIsUpgradedOnLoginAndRateLimitWorks() throws Exception {
                AppUser legacyUser = userService.register("legacy_user", STRONG_PW);
                legacyUser.setPasswordHash("{noop}" + STRONG_PW);
                userRepository.saveAndFlush(legacyUser);

                mvc.perform(formLogin("/login").user("legacy_user").password(STRONG_PW))
                                .andExpect(authenticated().withUsername("legacy_user"));

                AppUser upgraded = userRepository.findByUsername("legacy_user").orElseThrow();
                assertThat(upgraded.getPasswordHash()).startsWith("{bcrypt}$2a$");

                // Kiểm tra giới hạn tối đa 10 lần đăng ký mỗi giờ trên mỗi IP
                String testIp = "203.0.113.99";
                for (int i = 0; i < 10; i++) {
                        assertThat(rateLimitService.allowRegistration(testIp)).isTrue();
                }
                assertThat(rateLimitService.allowRegistration(testIp)).isFalse();
        }
}
