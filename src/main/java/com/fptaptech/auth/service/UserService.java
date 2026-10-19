package com.fptaptech.auth.service;

import com.fptaptech.auth.entity.*;
import com.fptaptech.auth.repository.*;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final SecurityTokenRepository tokenRepository;
    private final PasswordHistoryRepository passwordHistoryRepository;
    private final TotpRecoveryCodeRepository totpRecoveryCodeRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyValidator passwordPolicyValidator;
    private final SessionManagementService sessionManagementService;
    private final AesGcmCryptoService cryptoService;
    private final TotpService totpService;
    private final EmailService emailService;
    private final AuditService auditService;
    private final SecureRandom secureRandom = new SecureRandom();

    public UserService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       SecurityTokenRepository tokenRepository,
                       PasswordHistoryRepository passwordHistoryRepository,
                       TotpRecoveryCodeRepository totpRecoveryCodeRepository,
                       PasswordEncoder passwordEncoder,
                       PasswordPolicyValidator passwordPolicyValidator,
                       SessionManagementService sessionManagementService,
                       AesGcmCryptoService cryptoService,
                       TotpService totpService,
                       EmailService emailService,
                       AuditService auditService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.tokenRepository = tokenRepository;
        this.passwordHistoryRepository = passwordHistoryRepository;
        this.totpRecoveryCodeRepository = totpRecoveryCodeRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicyValidator = passwordPolicyValidator;
        this.sessionManagementService = sessionManagementService;
        this.cryptoService = cryptoService;
        this.totpService = totpService;
        this.emailService = emailService;
        this.auditService = auditService;
    }

    public static String normalize(String username) {
        return username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
    }

    public static String normalizeEmail(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }

    @Transactional
    public AppUser register(String rawUsername, String rawPassword) {
        String username = normalize(rawUsername);
        if (userRepository.existsByUsername(username)) {
            throw new UsernameAlreadyExistsException(username);
        }

        Role userRole = roleRepository.findByName(Role.USER)
                .orElseGet(() -> roleRepository.save(new Role(Role.USER)));

        AppUser user = new AppUser(username, passwordEncoder.encode(rawPassword));
        user.getRoles().add(userRole);

        try {
            AppUser saved = userRepository.saveAndFlush(user);
            passwordHistoryRepository.save(new PasswordHistory(saved, saved.getPasswordHash()));
            auditService.record(AuditEventType.ACCOUNT_ACTIVATED, username, username, "127.0.0.1", "System", "Đăng ký trực tiếp");
            return saved;
        } catch (DataIntegrityViolationException e) {
            throw new UsernameAlreadyExistsException(username);
        }
    }

    @Transactional
    public String registerStudent(String rawUsername, String rawEmail, String rawPassword) {
        String username = normalize(rawUsername);
        String email = normalizeEmail(rawEmail);

        if (userRepository.existsByUsername(username)) {
            throw new UsernameAlreadyExistsException(username);
        }
        if (email != null && userRepository.existsByEmail(email)) {
            throw new EmailAlreadyExistsException(email);
        }

        passwordPolicyValidator.validate(rawPassword, username, email, null);

        Role studentRole = roleRepository.findByName(Role.STUDENT)
                .orElseGet(() -> roleRepository.save(new Role(Role.STUDENT)));
        Role userRole = roleRepository.findByName(Role.USER)
                .orElseGet(() -> roleRepository.save(new Role(Role.USER)));

        AppUser user = new AppUser(username, email, passwordEncoder.encode(rawPassword), AccountStatus.PENDING);
        user.getRoles().add(studentRole);
        user.getRoles().add(userRole);

        AppUser saved;
        try {
            saved = userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException e) {
            throw new UsernameAlreadyExistsException(username);
        }

        passwordHistoryRepository.save(new PasswordHistory(saved, saved.getPasswordHash()));

        String rawToken = UUID.randomUUID().toString();
        String tokenHash = AesGcmCryptoService.sha256Hex(rawToken);
        SecurityToken token = new SecurityToken(saved, tokenHash, SecurityTokenType.EMAIL_VERIFICATION,
                Instant.now().plus(Duration.ofHours(24)));
        tokenRepository.save(token);

        emailService.sendVerificationEmail(email, rawToken);
        auditService.record(AuditEventType.LOGIN_FAILURE, username, username, "127.0.0.1", "System", "Tạo tài khoản PENDING chờ xác minh");

        return rawToken;
    }

    @Transactional
    public void verifyEmailToken(String rawToken) {
        String tokenHash = AesGcmCryptoService.sha256Hex(rawToken);
        SecurityToken token = tokenRepository.findByTokenHashAndTokenType(tokenHash, SecurityTokenType.EMAIL_VERIFICATION)
                .orElseThrow(() -> new IllegalStateException("Token xác minh email không hợp lệ"));

        if (token.isUsed()) {
            throw new IllegalStateException("Token xác minh email đã được sử dụng");
        }
        if (token.isExpired()) {
            throw new IllegalStateException("Token xác minh email đã hết hạn");
        }

        token.setUsedAt(Instant.now());
        tokenRepository.save(token);

        AppUser user = token.getUser();
        user.setStatus(AccountStatus.ACTIVE);
        user.setEnabled(true);
        userRepository.save(user);

        auditService.record(AuditEventType.EMAIL_VERIFIED, user.getUsername(), user.getUsername(), "127.0.0.1", "System", "Xác minh email thành công");
    }

    @Transactional
    public String resendVerificationEmail(String rawEmail) {
        String email = normalizeEmail(rawEmail);
        AppUser user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy tài khoản với email này"));

        if (user.getStatus() != AccountStatus.PENDING) {
            throw new IllegalStateException("Tài khoản không ở trạng thái chờ xác minh");
        }

        Instant now = Instant.now();
        Instant windowStart = user.getVerificationResendWindowStart();
        if (windowStart == null || Duration.between(windowStart, now).toMinutes() >= 60) {
            user.setVerificationResendWindowStart(now);
            user.setVerificationResendCount(1);
        } else {
            if (user.getVerificationResendCount() >= 3) {
                throw new IllegalStateException("Chỉ được gửi lại email xác minh tối đa 3 lần mỗi giờ");
            }
            user.setVerificationResendCount(user.getVerificationResendCount() + 1);
        }
        userRepository.save(user);

        String rawToken = UUID.randomUUID().toString();
        String tokenHash = AesGcmCryptoService.sha256Hex(rawToken);
        SecurityToken token = new SecurityToken(user, tokenHash, SecurityTokenType.EMAIL_VERIFICATION,
                Instant.now().plus(Duration.ofHours(24)));
        tokenRepository.save(token);

        emailService.sendVerificationEmail(email, rawToken);
        return rawToken;
    }

    @Transactional
    public Optional<String> requestPasswordReset(String rawEmail) {
        String email = normalizeEmail(rawEmail);
        Optional<AppUser> optUser = userRepository.findByEmail(email);
        if (optUser.isEmpty()) {
            return Optional.empty();
        }

        AppUser user = optUser.get();
        if (user.getStatus() != AccountStatus.ACTIVE) {
            return Optional.empty();
        }

        String rawToken = UUID.randomUUID().toString();
        String tokenHash = AesGcmCryptoService.sha256Hex(rawToken);
        SecurityToken token = new SecurityToken(user, tokenHash, SecurityTokenType.PASSWORD_RESET,
                Instant.now().plus(Duration.ofMinutes(30)));
        tokenRepository.save(token);

        emailService.sendPasswordResetEmail(email, rawToken);
        auditService.record(AuditEventType.PASSWORD_RESET_REQUESTED, user.getUsername(), user.getUsername(), "127.0.0.1", "System", "Yêu cầu đặt lại mật khẩu");

        return Optional.of(rawToken);
    }

    @Transactional
    public void resetPasswordWithToken(String rawToken, String newPassword) {
        String tokenHash = AesGcmCryptoService.sha256Hex(rawToken);
        SecurityToken token = tokenRepository.findByTokenHashAndTokenType(tokenHash, SecurityTokenType.PASSWORD_RESET)
                .orElseThrow(() -> new IllegalStateException("Token đặt lại mật khẩu không hợp lệ"));

        if (token.isUsed()) {
            throw new IllegalStateException("Token đặt lại mật khẩu đã được sử dụng");
        }
        if (token.isExpired()) {
            throw new IllegalStateException("Token đặt lại mật khẩu đã hết hạn");
        }

        AppUser user = token.getUser();
        passwordPolicyValidator.validate(newPassword, user.getUsername(), user.getEmail(), user);

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setFailedLoginCount(0);
        user.setLockedUntil(null);
        user.setFirstFailedLoginAt(null);
        user.setStatus(AccountStatus.ACTIVE);
        user.setEnabled(true);

        token.setUsedAt(Instant.now());
        tokenRepository.save(token);

        passwordHistoryRepository.save(new PasswordHistory(user, user.getPasswordHash()));
        userRepository.save(user);

        // Hủy mọi phiên cũ
        sessionManagementService.revokeAllUserSessions(user.getUsername());
        auditService.record(AuditEventType.PASSWORD_RESET_COMPLETED, user.getUsername(), user.getUsername(), "127.0.0.1", "System", "Đặt lại mật khẩu thành công qua token");
    }

    @Transactional
    public void changePassword(String username, String currentPassword, String newPassword, String currentSessionId) {
        AppUser user = userRepository.findByUsername(normalize(username))
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng"));

        if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
            throw new IllegalArgumentException("Mật khẩu hiện tại không đúng");
        }

        passwordPolicyValidator.validate(newPassword, user.getUsername(), user.getEmail(), user);

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        passwordHistoryRepository.save(new PasswordHistory(user, user.getPasswordHash()));

        // F9: Phiên hiện tại giữ nguyên, phiên khác bị hủy
        sessionManagementService.revokeAllUserSessionsExcept(user.getUsername(), currentSessionId);
        auditService.record(AuditEventType.PASSWORD_CHANGED, username, username, "127.0.0.1", "System", "Đổi mật khẩu thành công");
    }

    @Transactional
    public String inviteStaffAccount(String rawUsername, String rawEmail, String fullName, String roleName) {
        String username = normalize(rawUsername);
        String email = normalizeEmail(rawEmail);

        if (userRepository.existsByUsername(username)) {
            throw new UsernameAlreadyExistsException(username);
        }
        if (email != null && userRepository.existsByEmail(email)) {
            throw new EmailAlreadyExistsException(email);
        }

        Role role = roleRepository.findByName(roleName)
                .orElseGet(() -> roleRepository.save(new Role(roleName)));
        Role userRole = roleRepository.findByName(Role.USER)
                .orElseGet(() -> roleRepository.save(new Role(Role.USER)));

        AppUser user = new AppUser(username, email, "{noop}INVITED_NO_PASSWORD", AccountStatus.INVITED);
        user.setFullName(fullName);
        user.getRoles().add(role);
        user.getRoles().add(userRole);

        AppUser saved = userRepository.saveAndFlush(user);

        String rawToken = UUID.randomUUID().toString();
        String tokenHash = AesGcmCryptoService.sha256Hex(rawToken);
        SecurityToken token = new SecurityToken(saved, tokenHash, SecurityTokenType.STAFF_INVITATION,
                Instant.now().plus(Duration.ofHours(24)));
        tokenRepository.save(token);

        emailService.sendInvitationEmail(email, rawToken, roleName);
        auditService.record(AuditEventType.STAFF_INVITED, "ADMIN", username, "127.0.0.1", "System", "Mời tài khoản với vai trò " + roleName);

        return rawToken;
    }

    @Transactional
    public AppUser acceptInvitation(String rawToken, String newPassword) {
        String tokenHash = AesGcmCryptoService.sha256Hex(rawToken);
        SecurityToken token = tokenRepository.findByTokenHashAndTokenType(tokenHash, SecurityTokenType.STAFF_INVITATION)
                .orElseThrow(() -> new IllegalStateException("Token lời mời không hợp lệ"));

        if (token.isUsed()) {
            throw new IllegalStateException("Token lời mời đã được sử dụng");
        }
        if (token.isExpired()) {
            throw new IllegalStateException("Token lời mời đã hết hạn");
        }

        AppUser user = token.getUser();
        passwordPolicyValidator.validate(newPassword, user.getUsername(), user.getEmail(), user);

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setStatus(AccountStatus.ACTIVE);
        user.setEnabled(true);

        token.setUsedAt(Instant.now());
        tokenRepository.save(token);

        AppUser saved = userRepository.save(user);
        passwordHistoryRepository.save(new PasswordHistory(saved, saved.getPasswordHash()));

        auditService.record(AuditEventType.INVITATION_ACCEPTED, user.getUsername(), user.getUsername(), "127.0.0.1", "System", "Kích hoạt tài khoản nhân viên");
        return saved;
    }

    @Transactional
    public List<String> enableTotp(String username, String base32Secret, String verificationCode) {
        if (!totpService.verifyCode(base32Secret, verificationCode)) {
            throw new IllegalArgumentException("Mã xác thực TOTP không chính xác");
        }

        AppUser user = userRepository.findByUsername(normalize(username))
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng"));

        user.setTotpEnabled(true);
        user.setTotpSecretEnc(cryptoService.encrypt(base32Secret));
        userRepository.save(user);

        totpRecoveryCodeRepository.deleteByUser(user);

        List<String> recoveryCodes = new ArrayList<>(10);
        for (int i = 0; i < 10; i++) {
            String code = generateRandomAlphaNumeric(8);
            recoveryCodes.add(code);
            String codeHash = AesGcmCryptoService.sha256Hex(code);
            totpRecoveryCodeRepository.save(new TotpRecoveryCode(user, codeHash));
        }

        auditService.record(AuditEventType.TWO_FACTOR_ENABLED, username, username, "127.0.0.1", "System", "Bật xác thực 2 bước (TOTP)");
        return recoveryCodes;
    }

    @Transactional
    public boolean verifyTotpOrRecoveryCode(String username, String code) {
        if (code == null || code.isBlank()) return false;
        AppUser user = userRepository.findByUsername(normalize(username)).orElse(null);
        if (user == null || !user.isTotpEnabled() || user.getTotpSecretEnc() == null) {
            return false;
        }

        String decryptedSecret = cryptoService.decrypt(user.getTotpSecretEnc());
        if (totpService.verifyCode(decryptedSecret, code)) {
            return true;
        }

        String codeHash = AesGcmCryptoService.sha256Hex(code.trim());
        List<TotpRecoveryCode> codes = totpRecoveryCodeRepository.findByUserAndUsedFalse(user);
        for (TotpRecoveryCode rc : codes) {
            if (rc.getCodeHash().equals(codeHash)) {
                rc.setUsed(true);
                rc.setUsedAt(Instant.now());
                totpRecoveryCodeRepository.save(rc);
                return true;
            }
        }

        return false;
    }

    @Transactional
    public void disableTotp(String username, String password) {
        AppUser user = userRepository.findByUsername(normalize(username))
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng"));

        if (user.hasRole(Role.LECTURER) || user.hasRole(Role.ADMIN)) {
            throw new IllegalStateException("Xác thực 2 bước là bắt buộc đối với Giảng viên và Quản trị viên");
        }

        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new IllegalArgumentException("Mật khẩu không chính xác");
        }

        user.setTotpEnabled(false);
        user.setTotpSecretEnc(null);
        userRepository.save(user);

        totpRecoveryCodeRepository.deleteByUser(user);
        auditService.record(AuditEventType.TWO_FACTOR_DISABLED, username, username, "127.0.0.1", "System", "Tắt xác thực 2 bước");
    }

    @Transactional
    public void adminDeleteUser(Long targetUserId, String currentAdminUsername) {
        AppUser target = userRepository.findById(targetUserId)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng"));

        if (target.getUsername().equalsIgnoreCase(currentAdminUsername)) {
            throw new IllegalStateException("ADMIN không thể tự xóa tài khoản của mình");
        }

        if (target.hasRole(Role.ADMIN)) {
            long activeAdmins = userRepository.countByRoleNameAndStatus(Role.ADMIN, AccountStatus.ACTIVE);
            if (activeAdmins <= 1 && target.getStatus() == AccountStatus.ACTIVE) {
                throw new IllegalStateException("Hệ thống phải luôn có ít nhất 1 ADMIN đang hoạt động");
            }
        }

        sessionManagementService.revokeAllUserSessions(target.getUsername());
        userRepository.delete(target);
        auditService.record(AuditEventType.ACCOUNT_DISABLED, currentAdminUsername, target.getUsername(), "127.0.0.1", "Admin", "Xóa tài khoản");
    }

    @Transactional
    public void adminUpdateRoles(Long targetUserId, Set<String> newRoleNames, String currentAdminUsername) {
        AppUser target = userRepository.findById(targetUserId)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng"));

        if (target.getUsername().equalsIgnoreCase(currentAdminUsername) && !newRoleNames.contains(Role.ADMIN)) {
            throw new IllegalStateException("ADMIN không thể tự gỡ quyền ADMIN của mình");
        }

        if (target.hasRole(Role.ADMIN) && !newRoleNames.contains(Role.ADMIN)) {
            long activeAdmins = userRepository.countByRoleNameAndStatus(Role.ADMIN, AccountStatus.ACTIVE);
            if (activeAdmins <= 1 && target.getStatus() == AccountStatus.ACTIVE) {
                throw new IllegalStateException("Hệ thống phải luôn có ít nhất 1 ADMIN đang hoạt động");
            }
        }

        Set<Role> roles = new HashSet<>();
        for (String rName : newRoleNames) {
            Role role = roleRepository.findByName(rName)
                    .orElseGet(() -> roleRepository.save(new Role(rName)));
            roles.add(role);
        }
        target.setRoles(roles);
        userRepository.save(target);

        auditService.record(AuditEventType.ROLE_CHANGED, currentAdminUsername, target.getUsername(), "127.0.0.1", "Admin", "Cập nhật vai trò thành: " + newRoleNames);
    }

    @Transactional
    public void adminUpdateStatus(Long targetUserId, AccountStatus newStatus, String currentAdminUsername) {
        AppUser target = userRepository.findById(targetUserId)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng"));

        if (target.hasRole(Role.ADMIN) && newStatus != AccountStatus.ACTIVE) {
            long activeAdmins = userRepository.countByRoleNameAndStatus(Role.ADMIN, AccountStatus.ACTIVE);
            if (activeAdmins <= 1 && target.getStatus() == AccountStatus.ACTIVE) {
                throw new IllegalStateException("Hệ thống phải luôn có ít nhất 1 ADMIN đang hoạt động");
            }
        }

        target.setStatus(newStatus);
        target.setEnabled(newStatus == AccountStatus.ACTIVE);
        if (newStatus == AccountStatus.ACTIVE) {
            target.setFailedLoginCount(0);
            target.setLockedUntil(null);
            target.setFirstFailedLoginAt(null);
        } else if (newStatus == AccountStatus.DISABLED || newStatus == AccountStatus.LOCKED) {
            sessionManagementService.revokeAllUserSessions(target.getUsername());
        }

        userRepository.save(target);

        AuditEventType evt = switch (newStatus) {
            case ACTIVE -> AuditEventType.ACCOUNT_ACTIVATED;
            case LOCKED -> AuditEventType.ACCOUNT_LOCKED;
            case DISABLED -> AuditEventType.ACCOUNT_DISABLED;
            default -> AuditEventType.ROLE_CHANGED;
        };
        auditService.record(evt, currentAdminUsername, target.getUsername(), "127.0.0.1", "Admin", "Cập nhật trạng thái thành " + newStatus);
    }

    @Transactional
    public void updateFullName(String username, String fullName) {
        AppUser user = userRepository.findByUsername(normalize(username))
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng"));
        user.setFullName(fullName);
        userRepository.save(user);
    }

    private String generateRandomAlphaNumeric(int length) {
        String chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(secureRandom.nextInt(chars.length())));
        }
        return sb.toString();
    }
}
