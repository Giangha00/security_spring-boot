package com.fptaptech.auth.controller;

import com.fptaptech.auth.service.RateLimitService;
import com.fptaptech.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class PasswordController {

    public static final String UNIFIED_FORGOT_PASSWORD_MESSAGE = "Nếu email tồn tại trong hệ thống, hướng dẫn đặt lại mật khẩu đã được gửi đến hộp thư của bạn.";

    private final UserService userService;
    private final RateLimitService rateLimitService;

    public PasswordController(UserService userService, RateLimitService rateLimitService) {
        this.userService = userService;
        this.rateLimitService = rateLimitService;
    }

    @GetMapping("/password/forgot")
    String forgotPasswordForm() {
        return "forgot-password";
    }

    @PostMapping("/password/forgot")
    String handleForgotPassword(@RequestParam("email") String email, HttpServletRequest request, Model model) {
        String ip = getClientIp(request);
        if (!rateLimitService.allowForgotPassword(ip)) {
            model.addAttribute("error", "Đã vượt quá giới hạn gửi yêu cầu quên mật khẩu (tối đa 20 lần/giờ).");
            return "forgot-password";
        }

        userService.requestPasswordReset(email);
        model.addAttribute("message", UNIFIED_FORGOT_PASSWORD_MESSAGE);
        return "forgot-password";
    }

    @GetMapping("/password/reset")
    String resetPasswordForm(@RequestParam("token") String token, Model model) {
        model.addAttribute("token", token);
        model.addAttribute("inviteMode", false);
        return "reset-password";
    }

    @PostMapping("/password/reset")
    String handleResetPassword(@RequestParam("token") String token,
                               @RequestParam("password") String password,
                               @RequestParam("passwordConfirm") String passwordConfirm,
                               Model model) {
        model.addAttribute("token", token);
        model.addAttribute("inviteMode", false);

        if (!password.equals(passwordConfirm)) {
            model.addAttribute("error", "Mật khẩu xác nhận không khớp");
            return "reset-password";
        }

        try {
            userService.resetPasswordWithToken(token, password);
            return "redirect:/login?resetSuccess";
        } catch (Exception e) {
            model.addAttribute("error", e.getMessage());
            return "reset-password";
        }
    }

    @GetMapping("/invite/accept")
    String acceptInviteForm(@RequestParam("token") String token, Model model) {
        model.addAttribute("token", token);
        model.addAttribute("inviteMode", true);
        return "reset-password";
    }

    @PostMapping("/invite/accept")
    String handleAcceptInvite(@RequestParam("token") String token,
                              @RequestParam("password") String password,
                              @RequestParam("passwordConfirm") String passwordConfirm,
                              Model model) {
        model.addAttribute("token", token);
        model.addAttribute("inviteMode", true);

        if (!password.equals(passwordConfirm)) {
            model.addAttribute("error", "Mật khẩu xác nhận không khớp");
            return "reset-password";
        }

        try {
            userService.acceptInvitation(token, password);
            return "redirect:/login?invitedActivated";
        } catch (Exception e) {
            model.addAttribute("error", e.getMessage());
            return "reset-password";
        }
    }

    @GetMapping("/password/change")
    String changePasswordForm() {
        return "change-password";
    }

    @PostMapping("/password/change")
    String handleChangePassword(@RequestParam("currentPassword") String currentPassword,
                                @RequestParam("newPassword") String newPassword,
                                @RequestParam("passwordConfirm") String passwordConfirm,
                                Authentication authentication,
                                HttpServletRequest request,
                                Model model) {
        if (!newPassword.equals(passwordConfirm)) {
            model.addAttribute("error", "Mật khẩu xác nhận không khớp");
            return "change-password";
        }

        String sessionId = null;
        HttpSession session = request.getSession(false);
        if (session != null) {
            sessionId = session.getId();
        }

        try {
            userService.changePassword(authentication.getName(), currentPassword, newPassword, sessionId);
            model.addAttribute("success", "Cập nhật mật khẩu thành công. Các phiên đăng nhập trên thiết bị khác đã bị thu hồi.");
            return "change-password";
        } catch (Exception e) {
            model.addAttribute("error", e.getMessage());
            return "change-password";
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        if (xf != null && !xf.isBlank()) {
            return xf.split(",")[0].trim();
        }
        return request.getRemoteAddr() != null ? request.getRemoteAddr() : "127.0.0.1";
    }
}
