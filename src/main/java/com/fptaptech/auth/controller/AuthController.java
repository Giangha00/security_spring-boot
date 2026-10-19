package com.fptaptech.auth.controller;

import com.fptaptech.auth.dto.RegistrationForm;
import com.fptaptech.auth.service.AutoLogin;
import com.fptaptech.auth.service.EmailAlreadyExistsException;
import com.fptaptech.auth.service.PasswordPolicyException;
import com.fptaptech.auth.service.RateLimitService;
import com.fptaptech.auth.service.UserService;
import com.fptaptech.auth.service.UsernameAlreadyExistsException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthController {

    private final UserService userService;
    private final AutoLogin autoLogin;
    private final RateLimitService rateLimitService;

    public AuthController(UserService userService, AutoLogin autoLogin, RateLimitService rateLimitService) {
        this.userService = userService;
        this.autoLogin = autoLogin;
        this.rateLimitService = rateLimitService;
    }

    @GetMapping("/registration")
    String registrationForm(Authentication authentication, Model model) {
        if (authentication != null && authentication.isAuthenticated() && !"anonymousUser".equals(authentication.getName())) {
            return "redirect:/";
        }
        model.addAttribute("form", new RegistrationForm());
        return "registration";
    }

    @PostMapping("/registration")
    String register(@Valid @ModelAttribute("form") RegistrationForm form,
                    BindingResult result,
                    HttpServletRequest request,
                    HttpServletResponse response,
                    Model model) {

        String ip = getClientIp(request);
        if (!rateLimitService.allowRegistration(ip)) {
            model.addAttribute("rateLimitError", "Đã vượt quá giới hạn 10 lần đăng ký mỗi giờ từ địa chỉ IP này.");
            form.clearPasswords();
            return "registration";
        }

        if (result.hasErrors()) {
            form.clearPasswords();
            return "registration";
        }

        if (form.getEmail() != null && !form.getEmail().isBlank()) {
            try {
                userService.registerStudent(form.getUsername(), form.getEmail(), form.getPassword());
                return "redirect:/login?registered";
            } catch (UsernameAlreadyExistsException e) {
                result.rejectValue("username", "registration.username.duplicate");
                form.clearPasswords();
                return "registration";
            } catch (EmailAlreadyExistsException e) {
                result.rejectValue("email", "registration.email.duplicate", "Email này đã được sử dụng");
                form.clearPasswords();
                return "registration";
            } catch (PasswordPolicyException e) {
                result.rejectValue("password", "registration.password.policy", e.getMessage());
                form.clearPasswords();
                return "registration";
            }
        }

        try {
            userService.register(form.getUsername(), form.getPassword());
        } catch (UsernameAlreadyExistsException e) {
            result.rejectValue("username", "registration.username.duplicate");
            form.clearPasswords();
            return "registration";
        }

        autoLogin.login(form.getUsername(), request, response);
        return "redirect:/";
    }

    @GetMapping("/verify-email")
    String verifyEmail(@RequestParam("token") String token) {
        try {
            userService.verifyEmailToken(token);
            return "redirect:/login?verified";
        } catch (Exception e) {
            return "redirect:/login?error";
        }
    }

    @GetMapping("/login")
    String login(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated() && !"anonymousUser".equals(authentication.getName())) {
            return "redirect:/";
        }
        return "login";
    }

    @GetMapping("/")
    String welcome() {
        return "welcome";
    }

    private String getClientIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        if (xf != null && !xf.isBlank()) {
            return xf.split(",")[0].trim();
        }
        return request.getRemoteAddr() != null ? request.getRemoteAddr() : "127.0.0.1";
    }
}
