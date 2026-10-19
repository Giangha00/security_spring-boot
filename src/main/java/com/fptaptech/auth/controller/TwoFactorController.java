package com.fptaptech.auth.controller;

import com.fptaptech.auth.entity.AppUser;
import com.fptaptech.auth.entity.Role;
import com.fptaptech.auth.repository.UserRepository;
import com.fptaptech.auth.service.TotpService;
import com.fptaptech.auth.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Controller
public class TwoFactorController {

    private final UserService userService;
    private final TotpService totpService;
    private final UserRepository userRepository;

    public TwoFactorController(UserService userService, TotpService totpService, UserRepository userRepository) {
        this.userService = userService;
        this.totpService = totpService;
        this.userRepository = userRepository;
    }

    @GetMapping("/2fa/setup")
    String setupForm(Authentication authentication, Model model) {
        AppUser user = userRepository.findByUsername(UserService.normalize(authentication.getName())).orElseThrow();
        boolean mandatory = user.hasRole(Role.LECTURER) || user.hasRole(Role.ADMIN);
        String secret = totpService.generateBase32Secret();

        model.addAttribute("secret", secret);
        model.addAttribute("mandatory", mandatory);
        model.addAttribute("totpEnabled", user.isTotpEnabled());
        return "totp-setup";
    }

    @PostMapping("/2fa/setup")
    String handleSetup(@RequestParam("secret") String secret,
                       @RequestParam("code") String code,
                       Authentication authentication,
                       Model model) {
        AppUser user = userRepository.findByUsername(UserService.normalize(authentication.getName())).orElseThrow();
        boolean mandatory = user.hasRole(Role.LECTURER) || user.hasRole(Role.ADMIN);

        try {
            List<String> recoveryCodes = userService.enableTotp(authentication.getName(), secret, code);
            model.addAttribute("recoveryCodes", recoveryCodes);
            model.addAttribute("mandatory", mandatory);
            model.addAttribute("totpEnabled", true);
            return "totp-setup";
        } catch (Exception e) {
            model.addAttribute("error", e.getMessage());
            model.addAttribute("secret", secret);
            model.addAttribute("mandatory", mandatory);
            model.addAttribute("totpEnabled", user.isTotpEnabled());
            return "totp-setup";
        }
    }

    @PostMapping("/2fa/disable")
    String handleDisable(@RequestParam("currentPassword") String currentPassword,
                         Authentication authentication) {
        try {
            userService.disableTotp(authentication.getName(), currentPassword);
            return "redirect:/profile?totpDisabled";
        } catch (Exception e) {
            return "redirect:/2fa/setup?error=" + URLEncoder.encode(e.getMessage(), StandardCharsets.UTF_8);
        }
    }

    @GetMapping("/2fa/verify")
    String verifyForm() {
        return "totp-verify";
    }

    @PostMapping("/2fa/verify")
    String handleVerify(@RequestParam("code") String code,
                        Authentication authentication,
                        Model model) {
        boolean valid = userService.verifyTotpOrRecoveryCode(authentication.getName(), code);
        if (valid) {
            return "redirect:/";
        }
        model.addAttribute("error", "Mã xác thực hoặc mã khôi phục không đúng");
        return "totp-verify";
    }
}
