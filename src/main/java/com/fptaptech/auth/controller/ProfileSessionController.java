package com.fptaptech.auth.controller;

import com.fptaptech.auth.entity.AppUser;
import com.fptaptech.auth.entity.UserSession;
import com.fptaptech.auth.repository.UserRepository;
import com.fptaptech.auth.service.SessionManagementService;
import com.fptaptech.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Controller
public class ProfileSessionController {

    private final UserRepository userRepository;
    private final UserService userService;
    private final SessionManagementService sessionManagementService;

    public ProfileSessionController(UserRepository userRepository,
                                    UserService userService,
                                    SessionManagementService sessionManagementService) {
        this.userRepository = userRepository;
        this.userService = userService;
        this.sessionManagementService = sessionManagementService;
    }

    @GetMapping("/profile")
    String profile(Authentication authentication, Model model) {
        AppUser user = userRepository.findByUsername(UserService.normalize(authentication.getName())).orElse(null);
        model.addAttribute("user", user);
        return "profile";
    }

    @PostMapping("/profile")
    String updateProfile(@RequestParam("fullName") String fullName, Authentication authentication, Model model) {
        userService.updateFullName(authentication.getName(), fullName);
        AppUser user = userRepository.findByUsername(UserService.normalize(authentication.getName())).orElse(null);
        model.addAttribute("user", user);
        model.addAttribute("success", "Cập nhật thông tin thành công");
        return "profile";
    }

    @GetMapping("/sessions")
    String sessions(Authentication authentication, HttpServletRequest request, Model model) {
        List<UserSession> sessions = sessionManagementService.getActiveSessions(authentication.getName());
        String currentSessionId = "";
        HttpSession httpSession = request.getSession(false);
        if (httpSession != null) {
            currentSessionId = httpSession.getId();
        }

        model.addAttribute("sessions", sessions);
        model.addAttribute("currentSessionId", currentSessionId);
        return "sessions";
    }

    @PostMapping("/sessions/{id}/revoke")
    String revokeSession(@PathVariable("id") Long id, Authentication authentication) {
        sessionManagementService.revokeSessionById(id, authentication.getName());
        return "redirect:/sessions?revoked";
    }
}
