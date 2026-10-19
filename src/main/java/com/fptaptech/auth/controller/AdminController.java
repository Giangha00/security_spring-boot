package com.fptaptech.auth.controller;

import com.fptaptech.auth.entity.AccountStatus;
import com.fptaptech.auth.entity.AppUser;
import com.fptaptech.auth.entity.AuditEventType;
import com.fptaptech.auth.entity.AuditLog;
import com.fptaptech.auth.repository.AuditLogRepository;
import com.fptaptech.auth.repository.UserRepository;
import com.fptaptech.auth.service.SessionManagementService;
import com.fptaptech.auth.service.UserService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@Controller
public class AdminController {

    private final UserRepository userRepository;
    private final UserService userService;
    private final SessionManagementService sessionManagementService;
    private final AuditLogRepository auditLogRepository;

    public AdminController(UserRepository userRepository,
                           UserService userService,
                           SessionManagementService sessionManagementService,
                           AuditLogRepository auditLogRepository) {
        this.userRepository = userRepository;
        this.userService = userService;
        this.sessionManagementService = sessionManagementService;
        this.auditLogRepository = auditLogRepository;
    }

    @GetMapping("/admin")
    String adminRoot() {
        return "redirect:/admin/users";
    }

    @GetMapping("/admin/users")
    String listUsers(@RequestParam(value = "keyword", required = false) String keyword,
                     @RequestParam(value = "role", required = false) String role,
                     @RequestParam(value = "status", required = false) AccountStatus status,
                     @RequestParam(value = "page", defaultValue = "0") int page,
                     Model model) {
        Pageable pageable = PageRequest.of(page, 20);
        Page<AppUser> userPage = userRepository.searchUsers(keyword, role, status, pageable);

        model.addAttribute("userPage", userPage);
        model.addAttribute("keyword", keyword);
        model.addAttribute("selectedRole", role);
        model.addAttribute("selectedStatus", status);
        model.addAttribute("statuses", AccountStatus.values());
        return "admin-users";
    }

    @PostMapping("/admin/users/invite")
    String inviteStaff(@RequestParam("username") String username,
                       @RequestParam("email") String email,
                       @RequestParam(value = "fullName", required = false) String fullName,
                       @RequestParam("role") String role,
                       Model model) {
        try {
            userService.inviteStaffAccount(username, email, fullName, role);
            return "redirect:/admin/users?invited";
        } catch (Exception e) {
            model.addAttribute("error", e.getMessage());
            return listUsers(null, null, null, 0, model);
        }
    }

    @PostMapping("/admin/users/{id}/status")
    String updateStatus(@PathVariable("id") Long id,
                        @RequestParam("status") AccountStatus status,
                        Authentication authentication) {
        userService.adminUpdateStatus(id, status, authentication.getName());
        return "redirect:/admin/users?statusChanged";
    }

    @PostMapping("/admin/users/{id}/force-logout")
    String forceLogout(@PathVariable("id") Long id) {
        userRepository.findById(id).ifPresent(u -> sessionManagementService.revokeAllUserSessions(u.getUsername()));
        return "redirect:/admin/users?forcedLogout";
    }

    @PostMapping("/admin/users/{id}/roles")
    String updateRoles(@PathVariable("id") Long id,
                       @RequestParam("roles") Set<String> roles,
                       Authentication authentication) {
        userService.adminUpdateRoles(id, roles, authentication.getName());
        return "redirect:/admin/users?rolesUpdated";
    }

    @GetMapping("/admin/audit-logs")
    String auditLogs(@RequestParam(value = "eventType", required = false) AuditEventType eventType,
                     @RequestParam(value = "username", required = false) String username,
                     @RequestParam(value = "page", defaultValue = "0") int page,
                     Model model) {
        Pageable pageable = PageRequest.of(page, 20);
        Page<AuditLog> logPage;

        if (eventType != null && username != null && !username.isBlank()) {
            logPage = auditLogRepository.searchByEventTypeAndKeyword(eventType, username.trim(), pageable);
        } else if (eventType != null) {
            logPage = auditLogRepository.findByEventTypeOrderByCreatedAtDesc(eventType, pageable);
        } else if (username != null && !username.isBlank()) {
            logPage = auditLogRepository.searchByKeyword(username.trim(), pageable);
        } else {
            logPage = auditLogRepository.findAllByOrderByCreatedAtDesc(pageable);
        }

        model.addAttribute("logPage", logPage);
        model.addAttribute("eventTypes", AuditEventType.values());
        model.addAttribute("selectedEventType", eventType);
        model.addAttribute("username", username);
        return "admin-audit-logs";
    }
}
