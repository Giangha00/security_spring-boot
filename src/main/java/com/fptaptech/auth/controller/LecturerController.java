package com.fptaptech.auth.controller;

import com.fptaptech.auth.entity.AppUser;
import com.fptaptech.auth.repository.UserRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LecturerController {

    private final UserRepository userRepository;

    public LecturerController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/lecturer/students")
    String listStudents(@RequestParam(value = "keyword", required = false) String keyword,
                        @RequestParam(value = "page", defaultValue = "0") int page,
                        Model model) {
        Pageable pageable = PageRequest.of(page, 20);
        Page<AppUser> studentPage = userRepository.searchStudents(keyword, pageable);

        model.addAttribute("studentPage", studentPage);
        model.addAttribute("keyword", keyword);
        return "lecturer-students";
    }
}
