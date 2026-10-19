package com.fptaptech.auth;

import com.fptaptech.auth.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthFlowTest {

    private static final String PASSWORD = "Secret#2026";

    @Autowired
    MockMvc mvc;
    @Autowired
    UserService userService;

    @Test
    void anonymousUserIsRedirectedToLogin() throws Exception {
        mvc.perform(get("/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));
    }

    @Test
    void registrationLogsUserInAutomatically() throws Exception {
        mvc.perform(post("/registration").with(csrf())
                .param("username", "Alice")
                .param("password", PASSWORD)
                .param("passwordConfirm", PASSWORD))
                .andExpect(redirectedUrl("/"))
                .andExpect(authenticated().withUsername("alice").withRoles("USER"));
    }

    @Test
    void duplicateUsernameIsRejected() throws Exception {
        userService.register("bob", PASSWORD);
        mvc.perform(post("/registration").with(csrf())
                .param("username", "BOB")
                .param("password", PASSWORD)
                .param("passwordConfirm", PASSWORD))
                .andExpect(status().isOk())
                .andExpect(model().attributeHasFieldErrorCode("form", "username",
                        "registration.username.duplicate"))
                .andExpect(unauthenticated());
    }

    @Test
    void mismatchedPasswordsAreRejected() throws Exception {
        mvc.perform(post("/registration").with(csrf())
                .param("username", "dave")
                .param("password", PASSWORD)
                .param("passwordConfirm", "Other#2026"))
                .andExpect(status().isOk())
                .andExpect(model().attributeHasFieldErrors("form", "passwordConfirm"));
    }

    @Test
    void formLoginWithValidCredentialsSucceeds() throws Exception {
        userService.register("carol", PASSWORD);
        mvc.perform(formLogin("/login").user("carol").password(PASSWORD))
                .andExpect(authenticated().withUsername("carol"));
    }

    @Test
    void wrongPasswordRedirectsToLoginError() throws Exception {
        userService.register("erin", PASSWORD);
        mvc.perform(formLogin("/login").user("erin").password("wrong-password"))
                .andExpect(redirectedUrl("/login?error"))
                .andExpect(unauthenticated());
    }

    @Test
    void postWithoutCsrfTokenIsForbidden() throws Exception {
        mvc.perform(post("/registration").param("username", "frank"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "USER")
    void regularUserCannotOpenAdminArea() throws Exception {
        mvc.perform(get("/admin"))
                .andExpect(status().isForbidden());
    }
}
