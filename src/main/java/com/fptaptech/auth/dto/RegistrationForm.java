package com.fptaptech.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

@PasswordsMatch
public class RegistrationForm {

    @NotBlank(message = "{registration.required}")
    @Size(min = 3, max = 32, message = "{registration.username.size}")
    @Pattern(regexp = "^[A-Za-z0-9._-]*$", message = "{registration.username.pattern}")
    private String username;

    private String email;

    @NotBlank(message = "{registration.required}")
    @Size(min = 8, max = 64, message = "{registration.password.size}")
    private String password;

    @NotBlank(message = "{registration.required}")
    private String passwordConfirm;

    public void clearPasswords() {
        this.password = "";
        this.passwordConfirm = "";
    }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public String getPasswordConfirm() { return passwordConfirm; }
    public void setPasswordConfirm(String passwordConfirm) { this.passwordConfirm = passwordConfirm; }
}
