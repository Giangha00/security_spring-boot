package com.fptaptech.auth.service;

public class UsernameAlreadyExistsException extends RuntimeException {
    public UsernameAlreadyExistsException(String username) {
        super("Username đã tồn tại: " + username);
    }
}
