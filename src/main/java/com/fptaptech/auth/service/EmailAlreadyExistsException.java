package com.fptaptech.auth.service;

public class EmailAlreadyExistsException extends RuntimeException {
    public EmailAlreadyExistsException(String email) {
        super("Email đã tồn tại: " + email);
    }
}
