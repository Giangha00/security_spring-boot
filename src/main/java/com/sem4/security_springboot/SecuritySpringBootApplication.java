package com.sem4.security_springboot;

import com.fptaptech.auth.AuthApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.fptaptech.auth")
public class SecuritySpringBootApplication {

    public static void main(String[] args) {
        AuthApplication.main(args);
    }
}
