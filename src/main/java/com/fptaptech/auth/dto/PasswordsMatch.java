package com.fptaptech.auth.dto;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Documented
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = PasswordsMatchValidator.class)
public @interface PasswordsMatch {
    String message() default "{registration.passwords.mismatch}";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
