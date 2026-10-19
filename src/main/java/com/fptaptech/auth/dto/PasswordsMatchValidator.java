package com.fptaptech.auth.dto;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.util.Objects;

public class PasswordsMatchValidator implements ConstraintValidator<PasswordsMatch, RegistrationForm> {

    @Override
    public boolean isValid(RegistrationForm form, ConstraintValidatorContext context) {
        if (form == null) return true;
        if (form.getPassword() == null || form.getPasswordConfirm() == null) {
            return true; // để @NotBlank báo lỗi
        }
        if (Objects.equals(form.getPassword(), form.getPasswordConfirm())) {
            return true;
        }
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(context.getDefaultConstraintMessageTemplate())
                .addPropertyNode("passwordConfirm")
                .addConstraintViolation();
        return false;
    }
}
