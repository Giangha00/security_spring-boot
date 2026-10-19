package com.fptaptech.auth.repository;

import com.fptaptech.auth.entity.AppUser;
import com.fptaptech.auth.entity.SecurityToken;
import com.fptaptech.auth.entity.SecurityTokenType;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface SecurityTokenRepository extends JpaRepository<SecurityToken, Long> {

    Optional<SecurityToken> findByTokenHashAndTokenType(String tokenHash, SecurityTokenType tokenType);

    List<SecurityToken> findByUserAndTokenType(AppUser user, SecurityTokenType tokenType);

    void deleteByUserAndTokenType(AppUser user, SecurityTokenType tokenType);
}
