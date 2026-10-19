package com.fptaptech.auth.repository;

import com.fptaptech.auth.entity.AppUser;
import com.fptaptech.auth.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    Optional<UserSession> findBySessionId(String sessionId);

    List<UserSession> findByUsernameAndRevokedFalseOrderByCreatedAtAsc(String username);

    List<UserSession> findByUsernameAndRevokedFalseOrderByCreatedAtDesc(String username);

    List<UserSession> findByUserAndRevokedFalse(AppUser user);

    List<UserSession> findByUsername(String username);

    void deleteByUser(AppUser user);
}
