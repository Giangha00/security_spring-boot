package com.fptaptech.auth.repository;

import com.fptaptech.auth.entity.AppUser;
import com.fptaptech.auth.entity.PasswordHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface PasswordHistoryRepository extends JpaRepository<PasswordHistory, Long> {

    List<PasswordHistory> findTop5ByUserOrderByCreatedAtDesc(AppUser user);

    List<PasswordHistory> findByUserOrderByCreatedAtDesc(AppUser user);

    void deleteByUser(AppUser user);
}
