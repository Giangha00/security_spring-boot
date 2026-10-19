package com.fptaptech.auth.repository;

import com.fptaptech.auth.entity.AppUser;
import com.fptaptech.auth.entity.TotpRecoveryCode;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface TotpRecoveryCodeRepository extends JpaRepository<TotpRecoveryCode, Long> {

    List<TotpRecoveryCode> findByUserAndUsedFalse(AppUser user);

    List<TotpRecoveryCode> findByUser(AppUser user);

    void deleteByUser(AppUser user);
}
