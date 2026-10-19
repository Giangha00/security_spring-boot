package com.fptaptech.auth.repository;

import com.fptaptech.auth.entity.AccountStatus;
import com.fptaptech.auth.entity.AppUser;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<AppUser, Long> {

    @EntityGraph(attributePaths = "roles")
    Optional<AppUser> findByUsername(String username);

    @EntityGraph(attributePaths = "roles")
    Optional<AppUser> findByEmail(String email);

    @EntityGraph(attributePaths = "roles")
    Optional<AppUser> findById(Long id);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    @Query("SELECT COUNT(u) FROM AppUser u JOIN u.roles r WHERE r.name = :roleName AND u.status = :status")
    long countByRoleNameAndStatus(@Param("roleName") String roleName, @Param("status") AccountStatus status);

    @EntityGraph(attributePaths = "roles")
    @Query("SELECT DISTINCT u FROM AppUser u LEFT JOIN u.roles r WHERE " +
           "(:keyword IS NULL OR :keyword = '' OR LOWER(u.username) LIKE LOWER(CONCAT('%', :keyword, '%')) OR (u.email IS NOT NULL AND LOWER(u.email) LIKE LOWER(CONCAT('%', :keyword, '%')))) AND " +
           "(:roleName IS NULL OR :roleName = '' OR r.name = :roleName) AND " +
           "(:status IS NULL OR u.status = :status)")
    Page<AppUser> searchUsers(@Param("keyword") String keyword,
                              @Param("roleName") String roleName,
                              @Param("status") AccountStatus status,
                              Pageable pageable);

    @EntityGraph(attributePaths = "roles")
    @Query("SELECT DISTINCT u FROM AppUser u JOIN u.roles r WHERE r.name = 'ROLE_STUDENT' AND " +
           "(:keyword IS NULL OR :keyword = '' OR LOWER(u.username) LIKE LOWER(CONCAT('%', :keyword, '%')) OR (u.email IS NOT NULL AND LOWER(u.email) LIKE LOWER(CONCAT('%', :keyword, '%'))))")
    Page<AppUser> searchStudents(@Param("keyword") String keyword, Pageable pageable);
}
