package com.fptaptech.auth.repository;

import com.fptaptech.auth.entity.AuditEventType;
import com.fptaptech.auth.entity.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    Page<AuditLog> findAllByOrderByCreatedAtDesc(Pageable pageable);

    Page<AuditLog> findByEventTypeOrderByCreatedAtDesc(AuditEventType eventType, Pageable pageable);

    @Query("SELECT a FROM AuditLog a WHERE (LOWER(a.username) LIKE LOWER(CONCAT('%', :keyword, '%')) OR LOWER(a.target) LIKE LOWER(CONCAT('%', :keyword, '%'))) ORDER BY a.createdAt DESC")
    Page<AuditLog> searchByKeyword(@Param("keyword") String keyword, Pageable pageable);

    @Query("SELECT a FROM AuditLog a WHERE a.eventType = :eventType AND (LOWER(a.username) LIKE LOWER(CONCAT('%', :keyword, '%')) OR LOWER(a.target) LIKE LOWER(CONCAT('%', :keyword, '%'))) ORDER BY a.createdAt DESC")
    Page<AuditLog> searchByEventTypeAndKeyword(@Param("eventType") AuditEventType eventType, @Param("keyword") String keyword, Pageable pageable);
}
