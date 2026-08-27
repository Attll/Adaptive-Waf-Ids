package com.adaptivewaf.control.events;

import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityEventRepository extends JpaRepository<PersistedSecurityEvent, Long> {
    boolean existsByEventId(String eventId);
}
