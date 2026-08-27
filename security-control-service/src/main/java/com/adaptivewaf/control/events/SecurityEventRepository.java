package com.adaptivewaf.control.events;

import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityEventRepository extends JpaRepository<PersistedSecurityEvent, Long> {
    boolean existsByEventId(String eventId);

    /** Request-shaped entries only; an escalation is a later revision of a request rather than a request itself. */
    List<PersistedSecurityEvent> findByCategoryNotOrderByOccurredAtDesc(String category, Pageable pageable);
}
