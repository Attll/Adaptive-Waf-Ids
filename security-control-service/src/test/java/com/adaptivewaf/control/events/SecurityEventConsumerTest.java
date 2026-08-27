package com.adaptivewaf.control.events;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

class SecurityEventConsumerTest {
    @Test
    void persistsSanitizedEventOnlyOnceWhenDeliveryIsDuplicated() {
        ObjectMapper objectMapper = new ObjectMapper();
        SecurityEventRepository repository = Mockito.mock(SecurityEventRepository.class);
        SecurityEventSanitizer sanitizer = new SecurityEventSanitizer(objectMapper);
        SecurityEventConsumer consumer = new SecurityEventConsumer(objectMapper, sanitizer, repository);
        String event = "{\"eventId\":\"ef3d5a26-b6f4-442d-8200-9be399058ad8\",\"occurredAt\":\"2026-08-27T04:00:00Z\",\"category\":\"security.attack\",\"requestId\":\"request-1\",\"sourceIp\":\"127.0.0.1\",\"method\":\"POST\",\"path\":\"/login\",\"statusCode\":403,\"action\":\"BLOCK\",\"predictedAttack\":\"SQL_INJECTION\",\"risk\":0.99,\"authorization\":\"Bearer secret\",\"password\":\"hidden\"}";
        when(repository.existsByEventId("ef3d5a26-b6f4-442d-8200-9be399058ad8")).thenReturn(false, true);

        consumer.consume(event);
        consumer.consume(event);

        ArgumentCaptor<PersistedSecurityEvent> persisted = ArgumentCaptor.forClass(PersistedSecurityEvent.class);
        verify(repository, times(1)).save(persisted.capture());
        assertNotEquals("127.0.0.1", persisted.getValue().getSourceHash());
        assertFalse(persisted.getValue().getDetailsJson().contains("Bearer secret"));
        assertFalse(persisted.getValue().getDetailsJson().contains("hidden"));
    }
}
