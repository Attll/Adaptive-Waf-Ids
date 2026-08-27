package com.adaptivewaf.control.events;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class SecurityEventConsumer {
    private final ObjectMapper objectMapper;
    private final SecurityEventSanitizer sanitizer;
    private final SecurityEventRepository repository;

    public SecurityEventConsumer(ObjectMapper objectMapper, SecurityEventSanitizer sanitizer, SecurityEventRepository repository) {
        this.objectMapper = objectMapper;
        this.sanitizer = sanitizer;
        this.repository = repository;
    }

    @RabbitListener(queues = "security.events.persist")
    @Transactional
    public void consume(String payload) {
        try {
            JsonNode event = objectMapper.readTree(payload);
            String eventId = requiredText(event, "eventId");
            if (repository.existsByEventId(eventId)) { return; }
            repository.save(new PersistedSecurityEvent(
                eventId,
                Instant.parse(requiredText(event, "occurredAt")),
                requiredText(event, "category"),
                event.path("requestId").asText(null),
                sanitizer.hash(event.path("sourceIp").asText(null)),
                event.path("method").asText(null),
                event.path("path").asText(null),
                event.path("statusCode").asInt(0),
                event.path("action").asText(null),
                event.path("predictedAttack").asText(null),
                event.path("risk").asDouble(0.0),
                sanitizer.json(event)
            ));
        } catch (Exception error) {
            throw new IllegalArgumentException("security event could not be persisted", error);
        }
    }

    private String requiredText(JsonNode event, String field) {
        String value = event.path(field).asText();
        if (value == null || value.isBlank()) { throw new IllegalArgumentException("missing event field " + field); }
        return value;
    }
}
