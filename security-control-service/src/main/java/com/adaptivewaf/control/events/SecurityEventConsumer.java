package com.adaptivewaf.control.events;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class SecurityEventConsumer {
    private final ObjectMapper objectMapper;
    private final SecurityEventSanitizer sanitizer;
    private final SecurityEventRepository repository;
    private final SecurityEventBroadcaster broadcaster;

    public SecurityEventConsumer(ObjectMapper objectMapper, SecurityEventSanitizer sanitizer,
                                 SecurityEventRepository repository, SecurityEventBroadcaster broadcaster) {
        this.objectMapper = objectMapper;
        this.sanitizer = sanitizer;
        this.repository = repository;
        this.broadcaster = broadcaster;
    }

    @RabbitListener(queues = "security.events.persist")
    @Transactional
    public void consume(String payload) {
        try {
            JsonNode event = objectMapper.readTree(payload);
            String eventId = requiredText(event, "eventId");
            if (repository.existsByEventId(eventId)) { return; }
            JsonNode detection = event.path("detection");
            PersistedSecurityEvent persisted = PersistedSecurityEvent.builder()
                .identity(eventId, Instant.parse(requiredText(event, "occurredAt")), requiredText(event, "category"), text(event, "requestId"))
                .request(text(event, "sourceIp"), text(event, "method"), text(event, "path"), text(event, "query"),
                    text(event, "userAgent"), text(event, "upstream"))
                .outcome(event.path("statusCode").asInt(0), text(event, "action"), text(event, "predictedAttack"),
                    event.path("risk").asDouble(0.0), text(event, "mitigation"), text(event, "mode"))
                .timings(event.path("detectionLatencyMs").asDouble(0.0), event.path("upstreamLatencyMs").asDouble(0.0),
                    event.path("gatewayLatencyMs").asDouble(0.0))
                .inference(routingPath(detection), detection.path("deep_model_used").asBoolean(false),
                    detection.path("triage").path("decision").asText(null), confidence(detection))
                .details(sanitizer.json(event))
                .build();
            repository.save(persisted);
            broadcaster.broadcast(persisted);
        } catch (Exception error) {
            throw new IllegalArgumentException("security event could not be persisted", error);
        }
    }

    private String routingPath(JsonNode detection) {
        JsonNode route = detection.path("routing_path");
        if (!route.isArray() || route.isEmpty()) { return null; }
        List<String> steps = new ArrayList<>();
        route.forEach(step -> steps.add(step.asText()));
        String joined = String.join(" > ", steps);
        return joined.length() > 512 ? joined.substring(0, 512) : joined;
    }

    /** Confidence of the stage that produced the final classification: the deep model when it ran, otherwise the strongest expert. */
    private double confidence(JsonNode detection) {
        JsonNode deep = detection.path("deep_output");
        if (deep.isObject() && deep.path("confidence").isNumber()) { return deep.path("confidence").doubleValue(); }
        double best = 0.0;
        for (JsonNode expert : detection.path("expert_outputs")) {
            best = Math.max(best, expert.path("confidence").asDouble(0.0));
        }
        if (best > 0.0) { return best; }
        JsonNode triage = detection.path("triage").path("suspicious_probability");
        return triage.isNumber() ? triage.doubleValue() : 0.0;
    }

    private String requiredText(JsonNode event, String field) {
        String value = event.path(field).asText();
        if (value == null || value.isBlank()) { throw new IllegalArgumentException("missing event field " + field); }
        return value;
    }

    private String text(JsonNode event, String field) {
        JsonNode value = event.path(field);
        return value.isMissingNode() || value.isNull() ? null : value.asText(null);
    }
}
