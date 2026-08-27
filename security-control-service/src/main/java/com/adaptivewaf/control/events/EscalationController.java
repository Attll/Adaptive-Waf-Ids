package com.adaptivewaf.control.events;

import com.fasterxml.jackson.databind.JsonNode;
import com.adaptivewaf.control.config.ControlProperties;
import com.adaptivewaf.control.plane.ControlPlaneService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Receives the revised verdict for a request that was allowed provisionally while the deep model adjudicated it in
 * the background. Every resolution is journalled, so a request the fast experts were unsure about remains visible
 * and actionable even though it was already answered.
 */
@RestController
public class EscalationController {
    private static final Logger LOGGER = LoggerFactory.getLogger(EscalationController.class);
    private static final int RETAINED = 200;
    private final Deque<Map<String, Object>> recent = new ArrayDeque<>();
    private final ObjectMapper objectMapper;
    private final SecurityEventRepository repository;
    private final SecurityEventSanitizer sanitizer;
    private final SecurityEventBroadcaster broadcaster;
    private final ControlPlaneService controlPlane;
    private final ControlProperties properties;

    public EscalationController(ObjectMapper objectMapper, SecurityEventRepository repository,
                                SecurityEventSanitizer sanitizer, SecurityEventBroadcaster broadcaster,
                                ControlPlaneService controlPlane, ControlProperties properties) {
        this.objectMapper = objectMapper;
        this.repository = repository;
        this.sanitizer = sanitizer;
        this.broadcaster = broadcaster;
        this.controlPlane = controlPlane;
        this.properties = properties;
    }

    @PostMapping("/internal/v1/security/escalations")
    public Map<String, Object> record(@RequestBody JsonNode payload) {
        String escalationId = payload.path("escalation_id").asText(UUID.randomUUID().toString());
        JsonNode revised = payload.path("revised");
        JsonNode provisional = payload.path("provisional");
        boolean changed = payload.path("changed").asBoolean(false);
        String revisedAttack = revised.path("predicted_attack").asText("UNKNOWN");

        PersistedSecurityEvent event = PersistedSecurityEvent.builder()
            .identity(UUID.randomUUID().toString(), Instant.now(), "security.escalation", payload.path("request_id").asText(null))
            .request(payload.path("source_ip").asText(null), payload.path("method").asText(null),
                payload.path("path").asText(null), payload.path("query").asText(null), null, null)
            .outcome(0, changed ? "ESCALATION_REVISED" : "ESCALATION_CONFIRMED", revisedAttack,
                revised.path("risk").asDouble(0.0),
                changed ? "DEEP_ESCALATION_REVISED_AFTER_ALLOW" : "DEEP_ESCALATION_CONFIRMED_ALLOW", null)
            .timings(payload.path("deep_latency_ms").asDouble(0.0), 0.0, payload.path("queued_ms").asDouble(0.0))
            .inference("DEEP_ESCALATION_ASYNC", true, null, revised.path("confidence").asDouble(0.0))
            .details(sanitizer.json(payload))
            .build();

        try {
            repository.save(event);
            broadcaster.broadcast(event);
        } catch (RuntimeException error) {
            LOGGER.warn("Escalation {} could not be journalled: {}", escalationId, error.getClass().getSimpleName());
        }

        synchronized (recent) {
            recent.addFirst(objectMapper.convertValue(payload, new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() { }));
            while (recent.size() > RETAINED) { recent.removeLast(); }
        }
        boolean blocked = false;
        if (changed) {
            LOGGER.info("Deep escalation {} revised {} to {} after the request was allowed",
                escalationId, provisional.path("predicted_attack").asText("UNKNOWN"), revisedAttack);
            blocked = blockSourceIfDangerous(payload, revised, revisedAttack);
        }
        return Map.of("escalationId", escalationId, "journalled", true, "changed", changed, "sourceBlocked", blocked);
    }

    /**
     * The provisional answer has already been sent, so the only remaining protection is to stop what follows from
     * the same origin. Blocking is skipped for benign revisions and for verdicts under the configured threshold.
     */
    private boolean blockSourceIfDangerous(JsonNode payload, JsonNode revised, String revisedAttack) {
        ControlProperties.Escalation settings = properties.getEscalation();
        String sourceIp = payload.path("source_ip").asText(null);
        if (!settings.isAutoBlockOnRevision() || sourceIp == null || sourceIp.isBlank()) { return false; }
        if ("BENIGN".equals(revisedAttack)) { return false; }
        double risk = revised.path("risk").asDouble(0.0);
        if (risk < settings.getAutoBlockRiskThreshold()) { return false; }
        try {
            controlPlane.block(new ControlPlaneService.BlockRequest(
                sourceIp,
                "Deep escalation revised a provisionally allowed request to " + revisedAttack,
                settings.getAutoBlockDuration()), "deep-escalation");
            LOGGER.warn("Blocked {} for {} after a deferred escalation revised the verdict to {}",
                sourceIp, settings.getAutoBlockDuration(), revisedAttack);
            return true;
        } catch (RuntimeException error) {
            LOGGER.warn("Could not block {} after escalation: {}", sourceIp, error.getClass().getSimpleName());
            return false;
        }
    }

    @GetMapping("/v1/security/escalations")
    public Map<String, Object> recent(@RequestParam(defaultValue = "50") int limit) {
        synchronized (recent) {
            List<Map<String, Object>> window = new ArrayList<>(recent);
            return Map.of(
                "escalations", window.subList(0, Math.min(window.size(), Math.max(1, limit))),
                "retained", recent.size());
        }
    }
}
