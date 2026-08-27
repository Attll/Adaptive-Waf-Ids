package com.adaptivewaf.gateway.events;

import java.time.Instant;
import java.util.UUID;

public record SecurityEvent(
    UUID eventId,
    Instant occurredAt,
    String category,
    String requestId,
    String sourceIp,
    String method,
    String path,
    int statusCode,
    String action,
    String predictedAttack,
    double risk
) {
    public static SecurityEvent create(String category, String requestId, String sourceIp, String method, String path,
                                       int statusCode, String action, String predictedAttack, double risk) {
        return new SecurityEvent(UUID.randomUUID(), Instant.now(), category, requestId, sourceIp, method, path,
            statusCode, action, predictedAttack, risk);
    }
}
