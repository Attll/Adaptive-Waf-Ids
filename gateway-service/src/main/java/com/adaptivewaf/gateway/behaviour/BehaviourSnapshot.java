package com.adaptivewaf.gateway.behaviour;

import java.util.Map;

public record BehaviourSnapshot(
    double risk,
    long shortWindowRequests,
    long mediumWindowRequests,
    long failedAuthAttempts,
    long endpointRequests,
    long previousAttackCount,
    boolean rateLimited,
    boolean temporarilyBlocked
) {
    public static BehaviourSnapshot empty() { return new BehaviourSnapshot(0.0, 0, 0, 0, 0, 0, false, false); }

    public BehaviourSnapshot withTemporaryBlock() {
        return new BehaviourSnapshot(risk, shortWindowRequests, mediumWindowRequests, failedAuthAttempts,
            endpointRequests, previousAttackCount, rateLimited, true);
    }
    public Map<String, Object> asDetectionContext() {
        return Map.of(
            "risk", risk,
            "requests_per_short_window", shortWindowRequests,
            "requests_per_medium_window", mediumWindowRequests,
            "failed_auth_attempts", failedAuthAttempts,
            "previous_attack_count", previousAttackCount
        );
    }
}
