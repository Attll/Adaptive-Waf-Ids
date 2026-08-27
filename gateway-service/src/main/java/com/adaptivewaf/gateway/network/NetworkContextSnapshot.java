package com.adaptivewaf.gateway.network;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;

public record NetworkContextSnapshot(double risk, String networkClass, Double confidence) {
    public static NetworkContextSnapshot empty() { return new NetworkContextSnapshot(0.0, null, null); }

    static NetworkContextSnapshot from(JsonNode value) {
        double risk = value.path("network_risk").asDouble(-1.0);
        if (risk < 0.0 || risk > 1.0) { return empty(); }
        JsonNode confidence = value.path("confidence");
        Double validatedConfidence = confidence.isNumber() && confidence.doubleValue() >= 0.0 && confidence.doubleValue() <= 1.0 ? confidence.doubleValue() : null;
        return new NetworkContextSnapshot(risk, value.path("network_class").asText(null), validatedConfidence);
    }

    public Map<String, Object> asDetectionContext() {
        return confidence == null
            ? Map.of("risk", risk, "network_class", networkClass == null ? "UNKNOWN" : networkClass)
            : Map.of("risk", risk, "network_class", networkClass == null ? "UNKNOWN" : networkClass, "confidence", confidence);
    }
}
