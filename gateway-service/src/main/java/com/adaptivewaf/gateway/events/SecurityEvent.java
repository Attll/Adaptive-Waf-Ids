package com.adaptivewaf.gateway.events;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Journal record published for one gateway decision. It carries the request identity, the enforcement outcome, and
 * the full per-stage detection evidence so the console can reconstruct how the request travelled the pipeline.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record SecurityEvent(
    UUID eventId,
    Instant occurredAt,
    String category,
    String requestId,
    String sourceIp,
    String method,
    String path,
    String query,
    int statusCode,
    String action,
    String predictedAttack,
    double risk,
    String mitigation,
    String mode,
    String userAgent,
    String upstream,
    double detectionLatencyMs,
    double upstreamLatencyMs,
    double gatewayLatencyMs,
    Map<String, Object> behaviour,
    Map<String, Object> network,
    JsonNode detection,
    String inspectionStatus
) {
    public static Builder builder(String category) { return new Builder(category); }

    public static final class Builder {
        private final String category;
        private String requestId;
        private String sourceIp;
        private String method;
        private String path;
        private String query;
        private int statusCode;
        private String action;
        private String predictedAttack;
        private double risk;
        private String mitigation;
        private String mode;
        private String userAgent;
        private String upstream;
        private double detectionLatencyMs;
        private double upstreamLatencyMs;
        private double gatewayLatencyMs;
        private Map<String, Object> behaviour;
        private Map<String, Object> network;
        private JsonNode detection;
        private String inspectionStatus;

        public Builder inspectionStatus(String value) { this.inspectionStatus = value; return this; }

        private Builder(String category) { this.category = category; }

        public Builder request(String requestId, String sourceIp, String method, String path, String query) {
            this.requestId = requestId; this.sourceIp = sourceIp; this.method = method; this.path = path; this.query = query;
            return this;
        }
        public Builder outcome(int statusCode, String action, String predictedAttack, double risk, String mitigation) {
            this.statusCode = statusCode; this.action = action; this.predictedAttack = predictedAttack;
            this.risk = risk; this.mitigation = mitigation;
            return this;
        }
        public Builder context(String mode, String userAgent, String upstream) {
            this.mode = mode; this.userAgent = userAgent; this.upstream = upstream;
            return this;
        }
        public Builder timings(double detectionLatencyMs, double upstreamLatencyMs, double gatewayLatencyMs) {
            this.detectionLatencyMs = detectionLatencyMs; this.upstreamLatencyMs = upstreamLatencyMs; this.gatewayLatencyMs = gatewayLatencyMs;
            return this;
        }
        public Builder evidence(Map<String, Object> behaviour, Map<String, Object> network, JsonNode detection) {
            this.behaviour = behaviour; this.network = network;
            this.detection = detection == null || detection.isNull() ? null : detection;
            return this;
        }
        public SecurityEvent build() {
            return new SecurityEvent(UUID.randomUUID(), Instant.now(), category, requestId, sourceIp, method, path, query,
                statusCode, action, predictedAttack, risk, mitigation, mode, userAgent, upstream,
                detectionLatencyMs, upstreamLatencyMs, gatewayLatencyMs, behaviour, network, detection, inspectionStatus);
        }
    }
}
