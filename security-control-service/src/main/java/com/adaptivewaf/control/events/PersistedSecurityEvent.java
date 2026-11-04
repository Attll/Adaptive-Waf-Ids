package com.adaptivewaf.control.events;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "security_events")
public class PersistedSecurityEvent {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "event_id", nullable = false, unique = true, length = 36)
    private String eventId;
    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;
    @Column(nullable = false, length = 64)
    private String category;
    @Column(name = "request_id", length = 64)
    private String requestId;
    @Column(name = "source_ip", length = 64)
    private String sourceIp;
    @Column(length = 16)
    private String method;
    @Column(length = 1024)
    private String path;
    @Column(name = "query", length = 2048)
    private String query;
    @Column(name = "status_code")
    private int statusCode;
    @Column(length = 64)
    private String action;
    @Column(name = "predicted_attack", length = 128)
    private String predictedAttack;
    private double risk;
    @Column(length = 64)
    private String mitigation;
    @Column(length = 32)
    private String mode;
    @Column(name = "user_agent", length = 512)
    private String userAgent;
    @Column(length = 1024)
    private String upstream;
    @Column(name = "detection_latency_ms", nullable = false)
    private double detectionLatencyMs;
    @Column(name = "upstream_latency_ms", nullable = false)
    private double upstreamLatencyMs;
    @Column(name = "gateway_latency_ms", nullable = false)
    private double gatewayLatencyMs;
    @Column(name = "routing_path", length = 512)
    private String routingPath;
    @Column(name = "deep_model_used", nullable = false)
    private boolean deepModelUsed;
    @Column(name = "triage_decision", length = 32)
    private String triageDecision;
    @Column(nullable = false)
    private double confidence;
    @Column(name = "details_json", nullable = false, columnDefinition = "text")
    private String detailsJson;
    @Column(name = "inspection_status", length = 32)
    private String inspectionStatus;
    @Column(name = "processed_at")
    private Instant processedAt;

    protected PersistedSecurityEvent() { }

    private PersistedSecurityEvent(Builder builder) {
        this.eventId = builder.eventId;
        this.occurredAt = builder.occurredAt;
        this.category = builder.category;
        this.requestId = builder.requestId;
        this.sourceIp = builder.sourceIp;
        this.method = builder.method;
        this.path = builder.path;
        this.query = builder.query;
        this.statusCode = builder.statusCode;
        this.action = builder.action;
        this.predictedAttack = builder.predictedAttack;
        this.risk = builder.risk;
        this.mitigation = builder.mitigation;
        this.mode = builder.mode;
        this.userAgent = builder.userAgent;
        this.upstream = builder.upstream;
        this.detectionLatencyMs = builder.detectionLatencyMs;
        this.upstreamLatencyMs = builder.upstreamLatencyMs;
        this.gatewayLatencyMs = builder.gatewayLatencyMs;
        this.routingPath = builder.routingPath;
        this.deepModelUsed = builder.deepModelUsed;
        this.triageDecision = builder.triageDecision;
        this.confidence = builder.confidence;
        this.detailsJson = builder.detailsJson;
        this.inspectionStatus = builder.inspectionStatus;
        this.processedAt = Instant.now();
    }

    public static Builder builder() { return new Builder(); }

    public Long getId() { return id; }
    public String getEventId() { return eventId; }
    public Instant getOccurredAt() { return occurredAt; }
    public String getCategory() { return category; }
    public String getRequestId() { return requestId; }
    public String getSourceIp() { return sourceIp; }
    public String getMethod() { return method; }
    public String getPath() { return path; }
    public String getQuery() { return query; }
    public int getStatusCode() { return statusCode; }
    public String getAction() { return action; }
    public String getPredictedAttack() { return predictedAttack; }
    public double getRisk() { return risk; }
    public String getMitigation() { return mitigation; }
    public String getMode() { return mode; }
    public String getUserAgent() { return userAgent; }
    public String getUpstream() { return upstream; }
    public double getDetectionLatencyMs() { return detectionLatencyMs; }
    public double getUpstreamLatencyMs() { return upstreamLatencyMs; }
    public double getGatewayLatencyMs() { return gatewayLatencyMs; }
    public String getRoutingPath() { return routingPath; }
    public boolean isDeepModelUsed() { return deepModelUsed; }
    public String getTriageDecision() { return triageDecision; }
    public double getConfidence() { return confidence; }
    public String getDetailsJson() { return detailsJson; }
    public String getInspectionStatus() { return inspectionStatus; }
    public Instant getProcessedAt() { return processedAt; }

    public static final class Builder {
        private String eventId;
        private Instant occurredAt;
        private String category;
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
        private String routingPath;
        private boolean deepModelUsed;
        private String triageDecision;
        private double confidence;
        private String detailsJson = "{}";
        private String inspectionStatus;

        public Builder inspectionStatus(String value) { this.inspectionStatus = value; return this; }

        public Builder identity(String eventId, Instant occurredAt, String category, String requestId) {
            this.eventId = eventId; this.occurredAt = occurredAt; this.category = category; this.requestId = requestId;
            return this;
        }
        public Builder request(String sourceIp, String method, String path, String query, String userAgent, String upstream) {
            this.sourceIp = sourceIp; this.method = method; this.path = path; this.query = query;
            this.userAgent = userAgent; this.upstream = upstream;
            return this;
        }
        public Builder outcome(int statusCode, String action, String predictedAttack, double risk, String mitigation, String mode) {
            this.statusCode = statusCode; this.action = action; this.predictedAttack = predictedAttack;
            this.risk = risk; this.mitigation = mitigation; this.mode = mode;
            return this;
        }
        public Builder timings(double detectionLatencyMs, double upstreamLatencyMs, double gatewayLatencyMs) {
            this.detectionLatencyMs = detectionLatencyMs; this.upstreamLatencyMs = upstreamLatencyMs; this.gatewayLatencyMs = gatewayLatencyMs;
            return this;
        }
        public Builder inference(String routingPath, boolean deepModelUsed, String triageDecision, double confidence) {
            this.routingPath = routingPath; this.deepModelUsed = deepModelUsed;
            this.triageDecision = triageDecision; this.confidence = confidence;
            return this;
        }
        public Builder details(String detailsJson) { this.detailsJson = detailsJson; return this; }
        public PersistedSecurityEvent build() { return new PersistedSecurityEvent(this); }
    }
}
