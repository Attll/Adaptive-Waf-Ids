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
    @Column(name = "source_hash", length = 64)
    private String sourceHash;
    @Column(length = 16)
    private String method;
    @Column(length = 1024)
    private String path;
    @Column(name = "status_code")
    private int statusCode;
    @Column(length = 64)
    private String action;
    @Column(name = "predicted_attack", length = 128)
    private String predictedAttack;
    private double risk;
    @Column(name = "details_json", nullable = false, columnDefinition = "text")
    private String detailsJson;

    protected PersistedSecurityEvent() { }

    public PersistedSecurityEvent(String eventId, Instant occurredAt, String category, String requestId, String sourceHash,
                                  String method, String path, int statusCode, String action, String predictedAttack,
                                  double risk, String detailsJson) {
        this.eventId = eventId; this.occurredAt = occurredAt; this.category = category; this.requestId = requestId;
        this.sourceHash = sourceHash; this.method = method; this.path = path; this.statusCode = statusCode;
        this.action = action; this.predictedAttack = predictedAttack; this.risk = risk; this.detailsJson = detailsJson;
    }
    public Long getId() { return id; }
    public String getEventId() { return eventId; }
    public Instant getOccurredAt() { return occurredAt; }
    public String getCategory() { return category; }
    public String getRequestId() { return requestId; }
    public String getSourceHash() { return sourceHash; }
    public String getMethod() { return method; }
    public String getPath() { return path; }
    public int getStatusCode() { return statusCode; }
    public String getAction() { return action; }
    public String getPredictedAttack() { return predictedAttack; }
    public double getRisk() { return risk; }
    public String getDetailsJson() { return detailsJson; }
}
