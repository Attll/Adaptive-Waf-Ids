package com.adaptivewaf.control.plane;

import com.adaptivewaf.control.config.ControlProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ControlPlaneService {
    public static final UUID DEFAULT_APPLICATION_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final StringRedisTemplate redis;
    private final ControlProperties properties;

    public ControlPlaneService(JdbcTemplate jdbc, ObjectMapper objectMapper, StringRedisTemplate redis, ControlProperties properties) {
        this.jdbc = jdbc; this.objectMapper = objectMapper; this.redis = redis; this.properties = properties;
    }

    public PolicySnapshot activePolicy() {
        return jdbc.queryForObject("select p.application_id, p.version, p.block_risk_threshold, p.rate_limit_short_window from policy_versions p where p.application_id = ? and p.active = true",
            (row, index) -> new PolicySnapshot(row.getObject("application_id", UUID.class), row.getInt("version"), row.getDouble("block_risk_threshold"), row.getLong("rate_limit_short_window")),
            DEFAULT_APPLICATION_ID);
    }

    @Transactional
    public PolicySnapshot updatePolicy(PolicyUpdate update, String administrator) {
        if (update.blockRiskThreshold() < 0 || update.blockRiskThreshold() > 1 || update.rateLimitShortWindow() < 1) {
            throw new IllegalArgumentException("policy threshold or rate limit is invalid");
        }
        PolicySnapshot old = activePolicy();
        int version = old.version() + 1;
        jdbc.update("update policy_versions set active = false where application_id = ? and active = true", DEFAULT_APPLICATION_ID);
        jdbc.update("insert into policy_versions(policy_id, application_id, version, block_risk_threshold, rate_limit_short_window, active) values (?, ?, ?, ?, ?, true)",
            UUID.randomUUID(), DEFAULT_APPLICATION_ID, version, update.blockRiskThreshold(), update.rateLimitShortWindow());
        PolicySnapshot current = activePolicy();
        audit(administrator, "POLICY", DEFAULT_APPLICATION_ID.toString(), "UPDATE", old, current);
        return current;
    }

    public List<ApplicationView> applications() {
        return jdbc.query("select application_id, name, upstream_url, enabled from protected_applications order by name",
            (row, index) -> new ApplicationView(row.getObject("application_id", UUID.class), row.getString("name"), row.getString("upstream_url"), row.getBoolean("enabled")));
    }

    @Transactional
    public ApplicationView createApplication(ApplicationCreate request, String administrator) {
        UUID id = UUID.randomUUID();
        ApplicationView created = new ApplicationView(id, request.name(), request.upstreamUrl(), true);
        jdbc.update("insert into protected_applications(application_id, name, upstream_url, enabled) values (?, ?, ?, true)", id, request.name(), request.upstreamUrl());
        audit(administrator, "PROTECTED_APPLICATION", id.toString(), "CREATE", null, created);
        return created;
    }

    @Transactional
    public BlockView block(BlockRequest request, String administrator) {
        if (request.sourceIp() == null || request.sourceIp().isBlank()) { throw new IllegalArgumentException("source IP is required"); }
        Instant expiry = Instant.now().plus(request.duration() == null ? properties.getBlocks().getDefaultDuration() : request.duration());
        BlockView old = findBlock(request.sourceIp());
        BlockView current = new BlockView(request.sourceIp(), request.reason(), expiry, true);
        jdbc.update("insert into blocked_entities(source_ip, reason, blocked_by, expires_at, active, updated_at) values (?, ?, ?, ?, true, now()) on conflict (source_ip) do update set reason = excluded.reason, blocked_by = excluded.blocked_by, expires_at = excluded.expires_at, active = true, updated_at = now()",
            request.sourceIp(), request.reason(), administrator, Timestamp.from(expiry));
        redis.opsForValue().set("waf:block:" + request.sourceIp(), "manual:" + request.reason(), request.duration() == null ? properties.getBlocks().getDefaultDuration() : request.duration());
        audit(administrator, "BLOCKED_ENTITY", request.sourceIp(), "BLOCK", old, current);
        return current;
    }

    @Transactional
    public void unblock(String sourceIp, String administrator) {
        BlockView old = findBlock(sourceIp);
        jdbc.update("update blocked_entities set active = false, updated_at = now() where source_ip = ?", sourceIp);
        redis.delete("waf:block:" + sourceIp);
        audit(administrator, "BLOCKED_ENTITY", sourceIp, "UNBLOCK", old, Map.of("active", false));
    }

    public List<ModelView> models() {
        return jdbc.query("select model_version_id, model_name, artifact_version, status, metrics_json from model_versions order by created_at desc",
            (row, index) -> new ModelView(row.getObject("model_version_id", UUID.class), row.getString("model_name"), row.getString("artifact_version"), row.getString("status"), row.getString("metrics_json")));
    }

    @Transactional
    public ModelView registerModel(ModelCreate request, String administrator) {
        UUID id = UUID.randomUUID();
        ModelView current = new ModelView(id, request.modelName(), request.artifactVersion(), "CHALLENGER", request.metricsJson() == null ? "{}" : request.metricsJson());
        jdbc.update("insert into model_versions(model_version_id, model_name, artifact_version, status, metrics_json) values (?, ?, ?, ?, ?)",
            id, current.modelName(), current.artifactVersion(), current.status(), current.metricsJson());
        audit(administrator, "MODEL_VERSION", id.toString(), "REGISTER", null, current);
        return current;
    }

    @Transactional
    public void promote(UUID modelVersionId, String administrator) {
        ModelView old = jdbc.queryForObject("select model_version_id, model_name, artifact_version, status, metrics_json from model_versions where model_version_id = ?",
            (row, index) -> new ModelView(row.getObject("model_version_id", UUID.class), row.getString("model_name"), row.getString("artifact_version"), row.getString("status"), row.getString("metrics_json")), modelVersionId);
        jdbc.update("update model_versions set status = 'RETIRED' where model_name = ? and status = 'ACTIVE'", old.modelName());
        jdbc.update("update model_versions set status = 'ACTIVE' where model_version_id = ?", modelVersionId);
        audit(administrator, "MODEL_VERSION", modelVersionId.toString(), "PROMOTE", old, Map.of("status", "ACTIVE"));
    }

    @Transactional
    public void assignModel(UUID modelVersionId, String administrator) {
        jdbc.update("insert into model_assignments(application_id, model_version_id, assigned_by, assigned_at) values (?, ?, ?, now()) on conflict (application_id) do update set model_version_id = excluded.model_version_id, assigned_by = excluded.assigned_by, assigned_at = now()",
            DEFAULT_APPLICATION_ID, modelVersionId, administrator);
        audit(administrator, "MODEL_ASSIGNMENT", DEFAULT_APPLICATION_ID.toString(), "ASSIGN", null, Map.of("modelVersionId", modelVersionId));
    }

    @Transactional
    public FeedbackView submitFeedback(FeedbackCreate request, String administrator) {
        UUID id = UUID.randomUUID();
        FeedbackView feedback = new FeedbackView(id, request.eventId(), request.verdict(), request.notes(), administrator);
        jdbc.update("insert into admin_feedback(feedback_id, event_id, verdict, notes, submitted_by) values (?, ?, ?, ?, ?)", id, request.eventId(), request.verdict(), request.notes(), administrator);
        audit(administrator, "ADMIN_FEEDBACK", id.toString(), "CREATE", null, feedback);
        return feedback;
    }

    public List<AuditView> auditEntries(int limit) {
        return jdbc.query("select audit_id, administrator, occurred_at, entity_type, entity_id, action, old_value_json, new_value_json from audit_log order by occurred_at desc limit ?",
            (row, index) -> new AuditView(row.getObject("audit_id", UUID.class), row.getString("administrator"), row.getTimestamp("occurred_at").toInstant(), row.getString("entity_type"), row.getString("entity_id"), row.getString("action"), row.getString("old_value_json"), row.getString("new_value_json")),
            Math.max(1, Math.min(limit, 200)));
    }

    private BlockView findBlock(String sourceIp) {
        try {
            return jdbc.queryForObject("select source_ip, reason, expires_at, active from blocked_entities where source_ip = ?", (row, index) -> new BlockView(row.getString("source_ip"), row.getString("reason"), row.getTimestamp("expires_at").toInstant(), row.getBoolean("active")), sourceIp);
        } catch (EmptyResultDataAccessException error) { return null; }
    }

    private void audit(String administrator, String entityType, String entityId, String action, Object oldValue, Object newValue) {
        jdbc.update("insert into audit_log(audit_id, administrator, entity_type, entity_id, action, old_value_json, new_value_json) values (?, ?, ?, ?, ?, ?, ?)",
            UUID.randomUUID(), administrator, entityType, entityId, action, json(oldValue), json(newValue));
    }

    private String json(Object value) {
        if (value == null) { return null; }
        try { return objectMapper.writeValueAsString(value); }
        catch (JsonProcessingException error) { throw new IllegalStateException("audit value cannot be serialized", error); }
    }

    public record PolicySnapshot(UUID applicationId, int version, double blockRiskThreshold, long rateLimitShortWindow) { }
    public record PolicyUpdate(double blockRiskThreshold, long rateLimitShortWindow) { }
    public record ApplicationCreate(String name, String upstreamUrl) { }
    public record ApplicationView(UUID applicationId, String name, String upstreamUrl, boolean enabled) { }
    public record BlockRequest(String sourceIp, String reason, java.time.Duration duration) { }
    public record BlockView(String sourceIp, String reason, Instant expiresAt, boolean active) { }
    public record ModelCreate(String modelName, String artifactVersion, String metricsJson) { }
    public record ModelView(UUID modelVersionId, String modelName, String artifactVersion, String status, String metricsJson) { }
    public record FeedbackCreate(String eventId, String verdict, String notes) { }
    public record FeedbackView(UUID feedbackId, String eventId, String verdict, String notes, String submittedBy) { }
    public record AuditView(UUID auditId, String administrator, Instant occurredAt, String entityType, String entityId, String action, String oldValueJson, String newValueJson) { }
}
