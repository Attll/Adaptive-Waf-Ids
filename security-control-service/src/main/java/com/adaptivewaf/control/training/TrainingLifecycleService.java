package com.adaptivewaf.control.training;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TrainingLifecycleService {
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    public TrainingLifecycleService(JdbcTemplate jdbc, ObjectMapper mapper) { this.jdbc = jdbc; this.mapper = mapper; }

    public List<TrainingRunView> runs() {
        return jdbc.query("select external_run_id, model_name, dataset_version, status, shadow_mode, artifact_uri, metrics_json, drift_json, started_at, completed_at from training_runs order by started_at desc",
            (row, index) -> new TrainingRunView(row.getString("external_run_id"), row.getString("model_name"), row.getString("dataset_version"), row.getString("status"), row.getBoolean("shadow_mode"), row.getString("artifact_uri"), row.getString("metrics_json"), row.getString("drift_json"), row.getTimestamp("started_at").toInstant(), row.getTimestamp("completed_at") == null ? null : row.getTimestamp("completed_at").toInstant()));
    }

    @Transactional
    public TrainingRunView createRun(TrainingRunCreate request) {
        TrainingRunView run = new TrainingRunView(request.externalRunId(), request.modelName(), request.datasetVersion(), "TRAINING", request.shadowMode(), request.artifactUri(), "{}", "{}", Instant.now(), null);
        jdbc.update("insert into training_runs(training_run_id, external_run_id, model_name, dataset_version, status, shadow_mode, artifact_uri, created_by) values (?, ?, ?, ?, ?, ?, ?, 'training-adaptation-service')",
            UUID.randomUUID(), run.externalRunId(), run.modelName(), run.datasetVersion(), run.status(), run.shadowMode(), run.artifactUri());
        audit("TRAINING_RUN", run.externalRunId(), "CREATE", null, run);
        return run;
    }

    @Transactional
    public TrainingRunView completeRun(String runId, TrainingRunCompletion request) {
        jdbc.update("update training_runs set status = ?, metrics_json = ?, drift_json = ?, completed_at = now() where external_run_id = ?", request.status(), request.metricsJson(), request.driftJson(), runId);
        TrainingRunView run = run(runId);
        audit("TRAINING_RUN", runId, "COMPLETE", null, run);
        return run;
    }

    @Transactional
    public ModelView registerCandidate(CandidateCreate request) {
        UUID id = UUID.randomUUID();
        ModelView candidate = new ModelView(id, request.modelName(), request.artifactVersion(), "CANDIDATE", request.metricsJson(), request.trainingRunId());
        jdbc.update("insert into model_versions(model_version_id, model_name, artifact_version, status, metrics_json) values (?, ?, ?, 'CANDIDATE', ?)", id, candidate.modelName(), candidate.artifactVersion(), candidate.metricsJson());
        audit("MODEL_VERSION", id.toString(), "REGISTER_CANDIDATE", null, candidate);
        return candidate;
    }

    @Transactional
    public ModelView evaluate(String modelVersionId, Evaluation request) {
        UUID id = UUID.fromString(modelVersionId);
        jdbc.update("update model_versions set status = 'CHALLENGER', metrics_json = ? where model_version_id = ? and status = 'CANDIDATE'", request.metricsJson(), id);
        ModelView model = model(id);
        audit("MODEL_VERSION", id.toString(), "EVALUATE_CHALLENGER", null, Map.of("comparison", request.comparisonJson(), "metrics", request.metricsJson(), "shadowMode", request.shadowMode()));
        return model;
    }

    @Transactional
    public void approve(String modelVersionId, String administrator) { transition(modelVersionId, "APPROVED", "APPROVE", administrator); }
    @Transactional
    public void retire(String modelVersionId, String administrator) { transition(modelVersionId, "RETIRED", "RETIRE", administrator); }

    public List<FeedbackView> feedback() {
        return jdbc.query("select f.feedback_id, f.event_id, f.verdict, f.correct_attack_type, f.notes, f.submitted_by, f.submitted_at, e.method, e.path, e.predicted_attack from admin_feedback f left join security_events e on e.event_id = f.event_id order by f.submitted_at desc",
            (row, index) -> new FeedbackView(row.getObject("feedback_id", UUID.class), row.getString("event_id"), row.getString("verdict"), row.getString("correct_attack_type"), row.getString("notes"), row.getString("submitted_by"), row.getTimestamp("submitted_at").toInstant(), row.getString("method"), row.getString("path"), row.getString("predicted_attack")));
    }

    private void transition(String modelVersionId, String status, String action, String administrator) {
        jdbc.update("update model_versions set status = ? where model_version_id = ?", status, UUID.fromString(modelVersionId));
        audit("MODEL_VERSION", modelVersionId, action, null, Map.of("status", status, "administrator", administrator));
    }
    private TrainingRunView run(String id) { return runs().stream().filter(run -> run.externalRunId().equals(id)).findFirst().orElseThrow(); }
    private ModelView model(UUID id) { return jdbc.queryForObject("select model_version_id, model_name, artifact_version, status, metrics_json from model_versions where model_version_id = ?", (row, index) -> new ModelView(row.getObject("model_version_id", UUID.class), row.getString("model_name"), row.getString("artifact_version"), row.getString("status"), row.getString("metrics_json"), null), id); }
    private void audit(String type, String id, String action, Object oldValue, Object newValue) { jdbc.update("insert into audit_log(audit_id, administrator, entity_type, entity_id, action, old_value_json, new_value_json) values (?, 'training-adaptation-service', ?, ?, ?, ?, ?)", UUID.randomUUID(), type, id, action, json(oldValue), json(newValue)); }
    private String json(Object value) { if (value == null) return null; try { return mapper.writeValueAsString(value); } catch (JsonProcessingException error) { throw new IllegalStateException(error); } }

    public record TrainingRunCreate(String externalRunId, String modelName, String datasetVersion, boolean shadowMode, String artifactUri) { }
    public record TrainingRunCompletion(String status, String metricsJson, String driftJson) { }
    public record CandidateCreate(String trainingRunId, String modelName, String artifactVersion, String metricsJson) { }
    public record Evaluation(String metricsJson, String comparisonJson, boolean shadowMode) { }
    public record TrainingRunView(String externalRunId, String modelName, String datasetVersion, String status, boolean shadowMode, String artifactUri, String metricsJson, String driftJson, Instant startedAt, Instant completedAt) { }
    public record ModelView(UUID modelVersionId, String modelName, String artifactVersion, String status, String metricsJson, String trainingRunId) { }
    public record FeedbackView(UUID feedbackId, String eventId, String verdict, String correctAttackType, String notes, String submittedBy, Instant submittedAt, String method, String path, String predictedAttack) { }
}
