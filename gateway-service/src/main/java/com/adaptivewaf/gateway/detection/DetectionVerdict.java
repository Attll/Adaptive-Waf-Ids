package com.adaptivewaf.gateway.detection;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.NullNode;

/**
 * Gateway view of one detection-service response. The full sanitized {@code detection} payload is retained so the
 * control plane can persist per-stage routing, latency, and model evidence alongside the final decision.
 */
public record DetectionVerdict(double overallRisk, String predictedAttack, JsonNode detection, double serviceInferenceMs) {

    /** A verdict without model evidence: inference was skipped, unavailable, or has not run yet. */
    public DetectionVerdict(double overallRisk, String predictedAttack) {
        this(overallRisk, predictedAttack, NullNode.getInstance(), 0.0);
    }

    public JsonNode evidence() { return detection == null ? NullNode.getInstance() : detection; }

    /** True when the deep model is still adjudicating this request on a background worker. */
    public boolean deepEscalationPending() {
        return evidence().path("deep_escalation_pending").asBoolean(false);
    }
}
