package com.adaptivewaf.gateway.policy;

import com.adaptivewaf.gateway.detection.DetectionVerdict;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;

class GatewayPolicyTest {
    @Test void mandatoryRulesAndRequiredStageFailureOverrideModelThreshold() {
        GatewayPolicyProperties properties = new GatewayPolicyProperties();
        properties.setBlockRiskThreshold(1.0);
        GatewayPolicy policy = new GatewayPolicy(properties, WebClient.builder());
        var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        var rule = mapper.createObjectNode();
        rule.putObject("explanation_evidence").put("classification_source", "DETERMINISTIC_RULE");
        assertTrue(policy.shouldBlock(new DetectionVerdict(.99, "XSS", rule, 0)));
        var fallback = mapper.createObjectNode();
        fallback.putObject("explanation_evidence").put("fallback_block", "true");
        assertTrue(policy.shouldBlock(new DetectionVerdict(0, "BENIGN", fallback, 0)));
    }
    @Test
    void blocksOnlyRiskAboveConfiguredThreshold() {
        GatewayPolicyProperties properties = new GatewayPolicyProperties();
        properties.setBlockRiskThreshold(0.81);
        GatewayPolicy policy = new GatewayPolicy(properties, WebClient.builder());

        assertFalse(policy.shouldBlock(new DetectionVerdict(0.81, "BENIGN")));
        assertTrue(policy.shouldBlock(new DetectionVerdict(0.82, "SQL_INJECTION")));
    }
}
