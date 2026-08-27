package com.adaptivewaf.gateway.policy;

import com.adaptivewaf.gateway.detection.DetectionVerdict;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;

class GatewayPolicyTest {
    @Test
    void blocksOnlyRiskAboveConfiguredThreshold() {
        GatewayPolicyProperties properties = new GatewayPolicyProperties();
        properties.setBlockRiskThreshold(0.81);
        GatewayPolicy policy = new GatewayPolicy(properties, WebClient.builder());

        assertFalse(policy.shouldBlock(new DetectionVerdict(0.81, "BENIGN")));
        assertTrue(policy.shouldBlock(new DetectionVerdict(0.82, "SQL_INJECTION")));
    }
}
