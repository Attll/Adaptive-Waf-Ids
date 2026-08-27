package com.adaptivewaf.gateway.policy;

import com.adaptivewaf.gateway.detection.DetectionVerdict;
import org.springframework.stereotype.Component;

@Component
public class GatewayPolicy {
    private final GatewayPolicyProperties properties;

    public GatewayPolicy(GatewayPolicyProperties properties) {
        this.properties = properties;
    }

    public boolean shouldBlock(DetectionVerdict verdict) {
        return verdict.overallRisk() > properties.getBlockRiskThreshold();
    }
}
