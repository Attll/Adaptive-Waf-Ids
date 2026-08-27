package com.adaptivewaf.gateway.policy;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "adaptive-waf.policy")
public class GatewayPolicyProperties {
    private double blockRiskThreshold = 0.81;

    public double getBlockRiskThreshold() { return blockRiskThreshold; }
    public void setBlockRiskThreshold(double blockRiskThreshold) { this.blockRiskThreshold = blockRiskThreshold; }
}
