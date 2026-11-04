package com.adaptivewaf.gateway.policy;

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.time.Duration;

@ConfigurationProperties(prefix = "adaptive-waf.policy")
public class GatewayPolicyProperties {
    private String internalToken = "";
    public String getInternalToken() { return internalToken; }
    public void setInternalToken(String token) { internalToken = token; }
    private double blockRiskThreshold = 0.81;
    private String controlServiceBaseUrl = "http://127.0.0.1:8082";
    private Duration refreshInterval = Duration.ofSeconds(30);

    public double getBlockRiskThreshold() { return blockRiskThreshold; }
    public void setBlockRiskThreshold(double blockRiskThreshold) { this.blockRiskThreshold = blockRiskThreshold; }
    public String getControlServiceBaseUrl() { return controlServiceBaseUrl; }
    public void setControlServiceBaseUrl(String controlServiceBaseUrl) { this.controlServiceBaseUrl = controlServiceBaseUrl; }
    public Duration getRefreshInterval() { return refreshInterval; }
    public void setRefreshInterval(Duration refreshInterval) { this.refreshInterval = refreshInterval; }
}
