package com.adaptivewaf.gateway.policy;

import com.adaptivewaf.gateway.detection.DetectionVerdict;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.annotation.PostConstruct;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.stereotype.Component;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.reactive.function.client.WebClient;

@Component
public class GatewayPolicy {
    private final GatewayPolicyProperties properties;
    private final WebClient controlClient;
    private final AtomicReference<CachedPolicy> cachedPolicy;

    public GatewayPolicy(GatewayPolicyProperties properties, WebClient.Builder builder) {
        this.properties = properties;
        this.controlClient = builder.baseUrl(properties.getControlServiceBaseUrl())
            .defaultHeader("X-WAF-Internal-Token", properties.getInternalToken()).build();
        this.cachedPolicy = new AtomicReference<>(new CachedPolicy(0, properties.getBlockRiskThreshold(), 0));
    }

    public boolean shouldBlock(DetectionVerdict verdict) {
        if ("DETERMINISTIC_RULE".equals(verdict.evidence().path("explanation_evidence").path("classification_source").asText())
                || verdict.evidence().path("explanation_evidence").path("fallback_block").asBoolean(false)) { return true; }
        return verdict.overallRisk() > cachedPolicy.get().blockRiskThreshold();
    }

    public CachedPolicy current() { return cachedPolicy.get(); }

    @PostConstruct
    void initializeCache() { refresh(); }

    @Scheduled(fixedDelayString = "${adaptive-waf.policy.refresh-interval:30s}")
    public void refresh() {
        try {
            JsonNode policy = controlClient.get().uri("/internal/v1/gateway-policy").retrieve().bodyToMono(JsonNode.class)
                .block(properties.getRefreshInterval());
            if (policy != null && policy.path("blockRiskThreshold").isNumber()
                    && Double.isFinite(policy.path("blockRiskThreshold").doubleValue())
                    && policy.path("blockRiskThreshold").doubleValue() >= 0
                    && policy.path("blockRiskThreshold").doubleValue() <= 1
                    && policy.path("rateLimitShortWindow").asLong(0) > 0) {
                cachedPolicy.set(new CachedPolicy(policy.path("version").asInt(0), policy.path("blockRiskThreshold").doubleValue(), policy.path("rateLimitShortWindow").asLong(0)));
            }
        } catch (RuntimeException ignored) {
            // Retain the last known policy when the control plane is unavailable.
        }
    }

    public record CachedPolicy(int version, double blockRiskThreshold, long rateLimitShortWindow) { }
}
