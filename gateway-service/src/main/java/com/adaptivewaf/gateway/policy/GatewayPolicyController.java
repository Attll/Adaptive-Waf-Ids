package com.adaptivewaf.gateway.policy;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/actuator/waf")
public class GatewayPolicyController {
    private final GatewayPolicy policy;
    public GatewayPolicyController(GatewayPolicy policy) { this.policy = policy; }
    @GetMapping("/policy")
    public Map<String, Object> current() {
        GatewayPolicy.CachedPolicy cached = policy.current();
        return Map.of("version", cached.version(), "blockRiskThreshold", cached.blockRiskThreshold(), "rateLimitShortWindow", cached.rateLimitShortWindow());
    }
}
