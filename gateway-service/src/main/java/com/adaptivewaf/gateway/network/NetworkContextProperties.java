package com.adaptivewaf.gateway.network;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "adaptive-waf.network-context")
public class NetworkContextProperties {
    private String keyPrefix = "waf:network:";
    private Duration lookupTimeout = Duration.ofMillis(25);

    public String getKeyPrefix() { return keyPrefix; }
    public void setKeyPrefix(String keyPrefix) { this.keyPrefix = keyPrefix; }
    public Duration getLookupTimeout() { return lookupTimeout; }
    public void setLookupTimeout(Duration lookupTimeout) { this.lookupTimeout = lookupTimeout; }
}
