package com.adaptivewaf.gateway.detection;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "adaptive-waf.detection")
public class DetectionProperties {
    private String baseUrl = "http://127.0.0.1:8000";
    private Duration timeout = Duration.ofSeconds(5);
    private int maxBodyBytes = 65536;
    private String pathPrefixToStrip = "/backend";
    private Duration bodyReadTimeout = Duration.ofSeconds(5);
    private boolean failClosed = false;
    private String sessionHmacSecret = "";
    public String getSessionHmacSecret() { return sessionHmacSecret; }
    public void setSessionHmacSecret(String value) { sessionHmacSecret = value; }
    private java.util.Set<String> trustedProxyIps = java.util.Set.of();

    public java.util.Set<String> getTrustedProxyIps() { return trustedProxyIps; }
    public void setTrustedProxyIps(java.util.Set<String> values) {
        java.util.Set<String> normalized = new java.util.HashSet<>();
        for (String value : values) {
            java.net.InetAddress address = io.netty.util.NetUtil.createInetAddressFromIpAddressString(value);
            if (address == null) { throw new IllegalArgumentException("trusted proxy must be an IP literal"); }
            normalized.add(io.netty.util.NetUtil.toAddressString(address));
        }
        trustedProxyIps = java.util.Set.copyOf(normalized);
    }

    public String getBaseUrl() { return baseUrl; }
    public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
    public Duration getTimeout() { return timeout; }
    public void setTimeout(Duration timeout) { this.timeout = timeout; }
    public int getMaxBodyBytes() { return maxBodyBytes; }
    public void setMaxBodyBytes(int maxBodyBytes) {
        if (maxBodyBytes < 1) { throw new IllegalArgumentException("maxBodyBytes must be positive"); }
        this.maxBodyBytes = maxBodyBytes;
    }
    public Duration getBodyReadTimeout() { return bodyReadTimeout; }
    public void setBodyReadTimeout(Duration timeout) {
        if (timeout == null || timeout.isNegative() || timeout.isZero()) { throw new IllegalArgumentException("body read timeout must be positive"); }
        this.bodyReadTimeout = timeout;
    }
    public boolean isFailClosed() { return failClosed; }
    public void setFailClosed(boolean failClosed) { this.failClosed = failClosed; }
    public String getPathPrefixToStrip() { return pathPrefixToStrip; }
    public void setPathPrefixToStrip(String pathPrefixToStrip) { this.pathPrefixToStrip = pathPrefixToStrip; }
}
