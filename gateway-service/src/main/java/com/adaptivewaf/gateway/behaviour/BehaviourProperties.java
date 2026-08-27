package com.adaptivewaf.gateway.behaviour;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "adaptive-waf.behaviour")
public class BehaviourProperties {
    private Duration shortWindow = Duration.ofSeconds(10);
    private Duration mediumWindow = Duration.ofSeconds(60);
    private long rateLimitShortWindow = 40;
    private long temporaryBlockThreshold = 40;
    private Duration temporaryBlockDuration = Duration.ofMinutes(1);
    private long failedAuthBlockThreshold = 5;
    private long elevatedRequestsPerShortWindow = 20;
    private long degradedRequestsPerShortWindow = 40;
    private long emergencyRequestsPerShortWindow = 80;

    public Duration getShortWindow() { return shortWindow; }
    public void setShortWindow(Duration shortWindow) { this.shortWindow = shortWindow; }
    public Duration getMediumWindow() { return mediumWindow; }
    public void setMediumWindow(Duration mediumWindow) { this.mediumWindow = mediumWindow; }
    public long getRateLimitShortWindow() { return rateLimitShortWindow; }
    public void setRateLimitShortWindow(long rateLimitShortWindow) { this.rateLimitShortWindow = rateLimitShortWindow; }
    public long getTemporaryBlockThreshold() { return temporaryBlockThreshold; }
    public void setTemporaryBlockThreshold(long temporaryBlockThreshold) { this.temporaryBlockThreshold = temporaryBlockThreshold; }
    public Duration getTemporaryBlockDuration() { return temporaryBlockDuration; }
    public void setTemporaryBlockDuration(Duration temporaryBlockDuration) { this.temporaryBlockDuration = temporaryBlockDuration; }
    public long getFailedAuthBlockThreshold() { return failedAuthBlockThreshold; }
    public void setFailedAuthBlockThreshold(long failedAuthBlockThreshold) { this.failedAuthBlockThreshold = failedAuthBlockThreshold; }
    public long getElevatedRequestsPerShortWindow() { return elevatedRequestsPerShortWindow; }
    public void setElevatedRequestsPerShortWindow(long elevatedRequestsPerShortWindow) { this.elevatedRequestsPerShortWindow = elevatedRequestsPerShortWindow; }
    public long getDegradedRequestsPerShortWindow() { return degradedRequestsPerShortWindow; }
    public void setDegradedRequestsPerShortWindow(long degradedRequestsPerShortWindow) { this.degradedRequestsPerShortWindow = degradedRequestsPerShortWindow; }
    public long getEmergencyRequestsPerShortWindow() { return emergencyRequestsPerShortWindow; }
    public void setEmergencyRequestsPerShortWindow(long emergencyRequestsPerShortWindow) { this.emergencyRequestsPerShortWindow = emergencyRequestsPerShortWindow; }
}
