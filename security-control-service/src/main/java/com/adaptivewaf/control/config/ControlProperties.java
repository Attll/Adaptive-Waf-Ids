package com.adaptivewaf.control.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "adaptive-waf.control")
public class ControlProperties {
    private final Admin admin = new Admin();
    private final Blocks blocks = new Blocks();
    private final Escalation escalation = new Escalation();
    public Admin getAdmin() { return admin; }
    public Blocks getBlocks() { return blocks; }
    public Escalation getEscalation() { return escalation; }
    public static class Admin {
        private String username = "admin";
        private String initialPassword = "adaptive_waf_dev";
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getInitialPassword() { return initialPassword; }
        public void setInitialPassword(String initialPassword) { this.initialPassword = initialPassword; }
    }
    public static class Blocks {
        private Duration defaultDuration = Duration.ofHours(1);
        public Duration getDefaultDuration() { return defaultDuration; }
        public void setDefaultDuration(Duration defaultDuration) { this.defaultDuration = defaultDuration; }
    }

    /**
     * Deferred escalation answers the caller from the fast verdict, so the first request of an attack the fast
     * experts misjudge is allowed. Blocking the source once the deep model revises the verdict stops every
     * following request from that origin, which is what makes allowing it provisionally safe.
     */
    public static class Escalation {
        private boolean autoBlockOnRevision = true;
        private double autoBlockRiskThreshold = 0.81;
        private Duration autoBlockDuration = Duration.ofMinutes(15);
        public boolean isAutoBlockOnRevision() { return autoBlockOnRevision; }
        public void setAutoBlockOnRevision(boolean autoBlockOnRevision) { this.autoBlockOnRevision = autoBlockOnRevision; }
        public double getAutoBlockRiskThreshold() { return autoBlockRiskThreshold; }
        public void setAutoBlockRiskThreshold(double autoBlockRiskThreshold) { this.autoBlockRiskThreshold = autoBlockRiskThreshold; }
        public Duration getAutoBlockDuration() { return autoBlockDuration; }
        public void setAutoBlockDuration(Duration autoBlockDuration) { this.autoBlockDuration = autoBlockDuration; }
    }
}
