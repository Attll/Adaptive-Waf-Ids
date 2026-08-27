package com.adaptivewaf.control.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "adaptive-waf.control")
public class ControlProperties {
    private final Admin admin = new Admin();
    private final Blocks blocks = new Blocks();
    public Admin getAdmin() { return admin; }
    public Blocks getBlocks() { return blocks; }
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
}
