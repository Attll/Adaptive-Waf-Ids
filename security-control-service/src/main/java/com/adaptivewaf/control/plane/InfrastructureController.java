package com.adaptivewaf.control.plane;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Live view of the stores the platform depends on. The console uses this to show that Redis is actually carrying
 * behavioural counters, manual blocks, and network context while traffic is being generated — and that every
 * request really did land in Postgres.
 */
@RestController
@RequestMapping("/v1/control/infrastructure")
public class InfrastructureController {
    private static final int KEY_SAMPLE_LIMIT = 25;
    private final StringRedisTemplate redis;
    private final JdbcTemplate jdbc;
    private final DataSource dataSource;
    private final String externalJdbcUrl;
    private final String databaseUser;

    public InfrastructureController(StringRedisTemplate redis, JdbcTemplate jdbc, DataSource dataSource,
                                    @Value("${adaptive-waf.control.database.external-url:jdbc:postgresql://127.0.0.1:55432/adaptive_waf}") String externalJdbcUrl,
                                    @Value("${spring.datasource.username:adaptive_waf}") String databaseUser) {
        this.redis = redis;
        this.jdbc = jdbc;
        this.dataSource = dataSource;
        this.externalJdbcUrl = externalJdbcUrl;
        this.databaseUser = databaseUser;
    }

    @GetMapping
    public Map<String, Object> status() {
        return Map.of("redis", redis(), "database", database());
    }

    private Map<String, Object> redis() {
        Map<String, Object> status = new LinkedHashMap<>();
        long started = System.nanoTime();
        try {
            String pong = redis.execute((org.springframework.data.redis.connection.RedisConnection connection) -> connection.ping());
            status.put("reachable", true);
            status.put("ping", pong == null ? "PONG" : pong);
            status.put("pingLatencyMs", roundMs(System.nanoTime() - started));
            Map<String, Object> namespaces = new LinkedHashMap<>();
            namespaces.put("Manual blocks", describe("waf:block:*"));
            namespaces.put("Per-source behaviour", describe("waf:ip:*"));
            namespaces.put("Failed authentication", describe("waf:login:*"));
            namespaces.put("Network risk context", describe("waf:network:*"));
            namespaces.put("Load shedding", describe("waf:system:*"));
            status.put("namespaces", namespaces);
            status.put("totalTrackedKeys", namespaces.values().stream()
                .mapToLong(entry -> ((Number) ((Map<?, ?>) entry).get("count")).longValue()).sum());
        } catch (RuntimeException error) {
            status.put("reachable", false);
            status.put("error", error.getClass().getSimpleName());
            status.put("namespaces", Map.of());
            status.put("totalTrackedKeys", 0);
        }
        return status;
    }

    /** Key counts plus a bounded sample, so an operator can see the actual keys appear as traffic is generated. */
    private Map<String, Object> describe(String pattern) {
        try {
            Set<String> keys = redis.keys(pattern);
            if (keys == null) { keys = Set.of(); }
            List<String> sample = keys.stream().sorted().limit(KEY_SAMPLE_LIMIT).toList();
            List<Map<String, Object>> entries = sample.stream().map(key -> {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("key", key);
                Long ttl = redis.getExpire(key);
                entry.put("ttlSeconds", ttl == null ? -1 : ttl);
                try {
                    entry.put("type", String.valueOf(redis.type(key)));
                } catch (RuntimeException ignored) {
                    entry.put("type", "UNKNOWN");
                }
                return entry;
            }).toList();
            return Map.of("pattern", pattern, "count", keys.size(), "sample", entries);
        } catch (RuntimeException error) {
            return Map.of("pattern", pattern, "count", 0, "sample", List.of());
        }
    }

    private Map<String, Object> database() {
        Map<String, Object> status = new LinkedHashMap<>();
        long started = System.nanoTime();
        try {
            Long events = jdbc.queryForObject("select count(*) from security_events", Long.class);
            Long escalations = jdbc.queryForObject("select count(*) from security_events where category = 'security.escalation'", Long.class);
            Instant newest = jdbc.query("select max(occurred_at) as newest from security_events",
                result -> result.next() && result.getTimestamp("newest") != null ? result.getTimestamp("newest").toInstant() : null);
            status.put("reachable", true);
            status.put("queryLatencyMs", roundMs(System.nanoTime() - started));
            status.put("totalEvents", events == null ? 0 : events);
            status.put("escalationRecords", escalations == null ? 0 : escalations);
            status.put("newestEventAt", newest == null ? null : newest.toString());
            status.put("secondsSinceNewestEvent", newest == null ? null : Duration.between(newest, Instant.now()).toSeconds());
            status.put("tableCounts", tableCounts());
            status.put("jdbcUrl", jdbcUrl());
            // What an operator types into an external client; the service's own URL resolves inside the compose network.
            status.put("externalJdbcUrl", externalJdbcUrl);
            status.put("username", databaseUser);
        } catch (RuntimeException error) {
            status.put("reachable", false);
            status.put("error", error.getClass().getSimpleName());
        }
        return status;
    }

    private Map<String, Long> tableCounts() {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (String table : List.of("security_events", "audit_log", "admin_feedback", "training_runs", "model_versions", "blocked_entities", "policy_versions", "protected_applications")) {
            try {
                counts.put(table, jdbc.queryForObject("select count(*) from " + table, Long.class));
            } catch (RuntimeException ignored) {
                counts.put(table, -1L);
            }
        }
        return counts;
    }

    /** The connection string an operator points DBeaver at; credentials are deliberately not included. */
    private String jdbcUrl() {
        try (var connection = dataSource.getConnection()) {
            return connection.getMetaData().getURL();
        } catch (Exception error) {
            return "unavailable";
        }
    }

    private static double roundMs(long elapsedNanos) {
        return Math.round(elapsedNanos / 1_000.0) / 1_000.0;
    }
}
