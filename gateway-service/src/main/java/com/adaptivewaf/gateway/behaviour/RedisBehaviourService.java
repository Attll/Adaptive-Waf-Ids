package com.adaptivewaf.gateway.behaviour;

import java.time.Duration;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;
import org.springframework.data.domain.Range;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class RedisBehaviourService {
    private final ReactiveStringRedisTemplate redis;
    private final BehaviourProperties properties;
    private final com.adaptivewaf.gateway.policy.GatewayPolicy policy;
    private final com.adaptivewaf.gateway.detection.SourceIdentity sourceIdentity;

    public RedisBehaviourService(ReactiveStringRedisTemplate redis, BehaviourProperties properties,
                                 com.adaptivewaf.gateway.policy.GatewayPolicy policy,
                                 com.adaptivewaf.gateway.detection.SourceIdentity sourceIdentity) {
        this.redis = redis;
        this.properties = properties;
        this.policy = policy;
        this.sourceIdentity = sourceIdentity;
    }

    public Mono<BehaviourSnapshot> observe(ServerHttpRequest request, String requestId) {
        String source = sourceKey(request);
        return Mono.zip(
            rollingCount("waf:ip:" + source + ":requests:short", properties.getShortWindow(), requestId),
            rollingCount("waf:ip:" + source + ":requests:medium", properties.getMediumWindow(), requestId),
            rollingCount("waf:ip:" + source + ":endpoint:" + fingerprint(request.getPath().value()), properties.getMediumWindow(), requestId),
            counter("waf:login:" + source + ":failures"),
            counter("waf:ip:" + source + ":attacks"),
            redis.hasKey(blockKey(source))
        ).map(values -> snapshot(values.getT1(), values.getT2(), values.getT3(), values.getT4(), values.getT5(), values.getT6()))
            .flatMap(snapshot -> snapshot.shortWindowRequests() >= properties.getTemporaryBlockThreshold() && !snapshot.temporarilyBlocked()
                ? redis.opsForValue().set(blockKey(source), "rate-limit", properties.getTemporaryBlockDuration()).thenReturn(snapshot.withTemporaryBlock())
                : Mono.just(snapshot));
    }

    public Mono<Void> recordOutcome(ServerHttpRequest request, int statusCode, double risk, String predictedAttack) {
        String source = sourceKey(request);
        Mono<Void> failedLogin = isLogin(request) && (statusCode == 401 || statusCode == 403)
            ? incrementCounter("waf:login:" + source + ":failures", properties.getMediumWindow())
                .flatMap(count -> count >= properties.getFailedAuthBlockThreshold()
                    ? redis.opsForValue().set(blockKey(source), "repeated-login-failures", properties.getTemporaryBlockDuration())
                    : Mono.just(true))
                .then()
            : Mono.empty();
        boolean knownAttack = java.util.Set.of("SQL_INJECTION", "XSS", "COOKIE_INJECTION", "DIRECTORY_TRAVERSAL", "REMOTE_CODE_EXECUTION").contains(predictedAttack == null ? "" : predictedAttack);
        Mono<Boolean> attack = knownAttack || (risk >= 0.81 && !java.util.Set.of("SKIPPED", "UNAVAILABLE", "UNEVALUATED").contains(predictedAttack == null ? "" : predictedAttack))
            ? incrementCounter("waf:ip:" + source + ":attacks", properties.getMediumWindow()).thenReturn(true)
            : Mono.just(false);
        return Mono.when(failedLogin, attack).then();
    }

    public Mono<Boolean> isTemporarilyBlocked(ServerHttpRequest request) {
        return redis.hasKey(blockKey(sourceKey(request)));
    }

    private Mono<Long> rollingCount(String key, Duration window, String member) {
        return RedisWindow.count(redis, key, window);
    }

    private Mono<Long> counter(String key) {
        return redis.opsForValue().get(key).defaultIfEmpty("0").map(Long::parseLong);
    }

    private Mono<Long> incrementCounter(String key, Duration ttl) {
        return RedisWindow.increment(redis, key, ttl);
    }

    private BehaviourSnapshot snapshot(long shortCount, long mediumCount, long endpointCount, long failedAuthAttempts, long attackCount, boolean blocked) {
        long rateLimit = policy.current().rateLimitShortWindow();
        if (rateLimit <= 0) { rateLimit = properties.getRateLimitShortWindow(); }
        double rateRisk = shortCount / (double) rateLimit;
        double endpointRisk = endpointCount / (double) Math.max(1, rateLimit * 2);
        double authRisk = failedAuthAttempts / 5.0;
        double risk = Math.min(1.0, Math.max(rateRisk, Math.max(endpointRisk, authRisk)));
        return new BehaviourSnapshot(risk, shortCount, mediumCount, failedAuthAttempts, endpointCount, attackCount,
            shortCount >= rateLimit, blocked);
    }

    private String blockKey(String source) { return "waf:block:" + source; }

    private boolean isLogin(ServerHttpRequest request) { return request.getPath().value().toLowerCase().contains("login"); }

    private String fingerprint(String value) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder encoded = new StringBuilder();
            for (byte entry : hash) { encoded.append(String.format("%02x", entry)); }
            return encoded.toString();
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 is unavailable", error);
        }
    }

    private String sourceKey(ServerHttpRequest request) {
        return sourceIdentity.sourceKey(request);
    }
}
