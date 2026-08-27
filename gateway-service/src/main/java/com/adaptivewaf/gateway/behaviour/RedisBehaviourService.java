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

    public RedisBehaviourService(ReactiveStringRedisTemplate redis, BehaviourProperties properties) {
        this.redis = redis;
        this.properties = properties;
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
        Mono<Boolean> attack = risk >= 0.81 || !"BENIGN".equals(predictedAttack)
            ? incrementCounter("waf:ip:" + source + ":attacks", properties.getMediumWindow()).thenReturn(true)
            : Mono.just(false);
        return Mono.when(failedLogin, attack).then();
    }

    public Mono<Boolean> isTemporarilyBlocked(ServerHttpRequest request) {
        return redis.hasKey(blockKey(sourceKey(request)));
    }

    private Mono<Long> rollingCount(String key, Duration window, String member) {
        double now = System.currentTimeMillis();
        return redis.opsForZSet().add(key, now + ":" + member + ":" + UUID.randomUUID(), now)
            .then(redis.opsForZSet().removeRangeByScore(key, Range.closed(0.0, now - window.toMillis())))
            .then(redis.opsForZSet().size(key))
            .flatMap(count -> redis.expire(key, window.multipliedBy(2)).thenReturn(count));
    }

    private Mono<Long> counter(String key) {
        return redis.opsForValue().get(key).defaultIfEmpty("0").map(Long::parseLong);
    }

    private Mono<Long> incrementCounter(String key, Duration ttl) {
        return redis.opsForValue().increment(key).flatMap(value -> redis.expire(key, ttl).thenReturn(value));
    }

    private BehaviourSnapshot snapshot(long shortCount, long mediumCount, long endpointCount, long failedAuthAttempts, long attackCount, boolean blocked) {
        double rateRisk = shortCount / (double) properties.getRateLimitShortWindow();
        double endpointRisk = endpointCount / (double) Math.max(1, properties.getRateLimitShortWindow() * 2);
        double authRisk = failedAuthAttempts / 5.0;
        double risk = Math.min(1.0, Math.max(rateRisk, Math.max(endpointRisk, authRisk)));
        return new BehaviourSnapshot(risk, shortCount, mediumCount, failedAuthAttempts, endpointCount, attackCount,
            shortCount >= properties.getRateLimitShortWindow(), blocked);
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
        if (request.getRemoteAddress() == null || request.getRemoteAddress().getAddress() == null) {
            return "unknown";
        }
        return request.getRemoteAddress().getAddress().getHostAddress().replace(":", "_");
    }
}
