package com.adaptivewaf.gateway.behaviour;

import java.time.Duration;
import java.util.UUID;
import org.springframework.data.domain.Range;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class RedisLoadModeService {
    private static final String REQUEST_KEY = "waf:system:requests:short";
    private static final String MODE_KEY = "waf:system:mode";
    private final ReactiveStringRedisTemplate redis;
    private final BehaviourProperties properties;

    public RedisLoadModeService(ReactiveStringRedisTemplate redis, BehaviourProperties properties) {
        this.redis = redis;
        this.properties = properties;
    }

    public Mono<OperatingMode> recordRequest(String requestId) {
        double now = System.currentTimeMillis();
        Duration window = properties.getShortWindow();
        return redis.opsForZSet().add(REQUEST_KEY, now + ":" + requestId + ":" + UUID.randomUUID(), now)
            .then(redis.opsForZSet().removeRangeByScore(REQUEST_KEY, Range.closed(0.0, now - window.toMillis())))
            .then(redis.opsForZSet().size(REQUEST_KEY))
            .flatMap(count -> redis.expire(REQUEST_KEY, window.multipliedBy(2)).thenReturn(OperatingMode.forRequestCount(count, properties)))
            .flatMap(mode -> redis.opsForValue().set(MODE_KEY, mode.name(), window.multipliedBy(2)).thenReturn(mode));
    }

    public Mono<OperatingMode> currentMode() {
        return redis.opsForValue().get(MODE_KEY).map(this::parse).defaultIfEmpty(OperatingMode.NORMAL);
    }

    private OperatingMode parse(String mode) {
        try { return OperatingMode.valueOf(mode); }
        catch (IllegalArgumentException error) { return OperatingMode.NORMAL; }
    }
}
