package com.adaptivewaf.gateway.behaviour;

import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import reactor.core.publisher.Mono;

/** One atomic add/prune/count/expiry operation, with Redis server time. */
final class RedisWindow {
    private static final RedisScript<Long> WINDOW = RedisScript.of("""
        local t = redis.call('TIME')
        local now = t[1] * 1000 + math.floor(t[2] / 1000)
        redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - tonumber(ARGV[1]))
        redis.call('ZADD', KEYS[1], now, ARGV[2])
        local count = redis.call('ZCARD', KEYS[1])
        redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[1]) * 2)
        return count
        """, Long.class);
    private static final RedisScript<Long> INCREMENT = RedisScript.of("""
        local count = redis.call('INCR', KEYS[1])
        redis.call('PEXPIRE', KEYS[1], ARGV[1])
        return count
        """, Long.class);

    private RedisWindow() { }

    static Mono<Long> count(ReactiveStringRedisTemplate redis, String key, Duration window) {
        return redis.execute(WINDOW, List.of(key), List.of(Long.toString(window.toMillis()), UUID.randomUUID().toString())).single();
    }

    static Mono<Long> increment(ReactiveStringRedisTemplate redis, String key, Duration ttl) {
        return redis.execute(INCREMENT, List.of(key), List.of(Long.toString(ttl.toMillis()))).single();
    }
}
