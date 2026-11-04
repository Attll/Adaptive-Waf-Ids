package com.adaptivewaf.gateway.behaviour;

import com.adaptivewaf.gateway.detection.*;
import com.adaptivewaf.gateway.policy.GatewayPolicy;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.stream.LongStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@EnabledIfEnvironmentVariable(named = "WAF_TEST_REDIS_PORT", matches = "\\d+")
class RedisWindowIntegrationTest {
    private LettuceConnectionFactory connection;
    private ReactiveStringRedisTemplate redis;

    @BeforeEach void connect() {
        connection = new LettuceConnectionFactory("127.0.0.1", Integer.parseInt(System.getenv("WAF_TEST_REDIS_PORT")));
        connection.afterPropertiesSet();
        redis = new ReactiveStringRedisTemplate(connection);
    }
    @AfterEach void close() { connection.destroy(); }

    @Test void concurrentWindowCountsAreAtomicAndExpire() {
        String key = "fixture:" + java.util.UUID.randomUUID();
        var counts = Flux.range(0, 100).flatMap(index -> RedisWindow.count(redis, key, Duration.ofSeconds(2)), 20)
            .collectSortedList().block(Duration.ofSeconds(10));
        assertEquals(LongStream.rangeClosed(1, 100).boxed().toList(), counts);
        assertTrue(redis.getExpire(key).block().isPositive());
        String shortKey = key + ":expiry";
        assertEquals(1L, RedisWindow.count(redis, shortKey, Duration.ofMillis(50)).block());
        Mono.delay(Duration.ofMillis(150)).block();
        assertFalse(redis.hasKey(shortKey).block());
    }

    @Test void activePolicyChangesEnforcementAndUnknownVerdictsDoNotCountAsAttacks() {
        var properties = new BehaviourProperties();
        properties.setTemporaryBlockThreshold(1000);
        var policy = mock(GatewayPolicy.class);
        when(policy.current()).thenReturn(new GatewayPolicy.CachedPolicy(1, .81, 2));
        var identity = new SourceIdentity(new DetectionProperties());
        var service = new RedisBehaviourService(redis, properties, policy, identity);
        var request = MockServerHttpRequest.get("/backend/health")
            .remoteAddress(new InetSocketAddress("192.0.2.34", 1000)).build();
        assertFalse(service.observe(request, "first").block().rateLimited());
        assertTrue(service.observe(request, "second").block().rateLimited());
        when(policy.current()).thenReturn(new GatewayPolicy.CachedPolicy(2, .81, 10));
        assertFalse(service.observe(request, "third").block().rateLimited());
        service.recordOutcome(request, 200, 0, "UNAVAILABLE").block();
        service.recordOutcome(request, 200, 0, "SKIPPED").block();
        assertEquals(0, service.observe(request, "fourth").block().previousAttackCount());
        service.recordOutcome(request, 403, .99, "COOKIE_INJECTION").block();
        assertEquals(1, service.observe(request, "fifth").block().previousAttackCount());
    }
}
