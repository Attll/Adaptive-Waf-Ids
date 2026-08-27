package com.adaptivewaf.gateway.network;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class RedisNetworkContextService {
    private final ReactiveStringRedisTemplate redis;
    private final ObjectMapper objectMapper;
    private final NetworkContextProperties properties;

    public RedisNetworkContextService(ReactiveStringRedisTemplate redis, ObjectMapper objectMapper, NetworkContextProperties properties) {
        this.redis = redis;
        this.objectMapper = objectMapper;
        this.properties = properties;
    }

    public Mono<NetworkContextSnapshot> context(ServerHttpRequest request) {
        String source = sourceKey(request);
        if (source == null) { return Mono.just(NetworkContextSnapshot.empty()); }
        return redis.opsForValue().get(properties.getKeyPrefix() + source)
            .timeout(properties.getLookupTimeout())
            .flatMap(this::decode)
            .defaultIfEmpty(NetworkContextSnapshot.empty())
            .onErrorReturn(NetworkContextSnapshot.empty());
    }

    private Mono<NetworkContextSnapshot> decode(String raw) {
        try { return Mono.just(NetworkContextSnapshot.from(objectMapper.readTree(raw))); }
        catch (Exception ignored) { return Mono.just(NetworkContextSnapshot.empty()); }
    }

    private String sourceKey(ServerHttpRequest request) {
        if (request.getRemoteAddress() == null || request.getRemoteAddress().getAddress() == null) { return null; }
        return request.getRemoteAddress().getAddress().getHostAddress().replace(":", "_");
    }
}
