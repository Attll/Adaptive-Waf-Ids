package com.adaptivewaf.gateway.filter;

import com.adaptivewaf.gateway.detection.DetectionClient;
import com.adaptivewaf.gateway.detection.DetectionProperties;
import com.adaptivewaf.gateway.policy.GatewayPolicy;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Component
public class AdaptiveDetectionFilter implements GlobalFilter, Ordered {
    private static final Logger LOGGER = LoggerFactory.getLogger(AdaptiveDetectionFilter.class);
    private final DetectionClient detectionClient;
    private final DetectionProperties detectionProperties;
    private final GatewayPolicy policy;

    public AdaptiveDetectionFilter(DetectionClient detectionClient, DetectionProperties detectionProperties, GatewayPolicy policy) {
        this.detectionClient = detectionClient;
        this.detectionProperties = detectionProperties;
        this.policy = policy;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (exchange.getRequest().getPath().value().startsWith("/actuator/")) {
            return chain.filter(exchange);
        }
        String requestId = requestId(exchange.getRequest().getHeaders());
        ServerWebExchange correlated = exchange.mutate()
            .request(request -> request.headers(headers -> headers.set("X-Request-ID", requestId)))
            .build();
        return cacheSafeBody(correlated)
            .flatMap(cached -> detectionClient.detect(toDetectionRequest(cached.getRequest(), requestId, cached.body()))
                .flatMap(verdict -> policy.shouldBlock(verdict) ? block(cached.exchange(), requestId, verdict.predictedAttack()) : chain.filter(cached.exchange()))
                .onErrorResume(error -> {
                    LOGGER.warn("Detection unavailable for request {}: {}; forwarding request", requestId, error.getClass().getSimpleName());
                    return chain.filter(cached.exchange());
                }));
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 100;
    }

    private Mono<CachedExchange> cacheSafeBody(ServerWebExchange exchange) {
        long contentLength = exchange.getRequest().getHeaders().getContentLength();
        if (contentLength < 0 || contentLength > detectionProperties.getMaxBodyBytes()) {
            return Mono.just(new CachedExchange(exchange, ""));
        }
        return DataBufferUtils.join(exchange.getRequest().getBody())
            .map(buffer -> cache(exchange, buffer))
            .defaultIfEmpty(new CachedExchange(exchange, ""));
    }

    private CachedExchange cache(ServerWebExchange exchange, DataBuffer buffer) {
        byte[] bytes = new byte[buffer.readableByteCount()];
        buffer.read(bytes);
        DataBufferUtils.release(buffer);
        ServerHttpRequest decoratedRequest = new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            public Flux<DataBuffer> getBody() {
                return Flux.defer(() -> Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
            }
        };
        return new CachedExchange(exchange.mutate().request(decoratedRequest).build(), new String(bytes, StandardCharsets.UTF_8));
    }

    private Map<String, Object> toDetectionRequest(ServerHttpRequest request, String requestId, String body) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("method", request.getMethod().name());
        payload.put("path", request.getPath().value());
        payload.put("query", request.getURI().getRawQuery() == null ? "" : request.getURI().getRawQuery());
        payload.put("headers", safeHeaders(request.getHeaders()));
        payload.put("cookies", request.getCookies().toSingleValueMap());
        payload.put("body", body);
        payload.put("source_ip", sourceIp(request));
        payload.put("request_id", requestId);
        return payload;
    }

    private Map<String, String> safeHeaders(HttpHeaders headers) {
        Map<String, String> values = new LinkedHashMap<>();
        headers.forEach((name, entries) -> {
            if (!name.equalsIgnoreCase(HttpHeaders.AUTHORIZATION) && !name.equalsIgnoreCase(HttpHeaders.COOKIE)) {
                values.put(name, String.join(",", entries));
            }
        });
        return values;
    }

    private String sourceIp(ServerHttpRequest request) {
        InetSocketAddress remoteAddress = request.getRemoteAddress();
        return remoteAddress == null || remoteAddress.getAddress() == null ? null : remoteAddress.getAddress().getHostAddress();
    }

    private String requestId(HttpHeaders headers) {
        String supplied = headers.getFirst("X-Request-ID");
        return supplied == null || supplied.isBlank() ? UUID.randomUUID().toString() : supplied;
    }

    private Mono<Void> block(ServerWebExchange exchange, String requestId, String predictedAttack) {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        exchange.getResponse().getHeaders().set("X-Request-ID", requestId);
        byte[] message = ("{\"error\":{\"code\":\"waf_blocked\",\"predicted_attack\":\"" + predictedAttack + "\"},\"request_id\":\"" + requestId + "\"}").getBytes(StandardCharsets.UTF_8);
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(message)));
    }

    private record CachedExchange(ServerWebExchange exchange, String body) {
        ServerHttpRequest getRequest() { return exchange.getRequest(); }
    }
}
