package com.adaptivewaf.gateway.filter;

import com.adaptivewaf.gateway.detection.DetectionClient;
import com.adaptivewaf.gateway.detection.DetectionProperties;
import com.adaptivewaf.gateway.events.SecurityEvent;
import com.adaptivewaf.gateway.events.SecurityEventPublisher;
import com.adaptivewaf.gateway.behaviour.BehaviourSnapshot;
import com.adaptivewaf.gateway.behaviour.OperatingMode;
import com.adaptivewaf.gateway.behaviour.RedisBehaviourService;
import com.adaptivewaf.gateway.behaviour.RedisLoadModeService;
import com.adaptivewaf.gateway.policy.GatewayPolicy;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
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
    private final RedisBehaviourService behaviourService;
    private final RedisLoadModeService loadModeService;
    private final SecurityEventPublisher eventPublisher;

    public AdaptiveDetectionFilter(DetectionClient detectionClient, DetectionProperties detectionProperties, GatewayPolicy policy,
                                   RedisBehaviourService behaviourService, RedisLoadModeService loadModeService,
                                   SecurityEventPublisher eventPublisher) {
        this.detectionClient = detectionClient;
        this.detectionProperties = detectionProperties;
        this.policy = policy;
        this.behaviourService = behaviourService;
        this.loadModeService = loadModeService;
        this.eventPublisher = eventPublisher;
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
            .flatMap(cached -> loadModeService.recordRequest(requestId)
                .flatMap(mode -> process(cached, requestId, mode, chain))
                .onErrorResume(error -> {
                    LOGGER.warn("Redis unavailable for request {}; using stateless processing", requestId);
                    return detectOrForward(cached, requestId, OperatingMode.NORMAL, BehaviourSnapshot.empty(), chain);
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

    private Mono<Void> process(CachedExchange cached, String requestId, OperatingMode mode, GatewayFilterChain chain) {
        return behaviourService.isTemporarilyBlocked(cached.getRequest())
            .flatMap(blocked -> blocked
                ? temporarilyBlocked(cached, requestId)
                : behaviourService.observe(cached.getRequest(), requestId)
                    .flatMap(behaviour -> behaviour.rateLimited()
                        ? rateLimited(cached, requestId)
                        : detectOrForward(cached, requestId, mode, behaviour, chain)));
    }

    private Mono<Void> detectOrForward(CachedExchange cached, String requestId, OperatingMode mode,
                                       BehaviourSnapshot behaviour, GatewayFilterChain chain) {
        if (!mode.permitsModelInference()) {
            LOGGER.warn("Skipping model inference for request {} in {} mode", requestId, mode);
            return forwardAndRecord(cached, chain, 0.0, "SKIPPED");
        }
        return detectionClient.detect(toDetectionRequest(cached.getRequest(), requestId, cached.body(), behaviour))
            .flatMap(verdict -> {
                LOGGER.debug("Detection verdict for request {}: attack={}, risk={}", requestId, verdict.predictedAttack(), verdict.overallRisk());
                if (policy.shouldBlock(verdict)) {
                    eventPublisher.publish(event(cached, requestId, "security.attack", HttpStatus.FORBIDDEN.value(), "BLOCK", verdict.predictedAttack(), verdict.overallRisk()));
                    return behaviourService.recordOutcome(cached.getRequest(), HttpStatus.FORBIDDEN.value(), verdict.overallRisk(), verdict.predictedAttack())
                        .onErrorResume(error -> Mono.empty())
                        .then(block(cached.exchange(), requestId, verdict.predictedAttack()));
                }
                return forwardAndRecord(cached, chain, verdict.overallRisk(), verdict.predictedAttack());
            })
            .onErrorResume(error -> {
                LOGGER.warn("Detection unavailable for request {}: {}; forwarding request", requestId, error.getClass().getSimpleName());
                return forwardAndRecord(cached, chain, 0.0, "UNAVAILABLE");
            });
    }

    private Mono<Void> forwardAndRecord(CachedExchange cached, GatewayFilterChain chain, double risk, String attack) {
        cached.exchange().getResponse().beforeCommit(() -> {
            int status = responseStatus(cached.exchange());
            eventPublisher.publish(event(cached, requestId(cached.getRequest().getHeaders()), "security.request", status, "ALLOW", attack, risk));
            return behaviourService.recordOutcome(cached.getRequest(), status, risk, attack)
                .onErrorResume(error -> {
                    LOGGER.warn("Could not persist behavioural outcome: {}", error.getClass().getSimpleName());
                    return Mono.empty();
                });
        });
        return chain.filter(cached.exchange());
    }

    private int responseStatus(ServerWebExchange exchange) {
        return exchange.getResponse().getStatusCode() == null ? 200 : exchange.getResponse().getStatusCode().value();
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

    private Map<String, Object> toDetectionRequest(ServerHttpRequest request, String requestId, String body, BehaviourSnapshot behaviour) {
        Map<String, Object> payload = new LinkedHashMap<>();
        String normalizedPath = normalizedPath(request.getPath().value());
        String normalizedQuery = normalizedQuery(request);
        LOGGER.debug("Detection representation for request {}: path={}, queryLength={}", requestId, normalizedPath, normalizedQuery.length());
        payload.put("method", request.getMethod().name());
        payload.put("path", normalizedPath);
        payload.put("query", normalizedQuery);
        payload.put("headers", safeHeaders(request.getHeaders()));
        payload.put("cookies", request.getCookies().toSingleValueMap());
        payload.put("body", body);
        payload.put("source_ip", sourceIp(request));
        payload.put("request_id", requestId);
        payload.put("behaviour_context", behaviour.asDetectionContext());
        return payload;
    }

    private Map<String, String> safeHeaders(HttpHeaders headers) {
        Map<String, String> values = new LinkedHashMap<>();
        headers.forEach((name, entries) -> {
            if (!isTransportOrSensitiveHeader(name)) {
                values.put(name, String.join(",", entries));
            }
        });
        return values;
    }

    private boolean isTransportOrSensitiveHeader(String name) {
        return name.equalsIgnoreCase(HttpHeaders.AUTHORIZATION)
            || name.equalsIgnoreCase(HttpHeaders.COOKIE)
            || name.equalsIgnoreCase("X-Request-ID")
            || name.equalsIgnoreCase(HttpHeaders.HOST)
            || name.equalsIgnoreCase(HttpHeaders.CONNECTION)
            || name.equalsIgnoreCase(HttpHeaders.ACCEPT)
            || name.equalsIgnoreCase(HttpHeaders.ACCEPT_ENCODING)
            || name.equalsIgnoreCase(HttpHeaders.USER_AGENT)
            || name.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH)
            || name.equalsIgnoreCase(HttpHeaders.TRANSFER_ENCODING);
    }

    private String sourceIp(ServerHttpRequest request) {
        InetSocketAddress remoteAddress = request.getRemoteAddress();
        return remoteAddress == null || remoteAddress.getAddress() == null ? null : remoteAddress.getAddress().getHostAddress();
    }

    private String normalizedPath(String path) {
        String prefix = detectionProperties.getPathPrefixToStrip();
        if (prefix != null && !prefix.isBlank() && (path.equals(prefix) || path.startsWith(prefix + "/"))) {
            String normalized = path.substring(prefix.length());
            return normalized.isEmpty() ? "/" : normalized;
        }
        return path;
    }

    private String normalizedQuery(ServerHttpRequest request) {
        return request.getQueryParams().entrySet().stream()
            .flatMap(entry -> entry.getValue().stream().map(value -> entry.getKey() + "=" + value))
            .collect(Collectors.joining("&"));
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

    private Mono<Void> rateLimited(CachedExchange cached, String requestId) {
        eventPublisher.publish(event(cached, requestId, "security.decision", HttpStatus.TOO_MANY_REQUESTS.value(), "RATE_LIMIT", "RATE_LIMIT", 1.0));
        return securityResponse(cached.exchange(), requestId, HttpStatus.TOO_MANY_REQUESTS, "rate_limited", "RATE_LIMIT");
    }

    private Mono<Void> temporarilyBlocked(CachedExchange cached, String requestId) {
        eventPublisher.publish(event(cached, requestId, "security.decision", HttpStatus.FORBIDDEN.value(), "TEMPORARY_BLOCK", "BEHAVIOURAL", 1.0));
        return securityResponse(cached.exchange(), requestId, HttpStatus.FORBIDDEN, "temporary_block", "BEHAVIOURAL");
    }

    private Mono<Void> securityResponse(ServerWebExchange exchange, String requestId, HttpStatus status, String code, String predictedAttack) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        exchange.getResponse().getHeaders().set("X-Request-ID", requestId);
        byte[] message = ("{\"error\":{\"code\":\"" + code + "\",\"predicted_attack\":\"" + predictedAttack + "\"},\"request_id\":\"" + requestId + "\"}").getBytes(StandardCharsets.UTF_8);
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(message)));
    }

    private SecurityEvent event(CachedExchange cached, String requestId, String category, int status, String action,
                                String predictedAttack, double risk) {
        ServerHttpRequest request = cached.getRequest();
        return SecurityEvent.create(category, requestId, sourceIp(request), request.getMethod().name(),
            normalizedPath(request.getPath().value()), status, action, predictedAttack, risk);
    }

    private record CachedExchange(ServerWebExchange exchange, String body) {
        ServerHttpRequest getRequest() { return exchange.getRequest(); }
    }
}
