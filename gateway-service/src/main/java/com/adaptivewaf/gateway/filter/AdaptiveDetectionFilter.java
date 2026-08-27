package com.adaptivewaf.gateway.filter;

import com.adaptivewaf.gateway.detection.DetectionClient;
import com.adaptivewaf.gateway.detection.DetectionProperties;
import com.adaptivewaf.gateway.detection.DetectionVerdict;
import com.adaptivewaf.gateway.events.SecurityEvent;
import com.adaptivewaf.gateway.events.SecurityEventPublisher;
import com.adaptivewaf.gateway.behaviour.BehaviourSnapshot;
import com.adaptivewaf.gateway.behaviour.OperatingMode;
import com.adaptivewaf.gateway.behaviour.RedisBehaviourService;
import com.adaptivewaf.gateway.behaviour.RedisLoadModeService;
import com.adaptivewaf.gateway.network.RedisNetworkContextService;
import com.adaptivewaf.gateway.network.NetworkContextSnapshot;
import com.adaptivewaf.gateway.policy.GatewayPolicy;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
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
    private static final Duration REDIS_OPERATION_TIMEOUT = Duration.ofMillis(250);
    private final DetectionClient detectionClient;
    private final DetectionProperties detectionProperties;
    private final GatewayPolicy policy;
    private final RedisBehaviourService behaviourService;
    private final RedisLoadModeService loadModeService;
    private final SecurityEventPublisher eventPublisher;
    private final RedisNetworkContextService networkContextService;

    public AdaptiveDetectionFilter(DetectionClient detectionClient, DetectionProperties detectionProperties, GatewayPolicy policy,
                                   RedisBehaviourService behaviourService, RedisLoadModeService loadModeService,
                                   SecurityEventPublisher eventPublisher, RedisNetworkContextService networkContextService) {
        this.detectionClient = detectionClient;
        this.detectionProperties = detectionProperties;
        this.policy = policy;
        this.behaviourService = behaviourService;
        this.loadModeService = loadModeService;
        this.eventPublisher = eventPublisher;
        this.networkContextService = networkContextService;
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
        return cacheSafeBody(correlated, requestId)
            .flatMap(scope -> loadModeService.recordRequest(requestId)
                .timeout(REDIS_OPERATION_TIMEOUT)
                .flatMap(mode -> process(scope.withMode(mode), chain))
                .onErrorResume(error -> {
                    LOGGER.warn("Redis unavailable for request {}; using stateless processing", requestId);
                    return detectOrForward(scope.withMode(OperatingMode.NORMAL).withBehaviour(BehaviourSnapshot.empty()), chain);
                }));
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 100;
    }

    private Mono<RequestScope> cacheSafeBody(ServerWebExchange exchange, String requestId) {
        long contentLength = exchange.getRequest().getHeaders().getContentLength();
        if (contentLength < 0 || contentLength > detectionProperties.getMaxBodyBytes()) {
            return Mono.just(new RequestScope(exchange, "", requestId));
        }
        return DataBufferUtils.join(exchange.getRequest().getBody())
            .map(buffer -> cache(exchange, buffer, requestId))
            .defaultIfEmpty(new RequestScope(exchange, "", requestId));
    }

    private Mono<Void> process(RequestScope scope, GatewayFilterChain chain) {
        return behaviourService.isTemporarilyBlocked(scope.getRequest())
            .flatMap(blocked -> blocked
                ? temporarilyBlocked(scope)
                : behaviourService.observe(scope.getRequest(), scope.requestId())
                    .flatMap(behaviour -> behaviour.rateLimited()
                        ? rateLimited(scope.withBehaviour(behaviour))
                        : detectOrForward(scope.withBehaviour(behaviour), chain)))
            .timeout(REDIS_OPERATION_TIMEOUT);
    }

    private Mono<Void> detectOrForward(RequestScope scope, GatewayFilterChain chain) {
        if (!scope.mode().permitsModelInference()) {
            LOGGER.warn("Skipping model inference for request {} in {} mode", scope.requestId(), scope.mode());
            scope.recordVerdict(new DetectionVerdict(0.0, "SKIPPED"), 0.0);
            return forwardAndRecord(scope, chain, "INFERENCE_SKIPPED_UNDER_LOAD");
        }
        return networkContextService.context(scope.getRequest())
            .doOnNext(scope::withNetwork)
            .flatMap(network -> {
                long detectionStart = System.nanoTime();
                return detectionClient.detect(toDetectionRequest(scope, network))
                    .doOnNext(verdict -> scope.recordVerdict(verdict, elapsedMs(detectionStart)));
            })
            .flatMap(verdict -> {
                LOGGER.debug("Detection verdict for request {}: attack={}, risk={}", scope.requestId(), verdict.predictedAttack(), verdict.overallRisk());
                if (policy.shouldBlock(verdict)) {
                    eventPublisher.publish(scope.event("security.attack")
                        .outcome(HttpStatus.FORBIDDEN.value(), "BLOCK", verdict.predictedAttack(), verdict.overallRisk(), "BLOCKED_AT_GATEWAY")
                        .build());
                    return behaviourService.recordOutcome(scope.getRequest(), HttpStatus.FORBIDDEN.value(), verdict.overallRisk(), verdict.predictedAttack())
                        .onErrorResume(error -> Mono.empty())
                        .then(block(scope.exchange(), scope.requestId(), verdict.predictedAttack()));
                }
                // A request the fast experts were unsure about is forwarded now and adjudicated out of band; the
                // mitigation records that it was allowed provisionally rather than on a settled verdict.
                return forwardAndRecord(scope, chain,
                    verdict.deepEscalationPending() ? "FORWARDED_PENDING_DEEP_ESCALATION" : "FORWARDED_TO_UPSTREAM");
            })
            .onErrorResume(error -> {
                LOGGER.warn("Detection unavailable for request {}: {}; forwarding request", scope.requestId(), error.getClass().getSimpleName());
                scope.recordVerdict(new DetectionVerdict(0.0, "UNAVAILABLE"), 0.0);
                return forwardAndRecord(scope, chain, "FAIL_OPEN_DETECTION_UNAVAILABLE");
            });
    }

    private Mono<Void> forwardAndRecord(RequestScope scope, GatewayFilterChain chain, String mitigation) {
        long forwardStart = System.nanoTime();
        scope.exchange().getResponse().beforeCommit(() -> {
            int status = responseStatus(scope.exchange());
            DetectionVerdict verdict = scope.verdict();
            eventPublisher.publish(scope.event("security.request")
                .outcome(status, "ALLOW", verdict.predictedAttack(), verdict.overallRisk(), mitigation)
                .timings(scope.detectionLatencyMs(), elapsedMs(forwardStart), scope.totalLatencyMs())
                .build());
            return behaviourService.recordOutcome(scope.getRequest(), status, verdict.overallRisk(), verdict.predictedAttack())
                .onErrorResume(error -> {
                    LOGGER.warn("Could not persist behavioural outcome: {}", error.getClass().getSimpleName());
                    return Mono.empty();
                });
        });
        return chain.filter(scope.exchange());
    }

    private int responseStatus(ServerWebExchange exchange) {
        return exchange.getResponse().getStatusCode() == null ? 200 : exchange.getResponse().getStatusCode().value();
    }

    private RequestScope cache(ServerWebExchange exchange, DataBuffer buffer, String requestId) {
        byte[] bytes = new byte[buffer.readableByteCount()];
        buffer.read(bytes);
        DataBufferUtils.release(buffer);
        ServerHttpRequest decoratedRequest = new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            public Flux<DataBuffer> getBody() {
                return Flux.defer(() -> Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
            }
        };
        return new RequestScope(exchange.mutate().request(decoratedRequest).build(), new String(bytes, StandardCharsets.UTF_8), requestId);
    }

    private Map<String, Object> toDetectionRequest(RequestScope scope, NetworkContextSnapshot network) {
        ServerHttpRequest request = scope.getRequest();
        Map<String, Object> payload = new LinkedHashMap<>();
        String normalizedPath = normalizedPath(request.getPath().value());
        String normalizedQuery = normalizedQuery(request);
        LOGGER.debug("Detection representation for request {}: path={}, queryLength={}", scope.requestId(), normalizedPath, normalizedQuery.length());
        payload.put("method", request.getMethod().name());
        payload.put("path", normalizedPath);
        payload.put("query", normalizedQuery);
        payload.put("headers", safeHeaders(request.getHeaders()));
        payload.put("cookies", request.getCookies().toSingleValueMap());
        payload.put("body", scope.body());
        payload.put("source_ip", sourceIp(request));
        payload.put("request_id", scope.requestId());
        payload.put("behaviour_context", scope.behaviour().asDetectionContext());
        payload.put("network_context", network.asDetectionContext());
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
        String forwarded = request.getHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
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

    private static double elapsedMs(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000.0;
    }

    private Mono<Void> block(ServerWebExchange exchange, String requestId, String predictedAttack) {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        exchange.getResponse().getHeaders().set("X-Request-ID", requestId);
        byte[] message = ("{\"error\":{\"code\":\"waf_blocked\",\"predicted_attack\":\"" + predictedAttack + "\"},\"request_id\":\"" + requestId + "\"}").getBytes(StandardCharsets.UTF_8);
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(message)));
    }

    private Mono<Void> rateLimited(RequestScope scope) {
        eventPublisher.publish(scope.event("security.decision")
            .outcome(HttpStatus.TOO_MANY_REQUESTS.value(), "RATE_LIMIT", "RATE_LIMIT", 1.0, "RATE_LIMITED_AT_GATEWAY")
            .build());
        return securityResponse(scope.exchange(), scope.requestId(), HttpStatus.TOO_MANY_REQUESTS, "rate_limited", "RATE_LIMIT");
    }

    private Mono<Void> temporarilyBlocked(RequestScope scope) {
        eventPublisher.publish(scope.event("security.decision")
            .outcome(HttpStatus.FORBIDDEN.value(), "TEMPORARY_BLOCK", "BEHAVIOURAL", 1.0, "TEMPORARY_BLOCK_ACTIVE")
            .build());
        return securityResponse(scope.exchange(), scope.requestId(), HttpStatus.FORBIDDEN, "temporary_block", "BEHAVIOURAL");
    }

    private Mono<Void> securityResponse(ServerWebExchange exchange, String requestId, HttpStatus status, String code, String predictedAttack) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        exchange.getResponse().getHeaders().set("X-Request-ID", requestId);
        byte[] message = ("{\"error\":{\"code\":\"" + code + "\",\"predicted_attack\":\"" + predictedAttack + "\"},\"request_id\":\"" + requestId + "\"}").getBytes(StandardCharsets.UTF_8);
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(message)));
    }

    /** Mutable per-request state used to assemble one fully evidenced security event. */
    private final class RequestScope {
        private final ServerWebExchange exchange;
        private final String body;
        private final String requestId;
        private final long startNanos = System.nanoTime();
        private OperatingMode mode = OperatingMode.NORMAL;
        private BehaviourSnapshot behaviour = BehaviourSnapshot.empty();
        private NetworkContextSnapshot network = NetworkContextSnapshot.empty();
        private DetectionVerdict verdict = new DetectionVerdict(0.0, "UNEVALUATED");
        private double detectionLatencyMs;

        private RequestScope(ServerWebExchange exchange, String body, String requestId) {
            this.exchange = exchange; this.body = body; this.requestId = requestId;
        }

        ServerWebExchange exchange() { return exchange; }
        ServerHttpRequest getRequest() { return exchange.getRequest(); }
        String body() { return body; }
        String requestId() { return requestId; }
        OperatingMode mode() { return mode; }
        BehaviourSnapshot behaviour() { return behaviour; }
        DetectionVerdict verdict() { return verdict; }
        double detectionLatencyMs() { return detectionLatencyMs; }
        double totalLatencyMs() { return elapsedMs(startNanos); }

        RequestScope withMode(OperatingMode value) { this.mode = value; return this; }
        RequestScope withBehaviour(BehaviourSnapshot value) { this.behaviour = value; return this; }
        RequestScope withNetwork(NetworkContextSnapshot value) { this.network = value; return this; }
        void recordVerdict(DetectionVerdict value, double latencyMs) { this.verdict = value; this.detectionLatencyMs = latencyMs; }

        SecurityEvent.Builder event(String category) {
            ServerHttpRequest request = getRequest();
            JsonNode evidence = verdict.evidence();
            return SecurityEvent.builder(category)
                .request(requestId, sourceIp(request), request.getMethod().name(),
                    normalizedPath(request.getPath().value()), normalizedQuery(request))
                .context(mode.name(), request.getHeaders().getFirst(HttpHeaders.USER_AGENT), upstream())
                .timings(detectionLatencyMs, 0.0, totalLatencyMs())
                .evidence(behaviourEvidence(), networkEvidence(), evidence);
        }

        private Map<String, Object> behaviourEvidence() {
            Map<String, Object> values = new LinkedHashMap<>();
            values.put("risk", behaviour.risk());
            values.put("shortWindowRequests", behaviour.shortWindowRequests());
            values.put("mediumWindowRequests", behaviour.mediumWindowRequests());
            values.put("failedAuthAttempts", behaviour.failedAuthAttempts());
            values.put("endpointRequests", behaviour.endpointRequests());
            values.put("previousAttackCount", behaviour.previousAttackCount());
            values.put("rateLimited", behaviour.rateLimited());
            values.put("temporarilyBlocked", behaviour.temporarilyBlocked());
            return values;
        }

        private Map<String, Object> networkEvidence() {
            Map<String, Object> values = new LinkedHashMap<>();
            values.put("risk", network.risk());
            values.put("networkClass", network.networkClass() == null ? "UNKNOWN" : network.networkClass());
            values.put("confidence", network.confidence());
            return values;
        }

        private String upstream() {
            Object routed = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_REQUEST_URL_ATTR);
            return routed instanceof URI uri ? uri.toString() : null;
        }
    }
}
