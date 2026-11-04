package com.adaptivewaf.gateway.filter;

import com.adaptivewaf.gateway.detection.DetectionClient;
import com.adaptivewaf.gateway.detection.DetectionProperties;
import com.adaptivewaf.gateway.detection.DetectionVerdict;
import com.adaptivewaf.gateway.detection.InspectionStatus;
import com.adaptivewaf.gateway.detection.SourceIdentity;
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
import org.springframework.core.io.buffer.DataBufferLimitException;
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
    private final SourceIdentity sourceIdentity;

    public AdaptiveDetectionFilter(DetectionClient detectionClient, DetectionProperties detectionProperties, GatewayPolicy policy,
                                   RedisBehaviourService behaviourService, RedisLoadModeService loadModeService,
                                   SecurityEventPublisher eventPublisher, RedisNetworkContextService networkContextService,
                                   SourceIdentity sourceIdentity) {
        this.detectionClient = detectionClient;
        this.detectionProperties = detectionProperties;
        this.policy = policy;
        this.behaviourService = behaviourService;
        this.loadModeService = loadModeService;
        this.eventPublisher = eventPublisher;
        this.networkContextService = networkContextService;
        this.sourceIdentity = sourceIdentity;
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
        correlated.getResponse().getHeaders().set("X-Request-ID", requestId);
        return cacheSafeBody(correlated, requestId)
            .onErrorResume(DataBufferLimitException.class, error -> rejectInspection(correlated, requestId, HttpStatus.PAYLOAD_TOO_LARGE))
            .onErrorResume(java.util.concurrent.TimeoutException.class, error -> rejectInspection(correlated, requestId, HttpStatus.REQUEST_TIMEOUT))
            .onErrorResume(UninspectableBodyException.class, error -> rejectInspection(correlated, requestId, HttpStatus.UNSUPPORTED_MEDIA_TYPE))
            .flatMap(scope -> loadModeService.recordRequest(requestId)
                .timeout(REDIS_OPERATION_TIMEOUT)
                .onErrorResume(error -> {
                    LOGGER.warn("Redis unavailable for request {}; using stateless processing", requestId);
                    return Mono.just(OperatingMode.NORMAL);
                })
                .flatMap(mode -> process(scope.withMode(mode), chain)));
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 100;
    }

    private Mono<RequestScope> cacheSafeBody(ServerWebExchange exchange, String requestId) {
        long contentLength = exchange.getRequest().getHeaders().getContentLength();
        if (contentLength > detectionProperties.getMaxBodyBytes()) {
            return Mono.error(new DataBufferLimitException("request exceeds inspection limit"));
        }
        return DataBufferUtils.join(exchange.getRequest().getBody(), detectionProperties.getMaxBodyBytes())
            .timeout(detectionProperties.getBodyReadTimeout())
            .map(buffer -> cache(exchange, buffer, requestId))
            .defaultIfEmpty(new RequestScope(exchange, "", requestId));
    }

    private Mono<RequestScope> rejectInspection(ServerWebExchange exchange, String requestId, HttpStatus status) {
        RequestScope scope = new RequestScope(exchange, "", requestId);
        scope.inspectionStatus = InspectionStatus.INSPECTION_REJECTED;
        exchange.getResponse().getHeaders().set("X-WAF-Inspection-Status", scope.inspectionStatus.name());
        eventPublisher.publish(scope.event("security.decision")
            .outcome(status.value(), "BLOCK", "UNEVALUATED", 0.0, "INSPECTION_REJECTED").build());
        return securityResponse(exchange, requestId, status, "inspection_rejected", "UNEVALUATED").then(Mono.empty());
    }

    private Mono<Void> process(RequestScope scope, GatewayFilterChain chain) {
        return behaviourService.isTemporarilyBlocked(scope.getRequest())
            .flatMap(blocked -> blocked ? Mono.just(BehaviourSnapshot.empty().withTemporaryBlock())
                : behaviourService.observe(scope.getRequest(), scope.requestId()))
            .timeout(REDIS_OPERATION_TIMEOUT)
            .onErrorReturn(BehaviourSnapshot.empty())
            .flatMap(behaviour -> {
                scope.withBehaviour(behaviour);
                if (behaviour.rateLimited()) { return rateLimited(scope); }
                if (behaviour.temporarilyBlocked()) { return temporarilyBlocked(scope); }
                return detectOrForward(scope, chain);
            });
    }

    private Mono<Void> detectOrForward(RequestScope scope, GatewayFilterChain chain) {
        if (!scope.mode().permitsModelInference()) {
            LOGGER.warn("Skipping model inference for request {} in {} mode", scope.requestId(), scope.mode());
            scope.recordVerdict(new DetectionVerdict(0.0, "SKIPPED"), 0.0);
            return unavailableOrForward(scope, chain, "INFERENCE_SKIPPED_UNDER_LOAD");
        }
        return networkContextService.context(scope.getRequest())
            .doOnNext(scope::withNetwork)
            .flatMap(network -> {
                long detectionStart = System.nanoTime();
                return detectionClient.detect(toDetectionRequest(scope, network))
                    .doOnNext(verdict -> scope.recordVerdict(verdict, elapsedMs(detectionStart)));
            })
            .onErrorResume(error -> {
                LOGGER.warn("Detection unavailable for request {}: {}", scope.requestId(), error.getClass().getSimpleName());
                DetectionVerdict unavailable = new DetectionVerdict(0.0, "UNAVAILABLE");
                scope.recordVerdict(unavailable, 0.0);
                return Mono.just(unavailable);
            })
            .flatMap(verdict -> {
                if ("UNAVAILABLE".equals(verdict.predictedAttack())) {
                    return unavailableOrForward(scope, chain, "FAIL_OPEN_DETECTION_UNAVAILABLE");
                }
                boolean rejectedEscalation = verdict.evidence().path("explanation_evidence").path("deep_escalation")
                    .asText("").startsWith("rejected_");
                if (rejectedEscalation && detectionProperties.isFailClosed()) {
                    return unavailableOrForward(scope, chain, "DEEP_ESCALATION_REJECTED");
                }
                scope.inspectionStatus = verdict.deepEscalationPending() || rejectedEscalation
                    ? InspectionStatus.PARTIALLY_INSPECTED : InspectionStatus.FULLY_INSPECTED;
                String coverage = verdict.evidence().path("inspection_status").asText("");
                if (!coverage.isBlank()) { scope.inspectionStatus = InspectionStatus.valueOf(coverage); }
                scope.exchange().getResponse().getHeaders().set("X-WAF-Inspection-Status", scope.inspectionStatus.name());
                LOGGER.debug("Detection verdict for request {}: attack={}, risk={}", scope.requestId(), verdict.predictedAttack(), verdict.overallRisk());
                if (policy.shouldBlock(verdict)) {
                    eventPublisher.publish(scope.event("security.attack")
                        .outcome(HttpStatus.FORBIDDEN.value(), "BLOCK", verdict.predictedAttack(), verdict.overallRisk(), "BLOCKED_AT_GATEWAY")
                        .build());
                    return behaviourService.recordOutcome(scope.getRequest(), HttpStatus.FORBIDDEN.value(), verdict.overallRisk(), verdict.predictedAttack())
                        .timeout(REDIS_OPERATION_TIMEOUT)
                        .onErrorResume(error -> Mono.empty())
                        .then(block(scope.exchange(), scope.requestId(), verdict.predictedAttack()));
                }
                if ("RATE_LIMIT".equals(verdict.evidence().path("decision").path("recommended_action").asText())) {
                    eventPublisher.publish(scope.event("security.decision")
                        .outcome(429, "RATE_LIMIT", verdict.predictedAttack(), verdict.overallRisk(), "MODEL_RATE_LIMIT").build());
                    return securityResponse(scope.exchange(), scope.requestId(), HttpStatus.TOO_MANY_REQUESTS, "rate_limited", verdict.predictedAttack());
                }
                // A request the fast experts were unsure about is forwarded now and adjudicated out of band; the
                // mitigation records that it was allowed provisionally rather than on a settled verdict.
                return forwardAndRecord(scope, chain,
                    verdict.deepEscalationPending() ? "FORWARDED_PENDING_DEEP_ESCALATION" : "FORWARDED_TO_UPSTREAM");
            });
    }

    private Mono<Void> unavailableOrForward(RequestScope scope, GatewayFilterChain chain, String mitigation) {
        scope.inspectionStatus = InspectionStatus.DETECTION_UNAVAILABLE;
        scope.exchange().getResponse().getHeaders().set("X-WAF-Inspection-Status", scope.inspectionStatus.name());
        if (detectionProperties.isFailClosed()) {
            eventPublisher.publish(scope.event("security.decision")
                .outcome(503, "BLOCK", scope.verdict().predictedAttack(), 0.0, "FAIL_CLOSED_DETECTION_UNAVAILABLE").build());
            return securityResponse(scope.exchange(), scope.requestId(), HttpStatus.SERVICE_UNAVAILABLE, "detection_unavailable", "UNAVAILABLE");
        }
        return forwardAndRecord(scope, chain, mitigation);
    }

    private Mono<Void> forwardAndRecord(RequestScope scope, GatewayFilterChain chain, String mitigation) {
        String action = "MONITOR".equals(scope.verdict().evidence().path("decision").path("recommended_action").asText()) ? "MONITOR" : "ALLOW";
        scope.exchange().getResponse().getHeaders().set("X-WAF-Action", action);
        long forwardStart = System.nanoTime();
        scope.exchange().getResponse().beforeCommit(() -> {
            scope.exchange().getResponse().getHeaders().set("X-WAF-Action", action);
            scope.exchange().getResponse().getHeaders().set("X-Request-ID", scope.requestId());
            scope.exchange().getResponse().getHeaders().set("X-WAF-Inspection-Status", scope.inspectionStatus.name());
            int status = responseStatus(scope.exchange());
            DetectionVerdict verdict = scope.verdict();
            eventPublisher.publish(scope.event("security.request")
                .outcome(status, action, verdict.predictedAttack(), verdict.overallRisk(), mitigation)
                .timings(scope.detectionLatencyMs(), elapsedMs(forwardStart), scope.totalLatencyMs())
                .build());
            return behaviourService.recordOutcome(scope.getRequest(), status, verdict.overallRisk(), verdict.predictedAttack())
                .timeout(REDIS_OPERATION_TIMEOUT)
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
        String body;
        try {
            String encoding = exchange.getRequest().getHeaders().getFirst(HttpHeaders.CONTENT_ENCODING);
            MediaType type = exchange.getRequest().getHeaders().getContentType();
            if (bytes.length > 0 && ((encoding != null && !encoding.equalsIgnoreCase("identity"))
                    || (type != null && !("text".equals(type.getType()) || MediaType.APPLICATION_JSON.isCompatibleWith(type)
                        || type.getSubtype().endsWith("+json") || MediaType.APPLICATION_FORM_URLENCODED.isCompatibleWith(type))))) {
                throw new UninspectableBodyException();
            }
            var charset = type != null && type.getCharset() != null ? type.getCharset() : StandardCharsets.UTF_8;
            body = charset.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(bytes)).toString();
        } catch (java.nio.charset.CharacterCodingException | IllegalArgumentException error) {
            throw new UninspectableBodyException();
        }
        return new RequestScope(exchange.mutate().request(decoratedRequest).build(), body, requestId);
    }

    private static final class UninspectableBodyException extends RuntimeException { }

    private Map<String, Object> toDetectionRequest(RequestScope scope, NetworkContextSnapshot network) {
        ServerHttpRequest request = scope.getRequest();
        Map<String, Object> payload = new LinkedHashMap<>();
        String normalizedPath = normalizedPath(request.getPath().value());
        String normalizedQuery = normalizedQuery(request);
        payload.put("method", request.getMethod().name());
        payload.put("path", normalizedPath);
        payload.put("query", normalizedQuery);
        payload.put("headers", safeHeaders(request.getHeaders()));
        payload.put("cookies", inspectionCookies(request));
        payload.put("body", scope.body());
        payload.put("source_ip", sourceIp(request));
        payload.put("request_id", scope.requestId());
        String secret = detectionProperties.getSessionHmacSecret();
        var session = request.getCookies().getFirst("session");
        if (secret.length() >= 32 && session != null) {
            try {
                var mac = javax.crypto.Mac.getInstance("HmacSHA256");
                mac.init(new javax.crypto.spec.SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
                payload.put("session_key", java.util.HexFormat.of().formatHex(mac.doFinal(session.getValue().getBytes(StandardCharsets.UTF_8))));
            } catch (java.security.GeneralSecurityException error) { throw new IllegalStateException("session identity unavailable"); }
        }
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

    private Map<String, String> inspectionCookies(ServerHttpRequest request) {
        Map<String, String> values = new LinkedHashMap<>();
        var rawHeaders = request.getHeaders().getOrEmpty(HttpHeaders.COOKIE);
        if (rawHeaders.isEmpty()) {
            request.getCookies().forEach((name, entries) -> values.put(name,
                entries.stream().map(org.springframework.http.HttpCookie::getValue).collect(Collectors.joining("; "))));
            return values;
        }
        int index = 0;
        // Inspection must include bytes rejected by a strict cookie parser; never silently discard those values.
        for (String header : rawHeaders) {
            for (String part : header.split(";", -1)) {
                int equals = part.indexOf('=');
                String name = equals > 0 ? part.substring(0, equals).trim() : "__raw_cookie_" + index;
                String value = equals > 0 ? part.substring(equals + 1).trim() : part.trim();
                values.merge(name, value, (first, second) -> first + "; " + second);
                index++;
            }
        }
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
        return sourceIdentity.sourceIp(request);
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
        String query = request.getURI().getRawQuery();
        return query == null ? "" : query;
    }

    private String requestId(HttpHeaders headers) {
        String supplied = headers.getFirst("X-Request-ID");
        try { return UUID.fromString(supplied).toString(); }
        catch (IllegalArgumentException | NullPointerException error) { return UUID.randomUUID().toString(); }
    }

    private static double elapsedMs(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000.0;
    }

    private Mono<Void> block(ServerWebExchange exchange, String requestId, String predictedAttack) {
        exchange.getResponse().getHeaders().set("X-WAF-Action", "BLOCK");
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        exchange.getResponse().getHeaders().set("X-Request-ID", requestId);
        byte[] message = ("{\"error\":{\"code\":\"waf_blocked\",\"predicted_attack\":\"" + predictedAttack + "\"},\"request_id\":\"" + requestId + "\"}").getBytes(StandardCharsets.UTF_8);
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(message)));
    }

    private Mono<Void> rateLimited(RequestScope scope) {
        scope.inspectionStatus = InspectionStatus.RULES_ONLY;
        scope.exchange().getResponse().getHeaders().set("X-WAF-Inspection-Status", scope.inspectionStatus.name());
        eventPublisher.publish(scope.event("security.decision")
            .outcome(HttpStatus.TOO_MANY_REQUESTS.value(), "RATE_LIMIT", "RATE_LIMIT", 1.0, "RATE_LIMITED_AT_GATEWAY")
            .build());
        return securityResponse(scope.exchange(), scope.requestId(), HttpStatus.TOO_MANY_REQUESTS, "rate_limited", "RATE_LIMIT");
    }

    private Mono<Void> temporarilyBlocked(RequestScope scope) {
        scope.inspectionStatus = InspectionStatus.RULES_ONLY;
        scope.exchange().getResponse().getHeaders().set("X-WAF-Inspection-Status", scope.inspectionStatus.name());
        eventPublisher.publish(scope.event("security.decision")
            .outcome(HttpStatus.FORBIDDEN.value(), "BLOCK", "BEHAVIOURAL", 1.0, "TEMPORARY_BLOCK_ACTIVE")
            .build());
        return securityResponse(scope.exchange(), scope.requestId(), HttpStatus.FORBIDDEN, "temporary_block", "BEHAVIOURAL");
    }

    private Mono<Void> securityResponse(ServerWebExchange exchange, String requestId, HttpStatus status, String code, String predictedAttack) {
        exchange.getResponse().getHeaders().set("X-WAF-Action", status == HttpStatus.TOO_MANY_REQUESTS ? "RATE_LIMIT" : "BLOCK");
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
        private InspectionStatus inspectionStatus = InspectionStatus.DETECTION_UNAVAILABLE;

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
                .inspectionStatus(inspectionStatus.name())
                .request(requestId, sourceIp(request), request.getMethod().name(),
                    normalizedPath(request.getPath().value()), "[REDACTED]")
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
            if (!(routed instanceof URI uri)) { return null; }
            try { return new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), uri.getPath(), null, null).toString(); }
            catch (java.net.URISyntaxException error) { return null; }
        }
    }
}
