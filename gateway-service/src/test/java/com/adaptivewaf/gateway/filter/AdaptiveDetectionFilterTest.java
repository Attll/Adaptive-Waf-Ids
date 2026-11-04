package com.adaptivewaf.gateway.filter;

import com.adaptivewaf.gateway.behaviour.*;
import com.adaptivewaf.gateway.detection.*;
import com.adaptivewaf.gateway.events.SecurityEventPublisher;
import com.adaptivewaf.gateway.network.*;
import com.adaptivewaf.gateway.policy.GatewayPolicy;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpCookie;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AdaptiveDetectionFilterTest {
    private final DetectionClient client = mock(DetectionClient.class);
    private final DetectionProperties properties = new DetectionProperties();
    private final GatewayPolicy policy = mock(GatewayPolicy.class);
    private final RedisBehaviourService behaviour = mock(RedisBehaviourService.class);
    private final RedisLoadModeService load = mock(RedisLoadModeService.class);
    private final SecurityEventPublisher events = mock(SecurityEventPublisher.class);
    private final RedisNetworkContextService network = mock(RedisNetworkContextService.class);
    private AdaptiveDetectionFilter filter;

    @BeforeEach void setup() {
        when(load.recordRequest(anyString())).thenReturn(Mono.just(OperatingMode.NORMAL));
        when(behaviour.isTemporarilyBlocked(any())).thenReturn(Mono.just(false));
        when(behaviour.observe(any(), anyString())).thenReturn(Mono.just(BehaviourSnapshot.empty()));
        when(behaviour.recordOutcome(any(), anyInt(), anyDouble(), anyString())).thenReturn(Mono.empty());
        when(network.context(any())).thenReturn(Mono.just(NetworkContextSnapshot.empty()));
        when(client.detect(anyMap())).thenReturn(Mono.just(new DetectionVerdict(0.01, "BENIGN")));
        filter = new AdaptiveDetectionFilter(client, properties, policy, behaviour, load, events, network, new SourceIdentity(properties));
    }

    @Test void delayedPostPreservesBodyAndForwardsOnce() {
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/backend/save").body("payload=exact"));
        AtomicInteger forwards = new AtomicInteger();
        AtomicReference<String> body = new AtomicReference<>();
        filter.filter(exchange, upstream -> {
            forwards.incrementAndGet();
            return org.springframework.core.io.buffer.DataBufferUtils.join(upstream.getRequest().getBody())
                .flatMap(buffer -> {
                    body.set(buffer.toString(StandardCharsets.UTF_8));
                    org.springframework.core.io.buffer.DataBufferUtils.release(buffer);
                    return Mono.delay(Duration.ofMillis(400)).then(upstream.getResponse().setComplete());
                });
        }).block(Duration.ofSeconds(3));
        assertEquals(1, forwards.get());
        assertEquals("payload=exact", body.get());
        assertEquals("FULLY_INSPECTED", exchange.getResponse().getHeaders().getFirst("X-WAF-Inspection-Status"));
    }

    @Test void upstreamErrorPropagatesWithoutAnotherForward() {
        AtomicInteger forwards = new AtomicInteger();
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/backend/save").body("data"));
        assertThrows(IllegalStateException.class, () -> filter.filter(exchange, upstream -> {
            forwards.incrementAndGet();
            return Mono.error(new IllegalStateException("upstream failed"));
        }).block());
        assertEquals(1, forwards.get());
    }

    @Test void slowDetectionIsOutsideRedisDeadline() {
        when(client.detect(anyMap())).thenReturn(Mono.delay(Duration.ofMillis(350)).map(ignored -> new DetectionVerdict(.01, "BENIGN")));
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/backend/health"));
        filter.filter(exchange, upstream -> upstream.getResponse().setComplete()).block(Duration.ofSeconds(3));
        assertEquals("FULLY_INSPECTED", exchange.getResponse().getHeaders().getFirst("X-WAF-Inspection-Status"));
        verify(client, times(1)).detect(anyMap());
    }

    @Test void chunkedBodyAndCookieValuesReachDetection() {
        var request = MockServerHttpRequest.method(org.springframework.http.HttpMethod.POST, java.net.URI.create("/backend/save?q=a%26b&q=c&empty="))
            .cookie(new HttpCookie("session", "suspicious-value"))
            .header("X-Request-ID", "not-a-uuid")
            .body(Flux.just(DefaultDataBufferFactory.sharedInstance.wrap("chunked".getBytes(StandardCharsets.UTF_8))));
        var exchange = MockServerWebExchange.from(request);
        filter.filter(exchange, upstream -> upstream.getResponse().setComplete()).block();
        var captured = org.mockito.ArgumentCaptor.forClass(Map.class);
        verify(client).detect(captured.capture());
        assertEquals("chunked", captured.getValue().get("body"));
        assertEquals("q=a%26b&q=c&empty=", captured.getValue().get("query"));
        assertEquals(Map.of("session", "suspicious-value"), captured.getValue().get("cookies"));
        UUID.fromString((String) captured.getValue().get("request_id"));
    }

    @Test void oversizedStreamIsRejectedWithoutDetectionOrForward() {
        properties.setMaxBodyBytes(4);
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/backend/save")
            .body(Flux.just(DefaultDataBufferFactory.sharedInstance.wrap("12345".getBytes(StandardCharsets.UTF_8)))));
        filter.filter(exchange, upstream -> { fail("must not forward"); return Mono.empty(); }).block();
        assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, exchange.getResponse().getStatusCode());
        assertEquals("INSPECTION_REJECTED", exchange.getResponse().getHeaders().getFirst("X-WAF-Inspection-Status"));
        verifyNoInteractions(client);
    }

    @Test void exactBodyBoundaryIsAccepted() {
        properties.setMaxBodyBytes(4);
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/backend/save").body("1234"));
        filter.filter(exchange, upstream -> upstream.getResponse().setComplete()).block();
        verify(client).detect(anyMap());
    }

    @Test void encodedOrBinaryBodiesAreExplicitlyRejected() {
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/backend/save")
            .header("Content-Encoding", "gzip").body("compressed"));
        filter.filter(exchange, upstream -> { fail("must not forward"); return Mono.empty(); }).block();
        assertEquals(HttpStatus.UNSUPPORTED_MEDIA_TYPE, exchange.getResponse().getStatusCode());
        verifyNoInteractions(client);
    }

    @Test void nonTerminatingBodyTimesOutWithoutForward() {
        properties.setBodyReadTimeout(Duration.ofMillis(20));
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/backend/save").body(Flux.never()));
        filter.filter(exchange, upstream -> { fail("must not forward"); return Mono.empty(); }).block(Duration.ofSeconds(1));
        assertEquals(HttpStatus.REQUEST_TIMEOUT, exchange.getResponse().getStatusCode());
        verifyNoInteractions(client);
    }

    @Test void unavailableDetectionFailOpenIsExplicit() {
        when(client.detect(anyMap())).thenReturn(Mono.error(new IllegalStateException()));
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/backend/health"));
        AtomicInteger forwards = new AtomicInteger();
        filter.filter(exchange, upstream -> { forwards.incrementAndGet(); return upstream.getResponse().setComplete(); }).block();
        assertEquals(1, forwards.get());
        assertEquals("DETECTION_UNAVAILABLE", exchange.getResponse().getHeaders().getFirst("X-WAF-Inspection-Status"));
    }

    @Test void unavailableDetectionFailClosedNeverForwards() {
        properties.setFailClosed(true);
        when(client.detect(anyMap())).thenReturn(Mono.error(new IllegalStateException()));
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/backend/health"));
        filter.filter(exchange, upstream -> { fail("must not forward"); return Mono.empty(); }).block();
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, exchange.getResponse().getStatusCode());
    }

    @Test void redisFailureDoesNotDuplicateDetectionOrUpstream() {
        when(load.recordRequest(anyString())).thenReturn(Mono.error(new IllegalStateException()));
        when(behaviour.isTemporarilyBlocked(any())).thenReturn(Mono.never());
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/backend/health"));
        AtomicInteger forwards = new AtomicInteger();
        filter.filter(exchange, upstream -> { forwards.incrementAndGet(); return upstream.getResponse().setComplete(); }).block(Duration.ofSeconds(2));
        assertEquals(1, forwards.get());
        verify(client, times(1)).detect(anyMap());
    }

    @Test void deterministicBlockAndRateLimitNeverForward() {
        when(behaviour.observe(any(), anyString())).thenReturn(Mono.just(new BehaviourSnapshot(1, 40, 40, 0, 0, 0, true, false)));
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/backend/health"));
        filter.filter(exchange, upstream -> { fail("must not forward"); return Mono.empty(); }).block();
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, exchange.getResponse().getStatusCode());
        assertEquals("RULES_ONLY", exchange.getResponse().getHeaders().getFirst("X-WAF-Inspection-Status"));
        verifyNoInteractions(client);
    }

    @Test void blockedVerdictNeverForwards() {
        when(policy.shouldBlock(any())).thenReturn(true);
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/backend/search"));
        filter.filter(exchange, upstream -> { fail("must not forward"); return Mono.empty(); }).block();
        assertEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
    }
}
