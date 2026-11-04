package com.adaptivewaf.gateway.filter;

import com.adaptivewaf.gateway.behaviour.*;
import com.adaptivewaf.gateway.events.SecurityEventPublisher;
import com.adaptivewaf.gateway.network.*;
import com.adaptivewaf.gateway.policy.GatewayPolicy;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Real HTTP sockets + Spring Cloud Gateway + WebClient detection; Redis and models are explicit fixtures. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {"adaptive-waf.events.enabled=false", "adaptive-waf.detection.max-body-bytes=32",
        "adaptive-waf.detection.session-hmac-secret=fixture-session-secret-32-characters"})
class GatewayHttpIntegrationTest {
    private static final AtomicInteger POSTS = new AtomicInteger();
    private static final java.util.concurrent.atomic.AtomicReference<String> LAST_INSPECTION = new java.util.concurrent.atomic.AtomicReference<>();
    private static final java.util.concurrent.atomic.AtomicReference<String> LAST_BACKEND_URI = new java.util.concurrent.atomic.AtomicReference<>();
    private static final DisposableServer BACKEND = HttpServer.create().host("127.0.0.1").port(0)
        .handle((request, response) -> request.receive().aggregate().asString().defaultIfEmpty("").flatMap(body -> {
            POSTS.incrementAndGet();
            LAST_BACKEND_URI.set(request.uri());
            if (request.uri().equals("/error")) { return response.status(503).sendString(Mono.just("upstream unavailable")).then(); }
            return Mono.delay(Duration.ofMillis(400)).then(response.sendString(Mono.just(body)).then());
        })).bindNow();
    private static final DisposableServer DETECTION = HttpServer.create().host("127.0.0.1").port(0)
        .handle((request, response) -> request.receive().aggregate().asString().flatMap(body -> {
            LAST_INSPECTION.set(body);
            if (body.contains("/unavailable")) { return response.status(503).send().then(); }
            return response.header("Content-Type", "application/json").sendString(Mono.just(
                "{\"detection\":{\"risks\":{\"overall\":0.01},\"predicted_attack\":\"BENIGN\"}}")).then();
        })).bindNow();

    @LocalServerPort int port;
    @MockBean RedisLoadModeService load;
    @MockBean RedisBehaviourService behaviour;
    @MockBean RedisNetworkContextService network;
    @MockBean GatewayPolicy policy;
    @MockBean SecurityEventPublisher events;

    @DynamicPropertySource static void endpoints(DynamicPropertyRegistry registry) {
        registry.add("DEMO_BACKEND_URL", () -> "http://127.0.0.1:" + BACKEND.port());
        registry.add("adaptive-waf.detection.base-url", () -> "http://127.0.0.1:" + DETECTION.port());
    }

    @BeforeEach void setup() {
        POSTS.set(0);
        when(load.recordRequest(anyString())).thenReturn(Mono.just(OperatingMode.NORMAL));
        when(behaviour.isTemporarilyBlocked(any())).thenReturn(Mono.just(false));
        when(behaviour.observe(any(), anyString())).thenReturn(Mono.just(BehaviourSnapshot.empty()));
        when(behaviour.recordOutcome(any(), anyInt(), anyDouble(), anyString())).thenReturn(Mono.empty());
        when(network.context(any())).thenReturn(Mono.just(NetworkContextSnapshot.empty()));
    }

    @AfterAll static void closeFixtures() { BACKEND.disposeNow(); DETECTION.disposeNow(); }

    @Test void delayedChunkedPostExecutesExactlyOnceWithUnchangedBytes() {
        var response = client().post().uri("/backend/slow")
            .body(Flux.just("alpha=", "hello&beta=world"), String.class)
            .retrieve().toEntity(String.class).block(Duration.ofSeconds(5));
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("alpha=hello&beta=world", response.getBody());
        assertEquals(1, POSTS.get());
        assertEquals("FULLY_INSPECTED", response.getHeaders().getFirst("X-WAF-Inspection-Status"));
        assertNotNull(response.getHeaders().getFirst("X-Request-ID"));
    }

    @Test void upstream503IsReturnedWithoutRetry() {
        var response = client().post().uri("/backend/error").bodyValue("x=1")
            .exchangeToMono(result -> result.toEntity(String.class)).block(Duration.ofSeconds(5));
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
        assertEquals("upstream unavailable", response.getBody());
        assertEquals(1, POSTS.get());
    }

    @Test void rawCookieRejectedByStrictParserStillReachesInspection() throws Exception {
        client().post().uri("/backend/slow").header("Cookie", "session=' OR 1=1--")
            .bodyValue("x=1").retrieve().toBodilessEntity().block(Duration.ofSeconds(5));
        var inspected = new com.fasterxml.jackson.databind.ObjectMapper().readTree(LAST_INSPECTION.get());
        assertEquals("' OR 1=1--", inspected.path("cookies").path("session").asText());
        assertEquals(1, POSTS.get());
    }

    @Test void explicitSessionIdentityIsPseudonymousAndCompatibleWithPythonHmac() throws Exception {
        client().post().uri("/backend/slow").header("Cookie", "session=fixture-session-a")
            .bodyValue("x=1").retrieve().toBodilessEntity().block(Duration.ofSeconds(5));
        var inspected = new com.fasterxml.jackson.databind.ObjectMapper().readTree(LAST_INSPECTION.get());
        var mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec("fixture-session-secret-32-characters".getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256"));
        assertEquals(java.util.HexFormat.of().formatHex(mac.doFinal("fixture-session-a".getBytes(java.nio.charset.StandardCharsets.UTF_8))),
            inspected.path("session_key").asText());
    }

    @Test void parserDifferentialFixturesPreserveRawQueryPathAndSupportedBodyBytes() throws Exception {
        var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        var cases = java.util.List.of(
            new String[]{"/backend/echo?x=1&x=2&empty=&missing", "application/x-www-form-urlencoded", "a=1&a=2&empty="},
            new String[]{"/backend/a%2Fb?value=%252e%252e%252f", "application/json", "{\"a\":{\"b\":[1,null]}}"},
            new String[]{"/backend/unicode?q=%EF%BC%9C%26%2B", "text/plain;charset=UTF-8", "café é"},
            new String[]{"/backend/empty?flag&value=", "text/plain", ""},
            new String[]{"/backend/boundary", "text/plain", "x".repeat(32)});
        for (var fixture : cases) {
            var response = client().post().uri(java.net.URI.create("http://127.0.0.1:" + port + fixture[0]))
                .header("Content-Type", fixture[1]).bodyValue(fixture[2]).retrieve().toEntity(String.class).block(Duration.ofSeconds(5));
            var inspection = mapper.readTree(LAST_INSPECTION.get());
            var backendUri = java.net.URI.create(LAST_BACKEND_URI.get());
            assertEquals(backendUri.getRawPath(), inspection.path("path").asText(), fixture[0]);
            assertEquals(backendUri.getRawQuery() == null ? "" : backendUri.getRawQuery(), inspection.path("query").asText(), fixture[0]);
            assertEquals(fixture[2], inspection.path("body").asText(), fixture[0]);
            assertEquals(fixture[2], response.getBody() == null ? "" : response.getBody(), fixture[0]);
        }
        assertEquals(cases.size(), POSTS.get());
    }

    @Test void unsupportedMultipartBodyIsRejectedBeforeBackendExecution() {
        var response = client().post().uri("/backend/multipart").header("Content-Type", "multipart/form-data; boundary=test")
            .bodyValue("--test--").exchangeToMono(result -> result.toEntity(String.class)).block(Duration.ofSeconds(5));
        assertEquals(HttpStatus.UNSUPPORTED_MEDIA_TYPE, response.getStatusCode());
        assertEquals("INSPECTION_REJECTED", response.getHeaders().getFirst("X-WAF-Inspection-Status"));
        assertEquals(0, POSTS.get());
    }

    @Test void oversizedBodyNeverReachesBackend() {
        var response = client().post().uri("/backend/slow").bodyValue("x".repeat(33))
            .exchangeToMono(result -> result.toEntity(String.class)).block(Duration.ofSeconds(5));
        assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, response.getStatusCode());
        assertEquals(0, POSTS.get());
        assertEquals("INSPECTION_REJECTED", response.getHeaders().getFirst("X-WAF-Inspection-Status"));
    }

    @Test void detection503IsExplicitAndFailOpenForwardsOnce() {
        var response = client().post().uri("/backend/unavailable").bodyValue("x=1")
            .retrieve().toEntity(String.class).block(Duration.ofSeconds(5));
        assertEquals("x=1", response.getBody());
        assertEquals("DETECTION_UNAVAILABLE", response.getHeaders().getFirst("X-WAF-Inspection-Status"));
        assertEquals(1, POSTS.get());
    }

    private WebClient client() { return WebClient.create("http://127.0.0.1:" + port); }
}
