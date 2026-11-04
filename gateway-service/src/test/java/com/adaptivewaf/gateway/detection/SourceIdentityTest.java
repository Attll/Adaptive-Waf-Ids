package com.adaptivewaf.gateway.detection;

import java.net.InetSocketAddress;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import static org.junit.jupiter.api.Assertions.*;

class SourceIdentityTest {
    @Test void untrustedPeerCannotSpoofSource() {
        var identity = new SourceIdentity(new DetectionProperties());
        var request = MockServerHttpRequest.get("/").remoteAddress(new InetSocketAddress("127.0.0.1", 1234))
            .header("X-Forwarded-For", "192.0.2.1").build();
        assertEquals("127.0.0.1", identity.sourceIp(request));
    }

    @Test void trustedProxyChainStopsAtFirstUntrustedHop() {
        var properties = new DetectionProperties();
        properties.setTrustedProxyIps(Set.of("127.0.0.1"));
        var identity = new SourceIdentity(properties);
        var request = MockServerHttpRequest.get("/").remoteAddress(new InetSocketAddress("127.0.0.1", 1234))
            .header("X-Forwarded-For", "192.0.2.99, 2001:db8::1").build();
        assertEquals("2001:db8::1", identity.sourceIp(request));
        assertEquals("2001_db8__1", identity.sourceKey(request));
    }

    @Test void malformedForwardingFallsBackToPeerWithoutDns() {
        var properties = new DetectionProperties();
        properties.setTrustedProxyIps(Set.of("127.0.0.1"));
        var request = MockServerHttpRequest.get("/").remoteAddress(new InetSocketAddress("127.0.0.1", 1234))
            .header("X-Forwarded-For", "attacker.invalid").build();
        assertEquals("127.0.0.1", new SourceIdentity(properties).sourceIp(request));
    }
}
