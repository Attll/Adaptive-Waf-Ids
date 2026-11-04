package com.adaptivewaf.gateway.detection;

import io.netty.util.NetUtil;
import java.net.InetAddress;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

/** Only explicitly trusted peers may supply X-Forwarded-For; never performs DNS lookups. */
@Component
public class SourceIdentity {
    private final DetectionProperties properties;

    public SourceIdentity(DetectionProperties properties) { this.properties = properties; }

    public String sourceIp(ServerHttpRequest request) {
        if (request.getRemoteAddress() == null || request.getRemoteAddress().getAddress() == null) { return null; }
        String peer = NetUtil.toAddressString(request.getRemoteAddress().getAddress());
        if (!properties.getTrustedProxyIps().contains(peer)) { return peer; }
        String forwarded = request.getHeaders().getFirst("X-Forwarded-For");
        if (forwarded == null || forwarded.length() > 2048) { return peer; }
        String[] hops = forwarded.split(",", -1);
        // Walk from the actual peer towards the client; a client-supplied leftmost value is not trusted.
        String source = peer;
        for (int index = hops.length - 1; index >= 0 && properties.getTrustedProxyIps().contains(source); index--) {
            InetAddress parsed = NetUtil.createInetAddressFromIpAddressString(hops[index].trim());
            if (parsed == null) { return peer; }
            source = NetUtil.toAddressString(parsed);
        }
        return source;
    }

    public String sourceKey(ServerHttpRequest request) {
        String ip = sourceIp(request);
        return ip == null ? "unknown" : ip.replace(':', '_');
    }
}
