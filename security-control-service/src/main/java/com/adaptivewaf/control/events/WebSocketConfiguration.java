package com.adaptivewaf.control.events;

import java.util.Map;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import org.springframework.web.socket.server.HandshakeInterceptor;

@Configuration
@EnableWebSocket
public class WebSocketConfiguration implements WebSocketConfigurer {
    private final SecurityEventBroadcaster broadcaster;
    private final StreamTicketService tickets;

    public WebSocketConfiguration(SecurityEventBroadcaster broadcaster, StreamTicketService tickets) {
        this.broadcaster = broadcaster;
        this.tickets = tickets;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(broadcaster, "/v1/stream/events")
            .setAllowedOriginPatterns("*")
            .addInterceptors(new TicketHandshakeInterceptor(tickets));
    }

    private record TicketHandshakeInterceptor(StreamTicketService tickets) implements HandshakeInterceptor {
        @Override
        public boolean beforeHandshake(ServerHttpRequest request, ServerHttpResponse response,
                                       WebSocketHandler handler, Map<String, Object> attributes) {
            if (tickets.isValid(ticketFrom(request))) { return true; }
            response.setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
            return false;
        }

        @Override
        public void afterHandshake(ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler handler, Exception exception) { }

        private String ticketFrom(ServerHttpRequest request) {
            if (request instanceof ServletServerHttpRequest servletRequest) {
                return servletRequest.getServletRequest().getParameter("ticket");
            }
            return null;
        }
    }
}
