package com.adaptivewaf.control.events;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

/**
 * Pushes every persisted security event to connected consoles so the live views update without polling.
 */
@Component
public class SecurityEventBroadcaster extends TextWebSocketHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityEventBroadcaster.class);
    private final Set<WebSocketSession> sessions = new CopyOnWriteArraySet<>();
    private final ObjectMapper objectMapper;

    public SecurityEventBroadcaster(ObjectMapper objectMapper) { this.objectMapper = objectMapper; }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        sessions.add(session);
        send(session, Map.of("type", "connected", "subscribers", sessions.size()));
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        sessions.remove(session);
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) {
        if ("ping".equals(message.getPayload())) { send(session, Map.of("type", "pong")); }
    }

    public void broadcast(PersistedSecurityEvent event) {
        if (sessions.isEmpty()) { return; }
        Map<String, Object> frame = Map.of("type", "event", "event", event);
        sessions.forEach(session -> send(session, frame));
    }

    public int subscribers() { return sessions.size(); }

    private void send(WebSocketSession session, Object payload) {
        if (!session.isOpen()) { sessions.remove(session); return; }
        try {
            synchronized (session) {
                session.sendMessage(new TextMessage(objectMapper.writeValueAsString(payload)));
            }
        } catch (IOException | IllegalStateException error) {
            LOGGER.debug("Dropping console stream session {}: {}", session.getId(), error.getClass().getSimpleName());
            sessions.remove(session);
        }
    }
}
