package com.adaptivewaf.control.events;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Service;

/**
 * A browser cannot attach basic-authentication headers to a WebSocket handshake, so an authenticated operator
 * exchanges their session for a short-lived single-purpose ticket that the handshake presents instead.
 */
@Service
public class StreamTicketService {
    private static final Duration TICKET_LIFETIME = Duration.ofMinutes(10);
    private final Map<String, Ticket> tickets = new ConcurrentHashMap<>();

    public Ticket issue(String administrator) {
        purgeExpired();
        Ticket ticket = new Ticket(UUID.randomUUID().toString(), administrator, Instant.now().plus(TICKET_LIFETIME));
        tickets.put(ticket.value(), ticket);
        return ticket;
    }

    public boolean isValid(String value) {
        if (value == null || value.isBlank()) { return false; }
        Ticket ticket = tickets.get(value);
        if (ticket == null) { return false; }
        if (ticket.expiresAt().isBefore(Instant.now())) { tickets.remove(value); return false; }
        return true;
    }

    private void purgeExpired() {
        Instant now = Instant.now();
        tickets.values().removeIf(ticket -> ticket.expiresAt().isBefore(now));
    }

    public record Ticket(String value, String administrator, Instant expiresAt) { }
}
