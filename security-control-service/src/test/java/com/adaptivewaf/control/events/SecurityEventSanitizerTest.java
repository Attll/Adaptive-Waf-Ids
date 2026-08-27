package com.adaptivewaf.control.events;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class SecurityEventSanitizerTest {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SecurityEventSanitizer sanitizer = new SecurityEventSanitizer(objectMapper);

    @Test
    void redactsCredentialsWhileRetainingTheRequestRepresentation() throws Exception {
        String sanitized = sanitizer.json(objectMapper.readTree(
            "{\"authorization\":\"Bearer secret\",\"password\":\"p@ss\",\"sourceIp\":\"203.0.113.10\",\"path\":\"/search\",\"query\":\"q=1' OR '1'='1\"}"));

        assertFalse(sanitized.contains("Bearer secret"));
        assertFalse(sanitized.contains("p@ss"));
        assertTrue(sanitized.contains("203.0.113.10"));
        assertTrue(sanitized.contains("/search"));
        assertTrue(sanitized.contains("OR "));
    }
}
