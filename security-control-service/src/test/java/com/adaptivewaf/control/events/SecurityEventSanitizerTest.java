package com.adaptivewaf.control.events;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class SecurityEventSanitizerTest {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SecurityEventSanitizer sanitizer = new SecurityEventSanitizer(objectMapper);

    @Test
    void redactsCredentialsAndHashesSourceAddresses() throws Exception {
        String sanitized = sanitizer.json(objectMapper.readTree("{\"authorization\":\"Bearer secret\",\"password\":\"p@ss\",\"safe\":\"value\"}"));
        assertFalse(sanitized.contains("Bearer secret"));
        assertFalse(sanitized.contains("p@ss"));
        assertNotEquals("127.0.0.1", sanitizer.hash("127.0.0.1"));
    }
}
