package com.adaptivewaf.control.events;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class SecurityEventSanitizer {
    private static final int MAX_DETAILS_LENGTH = 4096;
    private final ObjectMapper objectMapper;

    public SecurityEventSanitizer(ObjectMapper objectMapper) { this.objectMapper = objectMapper; }

    public JsonNode sanitize(JsonNode input) {
        JsonNode copy = input.deepCopy();
        redact(copy);
        return copy;
    }

    public String json(JsonNode input) {
        try {
            String value = objectMapper.writeValueAsString(sanitize(input));
            return value.length() <= MAX_DETAILS_LENGTH ? value : value.substring(0, MAX_DETAILS_LENGTH) + "...[truncated]";
        } catch (Exception error) { throw new IllegalArgumentException("event cannot be serialized", error); }
    }

    public String hash(String value) {
        if (value == null || value.isBlank()) { return null; }
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder encoded = new StringBuilder();
            for (byte entry : hash) { encoded.append(String.format("%02x", entry)); }
            return encoded.toString();
        } catch (NoSuchAlgorithmException error) { throw new IllegalStateException("SHA-256 is unavailable", error); }
    }

    private void redact(JsonNode node) {
        if (node.isObject()) {
            ObjectNode object = (ObjectNode) node;
            Iterator<Map.Entry<String, JsonNode>> fields = object.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                if (sensitive(field.getKey())) { object.put(field.getKey(), "***REDACTED***"); }
                else { redact(field.getValue()); }
            }
        } else if (node.isArray()) {
            for (JsonNode entry : node) { redact(entry); }
        }
    }

    private boolean sensitive(String key) {
        String normalized = key.toLowerCase(Locale.ROOT);
        return normalized.contains("authorization") || normalized.contains("password") || normalized.contains("token")
            || normalized.contains("secret") || normalized.contains("api_key") || normalized.contains("cookie") || normalized.equals("body");
    }
}
