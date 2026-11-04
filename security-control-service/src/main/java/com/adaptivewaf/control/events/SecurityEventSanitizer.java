package com.adaptivewaf.control.events;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Keeps operational identity and model evidence while removing credentials and raw query/body/header/cookie
 * content from both structured journal columns and nested details. Oversized details remain valid JSON.
 */
@Component
public class SecurityEventSanitizer {
    private static final int MAX_DETAILS_LENGTH = 32_768;
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
            return value.length() <= MAX_DETAILS_LENGTH ? value : "{\"truncated\":true,\"reason\":\"event_details_limit\"}";
        } catch (Exception error) { throw new IllegalArgumentException("event cannot be serialized", error); }
    }

    private void redact(JsonNode node) {
        if (node.isObject()) {
            ObjectNode object = (ObjectNode) node;
            Iterator<Map.Entry<String, JsonNode>> fields = object.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                if (credential(field.getKey()) || sensitiveContent(field.getKey())) { object.put(field.getKey(), "***REDACTED***"); }
                else { redact(field.getValue()); }
            }
        } else if (node.isArray()) {
            for (JsonNode entry : node) { redact(entry); }
        }
    }

    private boolean credential(String key) {
        String normalized = key.toLowerCase(Locale.ROOT);
        return normalized.contains("authorization") || normalized.contains("password") || normalized.contains("token")
            || normalized.contains("secret") || normalized.contains("api_key") || normalized.contains("apikey");
    }

    private boolean sensitiveContent(String key) {
        return java.util.Set.of("query", "body", "cookies", "cookie", "headers").contains(key.toLowerCase(Locale.ROOT));
    }
}
