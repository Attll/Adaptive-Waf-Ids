package com.adaptivewaf.control.events;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Removes credential material from a security event while keeping the request representation intact. Request
 * identity, payloads, and model evidence are retained verbatim so an operator can see exactly what was submitted
 * and how the pipeline judged it.
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
            return value.length() <= MAX_DETAILS_LENGTH ? value : value.substring(0, MAX_DETAILS_LENGTH) + "...[truncated]";
        } catch (Exception error) { throw new IllegalArgumentException("event cannot be serialized", error); }
    }

    private void redact(JsonNode node) {
        if (node.isObject()) {
            ObjectNode object = (ObjectNode) node;
            Iterator<Map.Entry<String, JsonNode>> fields = object.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                if (credential(field.getKey())) { object.put(field.getKey(), "***REDACTED***"); }
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
}
