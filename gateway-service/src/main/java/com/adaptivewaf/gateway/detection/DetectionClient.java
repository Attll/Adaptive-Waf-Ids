package com.adaptivewaf.gateway.detection;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Component
public class DetectionClient {
    private final WebClient webClient;
    private final DetectionProperties properties;

    public DetectionClient(WebClient.Builder builder, DetectionProperties properties) {
        this.webClient = builder.baseUrl(properties.getBaseUrl()).build();
        this.properties = properties;
    }

    public Mono<DetectionVerdict> detect(Map<String, Object> request) {
        return webClient.post()
            .uri("/v1/detect")
            .header("X-Request-ID", String.valueOf(request.get("request_id")))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(request)
            .retrieve()
            .bodyToMono(JsonNode.class)
            .timeout(properties.getTimeout())
            .map(this::toVerdict);
    }

    private DetectionVerdict toVerdict(JsonNode response) {
        JsonNode detection = response.path("detection");
        JsonNode risk = detection.path("risks").path("overall");
        String inspectionStatus = detection.path("inspection_status").asText("");
        if (!inspectionStatus.isBlank() && !java.util.Set.of("FULLY_INSPECTED", "PARTIALLY_INSPECTED", "RULES_ONLY", "DETECTION_UNAVAILABLE", "INSPECTION_REJECTED").contains(inspectionStatus)) {
            throw new IllegalStateException("invalid inspection status");
        }
        if (!risk.isNumber() || !Double.isFinite(risk.doubleValue()) || risk.doubleValue() < 0 || risk.doubleValue() > 1
                || !detection.path("predicted_attack").isTextual()
                || !java.util.Set.of("BENIGN", "SQL_INJECTION", "XSS", "COOKIE_INJECTION", "DIRECTORY_TRAVERSAL", "REMOTE_CODE_EXECUTION")
                    .contains(detection.path("predicted_attack").asText())) {
            throw new IllegalStateException("detection service response did not contain overall risk");
        }
        return new DetectionVerdict(
            risk.doubleValue(),
            detection.path("predicted_attack").asText("UNKNOWN"),
            detection,
            response.path("service_inference_ms").asDouble(0.0));
    }
}
