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
        if (!risk.isNumber()) {
            throw new IllegalStateException("detection service response did not contain overall risk");
        }
        return new DetectionVerdict(risk.doubleValue(), detection.path("predicted_attack").asText("UNKNOWN"));
    }
}
