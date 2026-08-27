package com.adaptivewaf.backend;

import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {
    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ok");
    }

    @GetMapping("/public/hello")
    public Map<String, String> hello(@RequestHeader(value = "X-Request-ID", required = false) String requestId) {
        return Map.of("status", "backend_reached", "request_id", requestId == null ? "missing" : requestId);
    }

    @PostMapping("/api/echo")
    public Map<String, String> echo(@RequestBody(required = false) String body, @RequestHeader(value = "X-Request-ID", required = false) String requestId) {
        return Map.of("status", "backend_reached", "request_id", requestId == null ? "missing" : requestId, "body", body == null ? "" : body);
    }
}
