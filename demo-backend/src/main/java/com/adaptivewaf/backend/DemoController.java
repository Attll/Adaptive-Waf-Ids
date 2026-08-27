package com.adaptivewaf.backend;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
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

    @GetMapping("/search")
    public Map<String, String> search(@RequestHeader(value = "X-Request-ID", required = false) String requestId) {
        return Map.of("status", "backend_reached", "request_id", requestId == null ? "missing" : requestId);
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestHeader(value = "X-Request-ID", required = false) String requestId) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
            "status", "invalid_credentials",
            "request_id", requestId == null ? "missing" : requestId
        ));
    }

    @PostMapping("/api/echo")
    public Map<String, String> echo(@RequestBody(required = false) String body, @RequestHeader(value = "X-Request-ID", required = false) String requestId) {
        return Map.of("status", "backend_reached", "request_id", requestId == null ? "missing" : requestId, "body", body == null ? "" : body);
    }

    /**
     * Answers any other path so replayed dataset traffic reaches a real upstream instead of a 404. Without this the
     * console's generated requests would be indistinguishable from routing mistakes in the journal.
     */
    @RequestMapping("/**")
    public Map<String, String> catchAll(HttpServletRequest request,
                                        @RequestHeader(value = "X-Request-ID", required = false) String requestId) {
        return Map.of(
            "status", "backend_reached",
            "request_id", requestId == null ? "missing" : requestId,
            "method", request.getMethod(),
            "path", request.getRequestURI(),
            "query", request.getQueryString() == null ? "" : request.getQueryString());
    }
}
