package com.adaptivewaf.control.events;

import java.util.List;
import java.util.Map;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/security/events")
public class SecurityEventController {
    private final SecurityEventRepository repository;

    public SecurityEventController(SecurityEventRepository repository) { this.repository = repository; }

    @GetMapping
    public Map<String, List<PersistedSecurityEvent>> recent(@RequestParam(defaultValue = "50") int limit) {
        int boundedLimit = Math.max(1, Math.min(limit, 200));
        return Map.of("events", repository.findAll(PageRequest.of(0, boundedLimit)).getContent());
    }
}
