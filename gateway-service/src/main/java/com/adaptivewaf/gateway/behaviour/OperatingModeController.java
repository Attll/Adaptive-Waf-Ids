package com.adaptivewaf.gateway.behaviour;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/actuator/waf")
public class OperatingModeController {
    private final RedisLoadModeService loadModeService;

    public OperatingModeController(RedisLoadModeService loadModeService) {
        this.loadModeService = loadModeService;
    }

    @GetMapping("/mode")
    public Mono<Map<String, String>> mode() {
        return loadModeService.currentMode()
            .map(mode -> Map.of("mode", mode.name()))
            .onErrorReturn(Map.of("mode", "DEGRADED"));
    }
}
