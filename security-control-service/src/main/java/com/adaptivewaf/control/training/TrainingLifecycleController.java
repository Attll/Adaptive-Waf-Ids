package com.adaptivewaf.control.training;

import java.util.List;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/control")
public class TrainingLifecycleController {
    private final TrainingLifecycleService service;
    public TrainingLifecycleController(TrainingLifecycleService service) { this.service = service; }
    @GetMapping("/training-runs") public Map<String, List<TrainingLifecycleService.TrainingRunView>> runs() { return Map.of("runs", service.runs()); }
    @GetMapping("/feedback") public Map<String, List<TrainingLifecycleService.FeedbackView>> feedback() { return Map.of("feedback", service.feedback()); }
    @PostMapping("/models/{modelVersionId}/approve") public void approve(@PathVariable String modelVersionId, Authentication auth) { service.approve(modelVersionId, auth.getName()); }
    @PostMapping("/models/{modelVersionId}/retire") public void retire(@PathVariable String modelVersionId, Authentication auth) { service.retire(modelVersionId, auth.getName()); }
}
