package com.adaptivewaf.control.training;

import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/v1/training")
public class InternalTrainingController {
    private final TrainingLifecycleService service;
    public InternalTrainingController(TrainingLifecycleService service) { this.service = service; }
    @GetMapping("/feedback") public Map<String, List<TrainingLifecycleService.FeedbackView>> feedback() { return Map.of("feedback", service.feedback()); }
    @PostMapping("/runs") public TrainingLifecycleService.TrainingRunView create(@RequestBody TrainingLifecycleService.TrainingRunCreate request) { return service.createRun(request); }
    @PutMapping("/runs/{runId}") public TrainingLifecycleService.TrainingRunView complete(@PathVariable String runId, @RequestBody TrainingLifecycleService.TrainingRunCompletion request) { return service.completeRun(runId, request); }
    @PostMapping("/candidates") public TrainingLifecycleService.ModelView candidate(@RequestBody TrainingLifecycleService.CandidateCreate request) { return service.registerCandidate(request); }
    @PostMapping("/candidates/{modelVersionId}/evaluate") public TrainingLifecycleService.ModelView evaluate(@PathVariable String modelVersionId, @RequestBody TrainingLifecycleService.Evaluation request) { return service.evaluate(modelVersionId, request); }
}
