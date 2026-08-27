package com.adaptivewaf.control.plane;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/control")
public class ControlPlaneController {
    private final ControlPlaneService service;
    public ControlPlaneController(ControlPlaneService service) { this.service = service; }
    @GetMapping("/policy") public ControlPlaneService.PolicySnapshot policy() { return service.activePolicy(); }
    @PutMapping("/policy") public ControlPlaneService.PolicySnapshot updatePolicy(@RequestBody ControlPlaneService.PolicyUpdate request, Authentication auth) { return service.updatePolicy(request, auth.getName()); }
    @GetMapping("/applications") public Map<String, List<ControlPlaneService.ApplicationView>> applications() { return Map.of("applications", service.applications()); }
    @PostMapping("/applications") public ControlPlaneService.ApplicationView createApplication(@RequestBody ControlPlaneService.ApplicationCreate request, Authentication auth) { return service.createApplication(request, auth.getName()); }
    @PatchMapping("/applications/{applicationId}") public ControlPlaneService.ApplicationView setApplicationEnabled(@PathVariable UUID applicationId, @RequestBody ControlPlaneService.ApplicationToggle request, Authentication auth) { return service.setApplicationEnabled(applicationId, request.enabled(), auth.getName()); }
    @GetMapping("/blocks") public Map<String, List<ControlPlaneService.BlockView>> blocks() { return Map.of("blocks", service.blocks()); }
    @PostMapping("/blocks") public ControlPlaneService.BlockView block(@RequestBody ControlPlaneService.BlockRequest request, Authentication auth) { return service.block(request, auth.getName()); }
    @DeleteMapping("/blocks/{sourceIp}") public void unblock(@PathVariable String sourceIp, Authentication auth) { service.unblock(sourceIp, auth.getName()); }
    @GetMapping("/models") public Map<String, List<ControlPlaneService.ModelView>> models() { return Map.of("models", service.models()); }
    @PostMapping("/models") public ControlPlaneService.ModelView registerModel(@RequestBody ControlPlaneService.ModelCreate request, Authentication auth) { return service.registerModel(request, auth.getName()); }
    @PostMapping("/models/{modelVersionId}/promote") public void promote(@PathVariable UUID modelVersionId, Authentication auth) { service.promote(modelVersionId, auth.getName()); }
    @PostMapping("/models/{modelVersionId}/assign") public void assign(@PathVariable UUID modelVersionId, Authentication auth) { service.assignModel(modelVersionId, auth.getName()); }
    @PostMapping("/feedback") public ControlPlaneService.FeedbackView feedback(@RequestBody ControlPlaneService.FeedbackCreate request, Authentication auth) { return service.submitFeedback(request, auth.getName()); }
    @GetMapping("/audit") public Map<String, List<ControlPlaneService.AuditView>> audit(@RequestParam(defaultValue = "50") int limit) { return Map.of("audit", service.auditEntries(limit)); }
}
