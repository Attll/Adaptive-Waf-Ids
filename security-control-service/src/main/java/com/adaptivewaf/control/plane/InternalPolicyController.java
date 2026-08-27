package com.adaptivewaf.control.plane;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/v1")
public class InternalPolicyController {
    private final ControlPlaneService service;
    public InternalPolicyController(ControlPlaneService service) { this.service = service; }
    @GetMapping("/gateway-policy") public ControlPlaneService.PolicySnapshot gatewayPolicy() { return service.activePolicy(); }
}
