package com.adaptivewaf.control.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

class SecurityEventConsumerTest {
    private static final String EVENT = """
        {"eventId":"ef3d5a26-b6f4-442d-8200-9be399058ad8","occurredAt":"2026-08-27T04:00:00Z","category":"security.attack",
         "requestId":"request-1","sourceIp":"203.0.113.10","method":"POST","path":"/login","query":"q=1",
         "statusCode":403,"action":"BLOCK","predictedAttack":"SQL_INJECTION","risk":0.99,"mitigation":"BLOCKED_AT_GATEWAY",
         "mode":"NORMAL","detectionLatencyMs":12.5,"upstreamLatencyMs":0.0,"gatewayLatencyMs":18.25,
         "authorization":"Bearer secret","password":"hidden",
         "detection":{"triage":{"decision":"SUSPICIOUS","suspicious_probability":0.97},
                      "expert_outputs":[{"predicted_attack":"SQL_INJECTION","confidence":0.93,"risk":0.99}],
                      "deep_model_used":false,
                      "routing_path":["TRIAGE","ROUTER_TOP1","INJECTION_FAST","POLICY_PENDING"]}}
        """;

    @Test
    void persistsEvidencedEventOnlyOnceWhenDeliveryIsDuplicated() {
        ObjectMapper objectMapper = new ObjectMapper();
        SecurityEventRepository repository = Mockito.mock(SecurityEventRepository.class);
        SecurityEventBroadcaster broadcaster = Mockito.mock(SecurityEventBroadcaster.class);
        SecurityEventConsumer consumer = new SecurityEventConsumer(objectMapper, new SecurityEventSanitizer(objectMapper), repository, broadcaster);
        when(repository.existsByEventId("ef3d5a26-b6f4-442d-8200-9be399058ad8")).thenReturn(false, true);

        consumer.consume(EVENT);
        consumer.consume(EVENT);

        ArgumentCaptor<PersistedSecurityEvent> persisted = ArgumentCaptor.forClass(PersistedSecurityEvent.class);
        verify(repository, times(1)).save(persisted.capture());
        verify(broadcaster, times(1)).broadcast(Mockito.any());
        PersistedSecurityEvent event = persisted.getValue();
        assertEquals("203.0.113.10", event.getSourceIp());
        assertEquals("BLOCKED_AT_GATEWAY", event.getMitigation());
        assertEquals("SUSPICIOUS", event.getTriageDecision());
        assertEquals(0.93, event.getConfidence(), 1e-9);
        assertEquals(18.25, event.getGatewayLatencyMs(), 1e-9);
        assertTrue(event.getRoutingPath().startsWith("TRIAGE > ROUTER_TOP1"));
        assertFalse(event.getDetailsJson().contains("Bearer secret"));
        assertFalse(event.getDetailsJson().contains("hidden"));
    }
}
