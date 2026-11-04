package com.adaptivewaf.control.events;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(properties = {"spring.rabbitmq.host=127.0.0.1", "spring.data.redis.host=127.0.0.1",
    "spring.datasource.username=waf_fixture", "spring.datasource.password=local-fixture-only",
    "adaptive-waf.control.internal-token=fixture-service-token"})
@EnabledIfEnvironmentVariable(named = "WAF_TEST_POSTGRES_PORT", matches = "\\d+")
class EventPipelineIntegrationTest {
    @Autowired RabbitTemplate rabbit;
    @Autowired SecurityEventRepository repository;
    @Autowired ObjectMapper mapper;
    @Autowired com.adaptivewaf.control.plane.ControlPlaneService control;

    @DynamicPropertySource static void dependencies(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () -> "jdbc:postgresql://127.0.0.1:" + System.getenv("WAF_TEST_POSTGRES_PORT") + "/waf_fixture");
        registry.add("spring.rabbitmq.port", () -> System.getenv("WAF_TEST_RABBIT_PORT"));
        registry.add("spring.data.redis.port", () -> System.getenv("WAF_TEST_REDIS_PORT"));
    }

    @Test void duplicateBrokerDeliveryProducesOnePostgresRow() throws Exception {
        String id = UUID.randomUUID().toString();
        String payload = mapper.writeValueAsString(Map.of("eventId", id, "occurredAt", Instant.now().toString(),
            "category", "security.request", "requestId", UUID.randomUUID().toString(), "action", "ALLOW",
            "predictedAttack", "BENIGN", "statusCode", 200, "inspectionStatus", "FULLY_INSPECTED"));
        rabbit.convertAndSend("adaptive.waf.events", "security.request", payload);
        rabbit.convertAndSend("adaptive.waf.events", "security.request", payload);
        await(() -> repository.existsByEventId(id));
        Thread.sleep(200);
        assertEquals(1, repository.findAll().stream().filter(event -> id.equals(event.getEventId())).count());
        var persisted = repository.findAll().stream().filter(event -> id.equals(event.getEventId())).findFirst().orElseThrow();
        assertEquals("FULLY_INSPECTED", persisted.getInspectionStatus());
        assertNotNull(persisted.getProcessedAt());
        assertFalse(repository.findByCategoryNotAndMethodIsNotNullAndPathIsNotNullOrderByOccurredAtDesc(
            "security.escalation", org.springframework.data.domain.PageRequest.of(0,500)).stream().anyMatch(event -> id.equals(event.getEventId())),
            "Synthetic journal metadata without an HTTP method/path must not inflate request totals");
    }

    @Test void malformedEventHasBoundedRetriesAndReachesRecoveryQueue() {
        rabbit.convertAndSend("adaptive.waf.events", "security.invalid", "{}");
        var recovered = rabbit.receive("security.events.dead", 10000);
        assertNotNull(recovered);
        assertEquals("{}", new String(recovered.getBody(), java.nio.charset.StandardCharsets.UTF_8));
    }

    @Test void feedbackRejectsPoisonedVerdictsClassesAndUnknownEvents() {
        assertThrows(IllegalArgumentException.class, () -> control.submitFeedback(
            new com.adaptivewaf.control.plane.ControlPlaneService.FeedbackCreate("absent", "INVENTED", "fixture", null), "fixture"));
        assertThrows(IllegalArgumentException.class, () -> control.submitFeedback(
            new com.adaptivewaf.control.plane.ControlPlaneService.FeedbackCreate("absent", "WRONG_ATTACK_TYPE", "fixture", "INVENTED"), "fixture"));
        assertThrows(IllegalArgumentException.class, () -> control.submitFeedback(
            new com.adaptivewaf.control.plane.ControlPlaneService.FeedbackCreate("absent", "BENIGN", "fixture", null), "fixture"));
    }

    @Test void concurrentPolicyUpdatesAllocateDistinctVersions() throws Exception {
        int before = control.activePolicy().version();
        try (var pool = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            var first = pool.submit(() -> control.updatePolicy(
                new com.adaptivewaf.control.plane.ControlPlaneService.PolicyUpdate(.80, 20), "fixture"));
            var second = pool.submit(() -> control.updatePolicy(
                new com.adaptivewaf.control.plane.ControlPlaneService.PolicyUpdate(.82, 30), "fixture"));
            assertNotEquals(first.get().version(), second.get().version());
        }
        assertEquals(before + 2, control.activePolicy().version());
    }

    private void await(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (System.nanoTime() < deadline) {
            if (condition.getAsBoolean()) { return; }
            Thread.sleep(20);
        }
        fail("event did not reach PostgreSQL before the fixture deadline");
    }
}
