package com.adaptivewaf.gateway.events;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitAdmin;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import static org.junit.jupiter.api.Assertions.*;

@EnabledIfEnvironmentVariable(named = "WAF_TEST_RABBIT_PORT", matches = "\\d+")
class PublisherConfirmationIntegrationTest {
    @Test void confirmedRoutingAndUnroutablePublishingAreDistinguished() throws Exception {
        var connection = new CachingConnectionFactory("127.0.0.1", Integer.parseInt(System.getenv("WAF_TEST_RABBIT_PORT")));
        connection.setPublisherConfirmType(CachingConnectionFactory.ConfirmType.CORRELATED);
        connection.setPublisherReturns(true);
        var rabbit = new RabbitTemplate(connection);
        rabbit.setMandatory(true);
        var admin = new RabbitAdmin(connection);
        String exchange = "fixture.confirm." + UUID.randomUUID();
        admin.declareExchange(new TopicExchange(exchange, false, true));
        String queue = admin.declareQueue().getName();
        admin.declareBinding(new Binding(queue, Binding.DestinationType.QUEUE, exchange, "security.request", null));
        var properties = new SecurityEventProperties();
        properties.setExchange(exchange);
        var publisher = new SecurityEventPublisher(rabbit, new ObjectMapper().findAndRegisterModules(), properties);
        try {
            publisher.publish(SecurityEvent.builder("security.request").build());
            publisher.publish(SecurityEvent.builder("unroutable").build());
            long deadline = System.nanoTime() + Duration.ofSeconds(8).toNanos();
            while (publisher.statistics().get("confirmed") + publisher.statistics().get("failed") < 2 && System.nanoTime() < deadline) {
                Thread.sleep(20);
            }
            assertEquals(1L, publisher.statistics().get("confirmed"));
            assertEquals(1L, publisher.statistics().get("failed"));
            assertNotNull(rabbit.receive(queue, 1000));
        } finally {
            publisher.stop();
            connection.destroy();
        }
    }
}
