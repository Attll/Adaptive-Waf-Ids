package com.adaptivewaf.gateway.events;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.rabbit.connection.CorrelationData;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class SecurityEventPublisherTest {
    @Test void saturationIsCountedInsteadOfSilentlyDiscarded() throws Exception {
        var rabbit = mock(RabbitTemplate.class);
        var properties = new SecurityEventProperties();
        properties.setQueueCapacity(1);
        var entered = new CountDownLatch(2);
        var release = new CountDownLatch(1);
        doAnswer(invocation -> {
            entered.countDown();
            release.await(3, TimeUnit.SECONDS);
            ((CorrelationData) invocation.getArgument(3)).getFuture().complete(new CorrelationData.Confirm(true, null));
            return null;
        }).when(rabbit).convertAndSend(anyString(), anyString(), any(Object.class), any(CorrelationData.class));
        var publisher = new SecurityEventPublisher(rabbit, new ObjectMapper().findAndRegisterModules(), properties);
        try {
            for (int i = 0; i < 3; i++) { publisher.publish(SecurityEvent.builder("security.request").build()); }
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            publisher.publish(SecurityEvent.builder("security.request").build());
            assertEquals(1L, publisher.statistics().get("rejected"));
        } finally {
            release.countDown();
            publisher.stop();
        }
    }
}
