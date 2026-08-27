package com.adaptivewaf.gateway.events;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PreDestroy;
import java.util.concurrent.ThreadPoolExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.stereotype.Component;

@Component
public class SecurityEventPublisher {
    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityEventPublisher.class);
    private final RabbitTemplate rabbitTemplate;
    private final ObjectMapper objectMapper;
    private final SecurityEventProperties properties;
    private final ThreadPoolTaskExecutor executor;

    public SecurityEventPublisher(RabbitTemplate rabbitTemplate, ObjectMapper objectMapper, SecurityEventProperties properties) {
        this.rabbitTemplate = rabbitTemplate;
        this.objectMapper = objectMapper;
        this.properties = properties;
        this.executor = new ThreadPoolTaskExecutor();
        this.executor.setCorePoolSize(1);
        this.executor.setMaxPoolSize(2);
        this.executor.setQueueCapacity(properties.getQueueCapacity());
        this.executor.setThreadNamePrefix("security-event-");
        this.executor.setRejectedExecutionHandler(new ThreadPoolExecutor.DiscardPolicy());
        this.executor.initialize();
    }

    public void publish(SecurityEvent event) {
        if (!properties.isEnabled()) { return; }
        try {
            executor.execute(() -> send(event));
        } catch (TaskRejectedException error) {
            LOGGER.warn("Security event queue is full; dropping category={}", event.category());
        }
    }

    private void send(SecurityEvent event) {
        try {
            rabbitTemplate.convertAndSend(properties.getExchange(), event.category(), objectMapper.writeValueAsString(event));
        } catch (JsonProcessingException error) {
            LOGGER.error("Could not serialize security event {}", event.eventId(), error);
        } catch (RuntimeException error) {
            LOGGER.warn("Security event broker unavailable; event {} was not persisted", event.eventId());
        }
    }

    @PreDestroy
    void stop() { executor.shutdown(); }
}
