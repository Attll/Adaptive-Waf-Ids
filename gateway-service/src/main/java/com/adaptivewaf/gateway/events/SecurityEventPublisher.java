package com.adaptivewaf.gateway.events;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PreDestroy;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.atomic.LongAdder;
import java.util.Map;
import org.springframework.amqp.rabbit.connection.CorrelationData;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;
import io.micrometer.core.instrument.FunctionCounter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.stereotype.Component;

@Component
public class SecurityEventPublisher implements MeterBinder {
    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityEventPublisher.class);
    private final RabbitTemplate rabbitTemplate;
    private final ObjectMapper objectMapper;
    private final SecurityEventProperties properties;
    private final ThreadPoolTaskExecutor executor;
    private final LongAdder queued = new LongAdder();
    private final LongAdder sent = new LongAdder();
    private final LongAdder failed = new LongAdder();
    private final LongAdder rejected = new LongAdder();

    public SecurityEventPublisher(RabbitTemplate rabbitTemplate, ObjectMapper objectMapper, SecurityEventProperties properties) {
        this.rabbitTemplate = rabbitTemplate;
        this.objectMapper = objectMapper;
        this.properties = properties;
        this.executor = new ThreadPoolTaskExecutor();
        this.executor.setCorePoolSize(1);
        this.executor.setMaxPoolSize(2);
        this.executor.setQueueCapacity(properties.getQueueCapacity());
        this.executor.setThreadNamePrefix("security-event-");
        this.executor.setRejectedExecutionHandler(new ThreadPoolExecutor.AbortPolicy());
        this.executor.initialize();
    }

    public void publish(SecurityEvent event) {
        if (!properties.isEnabled()) { return; }
        try {
            executor.execute(() -> send(event));
            queued.increment();
        } catch (TaskRejectedException error) {
            rejected.increment();
            LOGGER.warn("Security event queue is full; dropping category={}", event.category());
        }
    }

    private void send(SecurityEvent event) {
        try {
            CorrelationData correlation = new CorrelationData(event.eventId().toString());
            rabbitTemplate.convertAndSend(properties.getExchange(), event.category(), objectMapper.writeValueAsString(event), correlation);
            correlation.getFuture().orTimeout(5, java.util.concurrent.TimeUnit.SECONDS).whenComplete((confirmation, error) -> {
                if (error == null && confirmation.isAck() && correlation.getReturned() == null) { sent.increment(); }
                else {
                    failed.increment();
                    LOGGER.warn("Security event {} was not confirmed as routed", event.eventId());
                }
            });
        } catch (JsonProcessingException error) {
            failed.increment();
            LOGGER.error("Could not serialize security event {}", event.eventId(), error);
        } catch (RuntimeException error) {
            failed.increment();
            LOGGER.warn("Security event broker unavailable; event {} was not persisted", event.eventId());
        }
    }

    public Map<String, Long> statistics() {
        return Map.of("queued", queued.sum(), "confirmed", sent.sum(), "failed", failed.sum(), "rejected", rejected.sum());
    }

    @Override public void bindTo(MeterRegistry registry) {
        FunctionCounter.builder("waf.events.queued", queued, LongAdder::doubleValue).register(registry);
        FunctionCounter.builder("waf.events.confirmed", sent, LongAdder::doubleValue).register(registry);
        FunctionCounter.builder("waf.events.failed", failed, LongAdder::doubleValue).register(registry);
        FunctionCounter.builder("waf.events.rejected", rejected, LongAdder::doubleValue).register(registry);
    }

    @PreDestroy
    void stop() { executor.shutdown(); }
}
