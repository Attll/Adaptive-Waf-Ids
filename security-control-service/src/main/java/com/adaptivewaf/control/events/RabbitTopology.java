package com.adaptivewaf.control.events;

import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitTopology {
    @Bean TopicExchange securityEventsExchange() { return new TopicExchange("adaptive.waf.events", true, false); }
    @Bean Queue securityEventsQueue() { return new Queue("security.events.persist", true); }
    @Bean Binding securityEventsBinding(Queue securityEventsQueue, TopicExchange securityEventsExchange) {
        return BindingBuilder.bind(securityEventsQueue).to(securityEventsExchange).with("security.#");
    }

    // Separate recovery topology avoids changing immutable arguments of the existing journal queue.
    @Bean TopicExchange securityDeadExchange() { return new TopicExchange("adaptive.waf.dead", true, false); }
    @Bean Queue securityDeadQueue() {
        return org.springframework.amqp.core.QueueBuilder.durable("security.events.dead")
            .maxLength(10000).overflow(org.springframework.amqp.core.QueueBuilder.Overflow.rejectPublish).build();
    }
    @Bean Binding securityDeadBinding() {
        return BindingBuilder.bind(securityDeadQueue()).to(securityDeadExchange()).with("security.events.failed");
    }
    @Bean org.springframework.amqp.rabbit.retry.MessageRecoverer securityEventRecoverer(org.springframework.amqp.rabbit.core.RabbitTemplate template) {
        return new org.springframework.amqp.rabbit.retry.RepublishMessageRecoverer(template, "adaptive.waf.dead", "security.events.failed");
    }
}
