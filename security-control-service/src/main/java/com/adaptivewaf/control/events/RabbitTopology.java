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
}
