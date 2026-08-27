package com.adaptivewaf.gateway;

import com.adaptivewaf.gateway.detection.DetectionProperties;
import com.adaptivewaf.gateway.behaviour.BehaviourProperties;
import com.adaptivewaf.gateway.policy.GatewayPolicyProperties;
import com.adaptivewaf.gateway.events.SecurityEventProperties;
import com.adaptivewaf.gateway.network.NetworkContextProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties({DetectionProperties.class, GatewayPolicyProperties.class, BehaviourProperties.class, SecurityEventProperties.class, NetworkContextProperties.class})
public class GatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}
