package com.adaptivewaf.gateway;

import com.adaptivewaf.gateway.detection.DetectionProperties;
import com.adaptivewaf.gateway.policy.GatewayPolicyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({DetectionProperties.class, GatewayPolicyProperties.class})
public class GatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}
