package com.adaptivewaf.control;

import com.adaptivewaf.control.config.ControlProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(ControlProperties.class)
public class SecurityControlApplication {
    public static void main(String[] args) {
        SpringApplication.run(SecurityControlApplication.class, args);
    }
}
