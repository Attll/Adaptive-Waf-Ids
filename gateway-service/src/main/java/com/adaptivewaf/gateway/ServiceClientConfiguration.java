package com.adaptivewaf.gateway;

import java.time.Duration;
import org.springframework.boot.web.reactive.function.client.WebClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import reactor.netty.http.client.HttpClient;

/** Refresh internal service addresses after container replacement without retrying requests. */
@Configuration
public class ServiceClientConfiguration {
    @Bean WebClientCustomizer serviceAddressRefresh() {
        return builder->builder.clientConnector(new ReactorClientHttpConnector(HttpClient.create()
            .resolver(spec->spec.cacheMinTimeToLive(Duration.ZERO).cacheMaxTimeToLive(Duration.ofSeconds(5))
                .cacheNegativeTimeToLive(Duration.ofSeconds(1)))));
    }
}
