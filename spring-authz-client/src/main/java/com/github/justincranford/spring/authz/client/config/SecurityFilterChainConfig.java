package com.github.justincranford.spring.authz.client.config;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityFilterChainConfig {
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(
        final HttpSecurity http,
        final ApplicationEventPublisher applicationEventPublisher
    ) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
            	.anyRequest().authenticated()
            )
            .oauth2Login(Customizer.withDefaults());
        return http.build();
    }
}