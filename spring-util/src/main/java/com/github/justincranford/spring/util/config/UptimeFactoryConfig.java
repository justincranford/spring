package com.github.justincranford.spring.util.config;

import java.time.Instant;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.github.justincranford.spring.util.model.Uptime;

@Configuration
public class UptimeFactoryConfig {
	@Bean
	public Uptime.Factory uptimeFactory() {
		return new Uptime.Factory(Instant.now());
	}
}
