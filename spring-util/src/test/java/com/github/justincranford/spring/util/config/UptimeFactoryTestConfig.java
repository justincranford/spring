package com.github.justincranford.spring.util.config;

import java.time.Instant;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;

import com.github.justincranford.spring.util.model.Uptime;

@TestConfiguration
//@Profile("!default")
public class UptimeFactoryTestConfig {
	@Bean
	public Uptime.Factory uptimeFactory() {
		return new Uptime.Factory(Instant.now());
	}
}
