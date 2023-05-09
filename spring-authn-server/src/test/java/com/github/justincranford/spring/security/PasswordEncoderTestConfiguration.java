package com.github.justincranford.spring.security;

import java.util.Map;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SuppressWarnings("deprecation")
@TestConfiguration
@EnableWebSecurity
public class PasswordEncoderTestConfiguration {

	@Bean
	public PasswordEncoder passwordEncoder() {
		final String defaultEncoderId = "sha256";
		final PasswordEncoder passwordEncoder = new DelegatingPasswordEncoder(defaultEncoderId,
			Map.of(
				"noop", org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance(),
				"sha256", new MessageDigestPasswordEncoder("SHA-256")
			));
		return passwordEncoder;
	}

}