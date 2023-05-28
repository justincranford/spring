package com.github.justincranford.spring.util.config;

import java.util.Collections;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@TestConfiguration
//@Profile("!default")
@SuppressWarnings("deprecation")
public class PasswordEncoderITConfig {
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new DelegatingPasswordEncoder("sha256", Collections.singletonMap("sha256", new MessageDigestPasswordEncoder("SHA-256")));
	}
}