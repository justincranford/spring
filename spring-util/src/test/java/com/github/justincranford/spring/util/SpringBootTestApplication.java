package com.github.justincranford.spring.util;

import java.time.Instant;
import java.util.Map;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import com.github.justincranford.spring.util.model.Uptime;

@SpringBootApplication
public class SpringBootTestApplication {
	@Bean
	public Uptime.Factory uptimeFactory() {
		return new Uptime.Factory(Instant.now());
	}

	@SuppressWarnings("deprecation")
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
	@Bean
	public UserDetailsService users(final PasswordEncoder passwordEncoder) {
		return new InMemoryUserDetailsManager(
			User.builder()
				.passwordEncoder(passwordEncoder::encode)
				.username("user")
				.password("password")
				.roles("USER")
				.build(),
			User.builder()
				.passwordEncoder(passwordEncoder::encode)
				.username("admin")
				.password("password")
				.roles("USER", "ADMIN")
				.build(),
			User.builder()
				.passwordEncoder(passwordEncoder::encode)
				.username("uptime")
				.password("uptime")
				.roles("USER")
				.build()		
		);
	}
}
