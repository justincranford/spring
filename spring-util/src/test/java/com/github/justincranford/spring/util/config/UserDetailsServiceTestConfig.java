package com.github.justincranford.spring.util.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@TestConfiguration
//@Profile("!default")
public class UserDetailsServiceTestConfig {
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