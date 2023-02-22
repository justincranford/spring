package com.github.justincranford.spring.configuration.security;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm;

@Configuration
@EnableWebSecurity
public class PasswordEncoderConfiguration {
    @Value(value="${spring.application.name}") protected String springApplicationName;

	@Bean
	public PasswordEncoder passwordEncoder() {
//		final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
//		final PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
		final String defaultEncoderId = "pbkdf2v1";
		final PasswordEncoder passwordEncoder = new DelegatingPasswordEncoder(defaultEncoderId,
			Map.of(
//				"null", org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance(),
//				"noop", org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance(),
				// TODO Remove v1 with only 1 iteration and SHA1
				"pbkdf2v1", new Pbkdf2PasswordEncoder(this.springApplicationName, 16, 1, SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA1)
//				"pbkdf2v1", new Pbkdf2PasswordEncoder(this.springApplicationName, 16, 310_000, SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256)
//				"pbkdf2v2", new Pbkdf2PasswordEncoder(this.springApplicationName, 16, 120_000, SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA512)
			));
		return passwordEncoder;
	}
}