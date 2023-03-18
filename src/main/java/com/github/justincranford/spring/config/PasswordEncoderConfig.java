package com.github.justincranford.spring.config;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm;

@Configuration
public class PasswordEncoderConfig {
    @Value(value="${spring.application.name}") protected String springApplicationName;

	@Bean
	public PasswordEncoder passwordEncoder() {
		// See: PasswordEncoderFactories.createDelegatingPasswordEncoder();
		@SuppressWarnings("deprecation")
		final PasswordEncoder passwordEncoder = new DelegatingPasswordEncoder(
			// TODO: Change from pbkdf2v0 (alpha) to pbkdf2v1 (production)
			// algorithm to use for hashing new passwords (only one can be defined)
			"pbkdf2v0",
			// algorithms to use for decoding parameters of stored password hashes, for comparing challenge passwords
			Map.of(
				"null", org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance(),
				"noop", org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance(),
				"pbkdf2v0", new Pbkdf2PasswordEncoder(this.springApplicationName, 16, 1,       SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA1),
				"pbkdf2v1", new Pbkdf2PasswordEncoder(this.springApplicationName, 16, 310_000, SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256)
			));
		return passwordEncoder;
	}
}