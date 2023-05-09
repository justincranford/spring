package com.github.justincranford.spring.authz.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;

import com.github.justincranford.spring.authz.server.model.AppUserCrudRepository;
import com.github.justincranford.spring.authz.server.model.OpsUserCrudRepository;
import com.github.justincranford.spring.authz.server.model.UserDetailsServiceImpl;

@Configuration
public class UserDetailsServiceConfig {
	@Bean
	public UserDetailsService userDetailsService(
		final OpsUserCrudRepository opsUserCrudRepository,
		final AppUserCrudRepository appUserCrudRepository
	) {
		// Impl uses separate repos for Operations vs Application users
		return new UserDetailsServiceImpl(opsUserCrudRepository, appUserCrudRepository);
	}
}