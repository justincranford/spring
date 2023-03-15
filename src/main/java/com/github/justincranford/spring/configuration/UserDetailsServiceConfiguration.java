package com.github.justincranford.spring.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;

import com.github.justincranford.spring.model.AppUserCrudRepository;
import com.github.justincranford.spring.model.OpsUserCrudRepository;
import com.github.justincranford.spring.model.UserDetailsServiceImpl;

@Configuration
@EnableWebSecurity
public class UserDetailsServiceConfiguration {
	@Bean
	public UserDetailsService userDetailsService(
		final OpsUserCrudRepository opsUserCrudRepository,
		final AppUserCrudRepository appUserCrudRepository
	) {
		return new UserDetailsServiceImpl(opsUserCrudRepository, appUserCrudRepository);
	}
}