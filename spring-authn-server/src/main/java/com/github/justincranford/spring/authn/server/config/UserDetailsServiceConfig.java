package com.github.justincranford.spring.authn.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;

import com.github.justincranford.spring.authn.server.model.UserCrudRepository;
import com.github.justincranford.spring.authn.server.model.UserDetailsServiceImpl;

@Configuration
public class UserDetailsServiceConfig {
	@Bean
	public UserDetailsService userDetailsService(final UserCrudRepository userCrudRepository) {
		return new UserDetailsServiceImpl(userCrudRepository);
	}
}