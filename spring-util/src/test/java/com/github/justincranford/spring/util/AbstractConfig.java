package com.github.justincranford.spring.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@TestConfiguration
//@Profile("!default")
@SuppressWarnings("deprecation")
public class AbstractConfig {
	public record TestUser(String username, String password, Collection<String> roles) { }

	public static final TestUser UPTIME_USER  = new TestUser("uptime", "uptime",  Collections.emptySet());
	public static final Set<TestUser> TEST_USERS = Set.of(UPTIME_USER);

	@Bean
	public UserDetailsService users(final PasswordEncoder passwordEncoder) {
		final UserBuilder builder = User.builder().passwordEncoder(passwordEncoder::encode);
		final Collection<UserDetails> users = new ArrayList<>(TEST_USERS.size());
		for (final TestUser u : TEST_USERS) {
			users.add(builder.username(u.username()).password(u.password()).roles(u.roles().toArray(new String[0])).build());
		}
		return new InMemoryUserDetailsManager(users);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new DelegatingPasswordEncoder("sha256", Collections.singletonMap("sha256", new MessageDigestPasswordEncoder("SHA-256")));
	}
}
