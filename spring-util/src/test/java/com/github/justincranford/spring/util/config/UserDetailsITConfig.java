package com.github.justincranford.spring.util.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@TestConfiguration
//@Profile("!default")
public class UserDetailsITConfig {
	public record TestUser(String username, String password, Collection<String> roles) { }

	public static final TestUser APP_USER  = new TestUser("appuser",  "appuser",  Set.of("APPUSER"));
	public static final TestUser APP_ADMIN = new TestUser("appadmin", "appadmin", Set.of("APPADMIN"));
	public static final TestUser OPS_USER  = new TestUser("opsuser",  "opsuser",  Set.of("OPSUSER"));
	public static final TestUser OPS_ADMIN = new TestUser("opsadmin", "opsadmin", Set.of("OPSADMIN"));
	public static final Set<TestUser> TEST_USERS = Set.of(APP_USER, APP_ADMIN, OPS_USER, OPS_ADMIN);

	@Bean
	public UserDetailsService users(final PasswordEncoder passwordEncoder) {
		final UserBuilder builder = User.builder().passwordEncoder(passwordEncoder::encode);
		final Collection<UserDetails> users = new ArrayList<>(TEST_USERS.size());
		for (final TestUser u : TEST_USERS) {
			users.add(builder.username(u.username()).password(u.password()).roles(u.roles().toArray(new String[0])).build());
		}
		return new InMemoryUserDetailsManager(users);
	}
}