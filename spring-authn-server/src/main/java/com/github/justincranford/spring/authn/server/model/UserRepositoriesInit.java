package com.github.justincranford.spring.authn.server.model;

import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.github.justincranford.spring.util.model.User;
import com.github.justincranford.spring.util.model.UserConfig.ConfiguredUser;
import com.github.justincranford.spring.util.model.UserConfig.ConfiguredUsers;

import jakarta.annotation.PostConstruct;

@Component
public class UserRepositoriesInit {
	private Logger logger = LoggerFactory.getLogger(UserRepositoriesInit.class);

	@Autowired protected PasswordEncoder    passwordEncoder;
	@Autowired protected ConfiguredUsers    configuredUsers;
	@Autowired protected UserCrudRepository userCrudRepository;

	@Transactional
	@PostConstruct
	public void configureUsers() throws Exception {
		final Map<String, Map<String, ConfiguredUser>> realms = this.configuredUsers.getUsers();
		for (final Map.Entry<String, Map<String, ConfiguredUser>> entry : realms.entrySet()) {
			final String realm = entry.getKey();
			final Map<String, ConfiguredUser> configuredUsers = entry.getValue();
			for (Map.Entry<String, ConfiguredUser> usernameAndConfiguredUser : configuredUsers.entrySet()) {
				final String username = usernameAndConfiguredUser.getKey();
				final ConfiguredUser configuredUser = usernameAndConfiguredUser.getValue();
				final List<User> foundUsers = this.userCrudRepository.findByUsername(username);
				if (foundUsers.isEmpty()) {
					final User user = this.userCrudRepository.save(new User(
						realm,
						username,
						this.passwordEncoder.encode(configuredUser.getPassword()),
						configuredUser.getEmailAddress(),
						configuredUser.getFirstName(),
						configuredUser.getMiddleName(),
						configuredUser.getLastName(),
						String.join(",", configuredUser.getAuthorities()),
						configuredUser.isEnabled(),
						configuredUser.isAccountNonExpired(),
						configuredUser.isAccountNonLocked(),
						configuredUser.isCredentialsNonExpired()
					));
					this.logger.info("User '{}' added:\n{}", username, user);
				} else {
					final User foundUser = foundUsers.get(0);
					this.logger.info("User '{}' already exists:\n{}", username, foundUser);
				}
			}
		}
	}
}
