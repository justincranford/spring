package com.github.justincranford.spring.authn.server.model;

import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.github.justincranford.spring.authn.server.controller.UsersProperties.ConfiguredUser;
import com.github.justincranford.spring.authn.server.controller.UsersProperties.OpsUsersProperties;
import com.github.justincranford.spring.util.model.OpsUser;

import jakarta.annotation.PostConstruct;

@Component
public class OpsUserCrudRepositoryInit {
	private Logger logger = LoggerFactory.getLogger(OpsUserCrudRepositoryInit.class);

	@Autowired protected PasswordEncoder       passwordEncoder;
	@Autowired protected OpsUsersProperties    opsUsersProperties;
	@Autowired protected OpsUserCrudRepository opsUserCrudRepository;

	@Transactional
	@PostConstruct
	public void run() {
		for (final ConfiguredUser configuredUser : this.opsUsersProperties.configuredUsers) {
			final List<OpsUser> foundUsers = this.opsUserCrudRepository.findByUsername(configuredUser.getUsername());
			if (foundUsers.isEmpty()) {
				final String username = configuredUser.getUsername();
				final String password = configuredUser.getPassword();
				final String emailAddress = configuredUser.getEmailAddress();
				final String firstName = configuredUser.getFirstName();
				final String middleName = configuredUser.getMiddleName();
				final String lastName = configuredUser.getLastName();
				final Set<String> authorities = configuredUser.getAuthorities();
				final Boolean isEnabled = configuredUser.isEnabled();
				final Boolean isAccountNonExpired = configuredUser.isAccountNonExpired();
				final Boolean isAccountNonLocked = configuredUser.isAccountNonLocked();
				final Boolean isCredentialsNonExpired = configuredUser.isCredentialsNonExpired();
				final OpsUser contructedOpsAdmin = new OpsUser(username, this.passwordEncoder.encode(password), emailAddress, firstName, middleName, lastName, String.join(",", authorities), isEnabled, isAccountNonExpired, isAccountNonLocked, isCredentialsNonExpired);
				final OpsUser opsAdmin = this.opsUserCrudRepository.save(contructedOpsAdmin);
				this.logger.info("OpsUser '{}' added:\n{}", configuredUser.getUsername(), opsAdmin);
			} else {
				final OpsUser foundUser = foundUsers.get(0);
				this.logger.info("OpsUser '{}' already exists:\n{}", configuredUser.getUsername(), foundUser);
			}
		}
	}
}
