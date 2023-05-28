package com.github.justincranford.spring.authn.server.model;

import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.github.justincranford.spring.authn.server.controller.UsersProperties.AppUsersProperties;
import com.github.justincranford.spring.authn.server.controller.UsersProperties.ConfiguredUser;
import com.github.justincranford.spring.util.model.AppUser;

import jakarta.annotation.PostConstruct;

@Component
public class AppUserCrudRepositoryInit {
	private Logger logger = LoggerFactory.getLogger(AppUserCrudRepositoryInit.class);

	@Autowired protected PasswordEncoder       passwordEncoder;
	@Autowired protected AppUsersProperties    appUsersProperties;
	@Autowired protected AppUserCrudRepository appUserCrudRepository;

	@Transactional
	@PostConstruct
	public void run() {
		for (final ConfiguredUser configuredUser : this.appUsersProperties.configuredUsers) {
			final List<AppUser> foundUsers = this.appUserCrudRepository.findByUsername(configuredUser.getUsername());
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
				final AppUser contructedAppAdmin = new AppUser(username, this.passwordEncoder.encode(password), emailAddress, firstName, middleName, lastName, String.join(",", authorities), isEnabled, isAccountNonExpired, isAccountNonLocked, isCredentialsNonExpired);
				final AppUser appAdmin = this.appUserCrudRepository.save(contructedAppAdmin);
				this.logger.info("AppUser '{}' added:\n{}", configuredUser.getUsername(), appAdmin);
			} else {
				final AppUser foundUser = foundUsers.get(0);
				this.logger.info("AppUser '{}' already exists:\n{}", configuredUser.getUsername(), foundUser);
			}
		}
	}
}
