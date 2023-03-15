package com.github.justincranford.spring.model;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class AppUserCrudRepositoryInit {
	private Logger logger = LoggerFactory.getLogger(AppUserCrudRepositoryInit.class);

	@Autowired protected AppUserCrudRepository appUserCrudRepository;
	@Autowired protected PasswordEncoder       passwordEncoder;

	@Transactional
	public void run() {
		this.appadmin();
		this.appuser();
	}

	private void appadmin() {
		final List<AppUser> appadminSearch = this.appUserCrudRepository.findByUsername("appadmin");
		final AppUser appAdmin;
		if (appadminSearch.isEmpty()) {
			final AppUser contructAppAdmin = contructAppAdmin();	// PBKDF2 is intentionally expensive for short passwords (i.e. low entropy)
			appAdmin = this.appUserCrudRepository.save(contructAppAdmin);
			this.logger.info("AppUser 'appadmin' added:\n{}", appAdmin);
		} else {
			appAdmin = appadminSearch.get(0);
			this.logger.info("AppUser 'appadmin' already exists:\n{}", appAdmin);
		}
	}

	private void appuser() {
		final List<AppUser> appuserSearch = this.appUserCrudRepository.findByUsername("appuser");
		final AppUser appUser;
		if (appuserSearch.isEmpty()) {
			final AppUser contructAppUser = contructAppUser();	// PBKDF2 is intentionally expensive for short passwords (i.e. low entropy)
			appUser = this.appUserCrudRepository.save(contructAppUser);
			this.logger.info("AppUser 'appuser' added:\n{}", appUser);
		} else {
			appUser = appuserSearch.get(0);
			this.logger.info("AppUser 'appuser' already exists:\n{}", appUser);
		}
	}

	private AppUser contructAppAdmin() {
		final String username = "appadmin";
		final String password = this.passwordEncoder.encode("appadmin"); // PBKDF2 is intentionally expensive for short passwords (i.e. low entropy)
		final String emailAddress = "appadmin@example.com";
		final String firstName = "Administrator";
		final String middleName = "Built-in";
		final String lastName = "Operations";
		final String rolesAndPrivileges = "ROLE_APP_ADMIN,ROLE_APP_USER";
		final boolean isEnabled = true;
		final boolean isAccountNonExpired = true;
		final boolean isAccountNonLocked = true;
		final boolean isCredentialsNonExpired = true;
		return new AppUser(username, password, emailAddress, firstName, middleName, lastName, rolesAndPrivileges, isEnabled, isAccountNonExpired, isAccountNonLocked, isCredentialsNonExpired);
	}

	private AppUser contructAppUser() {
		final String username = "appuser";
		final String password = this.passwordEncoder.encode("appuser"); // PBKDF2 is intentionally expensive for short passwords (i.e. low entropy)
		final String emailAddress = "appuser@example.com";
		final String firstName = "User";
		final String middleName = "Built-in";
		final String lastName = "Operations";
		final String rolesAndPrivileges = "ROLE_APP_USER";
		final boolean isEnabled = true;
		final boolean isAccountNonExpired = true;
		final boolean isAccountNonLocked = true;
		final boolean isCredentialsNonExpired = true;
		return new AppUser(username, password, emailAddress, firstName, middleName, lastName, rolesAndPrivileges, isEnabled, isAccountNonExpired, isAccountNonLocked, isCredentialsNonExpired);
	}
}
