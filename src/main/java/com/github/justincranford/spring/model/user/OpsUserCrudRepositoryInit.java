package com.github.justincranford.spring.model.user;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class OpsUserCrudRepositoryInit {
	private Logger logger = LoggerFactory.getLogger(OpsUserCrudRepositoryInit.class);

	@Autowired protected OpsUserCrudRepository opsUserCrudRepository;
	@Autowired protected PasswordEncoder       passwordEncoder;

	@Transactional
	public void run() {
		this.opsadmin();
		this.opsuser();
	}

	private void opsadmin() {
		final List<OpsUser> opsadminSearch = this.opsUserCrudRepository.findByUsername("opsadmin");
		final OpsUser opsAdmin;
		if (opsadminSearch.isEmpty()) {
			final OpsUser contructOpsAdmin = contructOpsAdmin();	// PBKDF2 is intentionally expensive for short passwords (i.e. low entropy)
			opsAdmin = this.opsUserCrudRepository.save(contructOpsAdmin);
			this.logger.info("OpsUser 'opsadmin' added:\n{}", opsAdmin);
		} else {
			opsAdmin = opsadminSearch.get(0);
			this.logger.info("OpsUser 'opsadmin' already exists:\n{}", opsAdmin);
		}
	}

	private void opsuser() {
		final List<OpsUser> opsuserSearch = this.opsUserCrudRepository.findByUsername("opsuser");
		final OpsUser opsUser;
		if (opsuserSearch.isEmpty()) {
			final OpsUser contructOpsUser = contructOpsUser();	// PBKDF2 is intentionally expensive for short passwords (i.e. low entropy)
			opsUser = this.opsUserCrudRepository.save(contructOpsUser);
			this.logger.info("OpsUser 'opsuser' added:\n{}", opsUser);
		} else {
			opsUser = opsuserSearch.get(0);
			this.logger.info("OpsUser 'opsuser' already exists:\n{}", opsUser);
		}
	}

	private OpsUser contructOpsAdmin() {
		final String username = "opsadmin";
		final String password = this.passwordEncoder.encode("opsadmin");	// PBKDF2 is intentionally expensive for short passwords (i.e. low entropy)
		final String emailAddress = "opsadmin@example.com";
		final String firstName = "Administrator";
		final String middleName = "Built-in";
		final String lastName = "Operations";
		final String rolesAndPrivileges = "ROLE_OPS_ADMIN,ROLE_OPS_USER";
		final boolean isEnabled = true;
		final boolean isAccountNonExpired = true;
		final boolean isAccountNonLocked = true;
		final boolean isCredentialsNonExpired = true;
		return new OpsUser(username, password, emailAddress, firstName, middleName, lastName, rolesAndPrivileges, isEnabled, isAccountNonExpired, isAccountNonLocked, isCredentialsNonExpired);
	}

	private OpsUser contructOpsUser() {
		final String username = "opsuser";
		final String password = this.passwordEncoder.encode("opsuser");	// PBKDF2 is intentionally expensive for short passwords (i.e. low entropy)
		final String emailAddress = "opsuser@example.com";
		final String firstName = "User";
		final String middleName = "Built-in";
		final String lastName = "Operations";
		final String rolesAndPrivileges = "ROLE_OPS_USER";
		final boolean isEnabled = true;
		final boolean isAccountNonExpired = true;
		final boolean isAccountNonLocked = true;
		final boolean isCredentialsNonExpired = true;
		return new OpsUser(username, password, emailAddress, firstName, middleName, lastName, rolesAndPrivileges, isEnabled, isAccountNonExpired, isAccountNonLocked, isCredentialsNonExpired);
	}
}
