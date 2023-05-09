package com.github.justincranford.spring.authz.server.model;

import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;

@Transactional
@Entity()
@Table(name = "ops_users")
public class OpsUser extends BaseUser {

	private static final long serialVersionUID = 1L;

	public OpsUser() {
		super();
	}

	public OpsUser(
		final String username, 
		final String password, 
		final String emailAddress,
		final String firstName, 
		final String middleName, 
		final String lastName,
		final String rolesAndPrivileges,
		final boolean isEnabled,
		final boolean isAccountNonExpired,
		final boolean isAccountNonLocked,
		final boolean isCredentialsNonExpired
	) {
		super(username, password, emailAddress, firstName, middleName, lastName, rolesAndPrivileges, isEnabled, isAccountNonExpired, isAccountNonLocked, isCredentialsNonExpired);
	}

	@Override public boolean equals(final Object o) {
		return (o instanceof OpsUser that) && super.equals(that);
	}

	@Override public int hashCode() {
		return super.hashCode();
	}
}