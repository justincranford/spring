package com.github.justincranford.spring.model.user;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.github.justincranford.spring.common.JsonUtil;

import jakarta.persistence.Column;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;

@Transactional
@MappedSuperclass
public class BaseUser implements UserDetails {

	private static final long serialVersionUID = 1L;

	// TODO Address, Phone Number

	@Id @GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;

	@Column(name = "username", nullable = false)
	private String username;

	@Column(name = "password", nullable = true)
	private String password;

	@Column(name = "emailAddress", nullable = false)
	private String emailAddress;

	@Column(name = "firstName", nullable = false)
	private String firstName;

	@Column(name = "middleName", nullable = false)
	private String middleName;

	@Column(name = "lastName", nullable = false)
	private String lastName;

	@Column(name = "rolesAndPrivileges", nullable = false)
	private String rolesAndPrivileges;

	@Column(name = "isEnabled", nullable = false)
	private boolean isEnabled;

	@Column(name = "isAccountNonExpired", nullable = false)
	private boolean isAccountNonExpired;

	@Column(name = "isAccountNonLocked", nullable = false)
	private boolean isAccountNonLocked;

	@Column(name = "isCredentialsNonExpired", nullable = false)
	private boolean isCredentialsNonExpired;

	public BaseUser() {
		// do nothing
	}

	public BaseUser(
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
		this.id = 0;//Long.MIN_VALUE;
		this.username = username;
		this.password = password;
		this.emailAddress = emailAddress;
		this.firstName = firstName;
		this.middleName = middleName;
		this.lastName = lastName;
		this.rolesAndPrivileges = rolesAndPrivileges;
		this.isEnabled = isEnabled;
		this.isAccountNonExpired = isAccountNonExpired;
		this.isAccountNonLocked = isAccountNonLocked;
		this.isCredentialsNonExpired = isCredentialsNonExpired;
	}

	public BaseUser(final BaseUser that) {
		this.id = that.id;
		this.username = that.username;
		this.password = that.password;
		this.emailAddress = that.emailAddress;
		this.firstName = that.firstName;
		this.middleName = that.middleName;
		this.lastName = that.lastName;
		this.rolesAndPrivileges = that.rolesAndPrivileges;
		this.isEnabled = that.isEnabled;
		this.isAccountNonExpired = that.isAccountNonExpired;
		this.isAccountNonLocked = that.isAccountNonLocked;
		this.isCredentialsNonExpired = that.isCredentialsNonExpired;
	}

	public long getId() {
		return this.id;
	}
	public void setId(final long id) {
		this.id = id;
	}

	@Override
	public String getUsername() {
		return this.username;
	}
	public void setUsername(final String username) {
		this.username = username;
	}

	public String getPassword() {
		return this.password;
	}
	public void setPassword(final String password) {
		this.password = password;
	}

	public String getEmailAddress() {
		return this.emailAddress;
	}
	public void setEmailAddress(final String emailAddress) {
		this.emailAddress = emailAddress;
	}

	public String getFirstName() {
		return this.firstName;
	}
	public void setFirstName(final String firstName) {
		this.firstName = firstName;
	}

	public String getMiddleName() {
		return this.middleName;
	}
	public void setMiddleName(final String middleName) {
		this.middleName = middleName;
	}

	public String getLastName() {
		return this.lastName;
	}
	public void setLastName(final String lastName) {
		this.lastName = lastName;
	}

	public String getRolesAndPrivileges() {
		return this.rolesAndPrivileges;
	}
	public void setRolesAndPrivileges(final String rolesAndPrivileges) {
		this.rolesAndPrivileges = rolesAndPrivileges;
	}

	@JsonIgnore
	@Override public Collection<? extends GrantedAuthority> getAuthorities() {
		return csvToAuthorities(this.rolesAndPrivileges);
	}

	@Override public boolean isEnabled() {
		return this.isEnabled;
	}
	public void setEnabled(final boolean isEnabled) {
		this.isEnabled = isEnabled;
	}

	@Override public boolean isAccountNonExpired() {
		return this.isAccountNonExpired;
	}
	public void setAccountNonExpired(final boolean isAccountNonExpired) {
		this.isAccountNonExpired = isAccountNonExpired;
	}

	@Override public boolean isAccountNonLocked() {
		return this.isAccountNonLocked;
	}
	public void setAccountNonLocked(final boolean isAccountNonLocked) {
		this.isAccountNonLocked = isAccountNonLocked;
	}

	@Override public boolean isCredentialsNonExpired() {
		return this.isCredentialsNonExpired;
	}
	public void setCredentialsNonExpired(final boolean isCredentialsNonExpired) {
		this.isCredentialsNonExpired = isCredentialsNonExpired;
	}

	@Override public boolean equals(final Object o) {
		return
			(o instanceof BaseUser that)
			&& Objects.equals(this.id, that.id)
			&& Objects.equals(this.username, that.username)
			&& Objects.equals(this.password, that.password)
			&& Objects.equals(this.emailAddress, that.emailAddress)
			&& Objects.equals(this.firstName, that.firstName)
			&& Objects.equals(this.middleName, that.middleName)
			&& Objects.equals(this.lastName, that.lastName)
			&& Objects.equals(this.rolesAndPrivileges, that.rolesAndPrivileges)
			&& Objects.equals(this.isEnabled, that.isEnabled)
			&& Objects.equals(this.isAccountNonExpired, that.isAccountNonExpired)
			&& Objects.equals(this.isAccountNonLocked, that.isAccountNonLocked)
			&& Objects.equals(this.isCredentialsNonExpired, that.isCredentialsNonExpired)
		;
	}

	@Override public int hashCode() {
		return Long.hashCode(this.id)
			+ this.username.hashCode()
			+ this.password.hashCode()
			+ this.emailAddress.hashCode()
			+ this.firstName.hashCode()
			+ this.middleName.hashCode()
			+ this.lastName.hashCode()
			+ this.rolesAndPrivileges.hashCode()
			+ Boolean.hashCode(this.isEnabled)
			+ Boolean.hashCode(this.isAccountNonExpired)
			+ Boolean.hashCode(this.isAccountNonLocked)
			+ Boolean.hashCode(this.isCredentialsNonExpired)
		;
	}

	@Override public String toString() {
		final BaseUser baseUserWithoutPassword = new BaseUser(this);
		baseUserWithoutPassword.setPassword("*** REDACTED ***");
		return JsonUtil.pojoToJsonString(baseUserWithoutPassword);
	}

	private static List<SimpleGrantedAuthority> csvToAuthorities(final String privileges) {
		return Arrays.stream(privileges.split(",")).map(p -> new SimpleGrantedAuthority(p)).toList();
	}
}