package com.github.justincranford.spring.util.model;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.justincranford.spring.util.util.JsonUtil;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Transactional
@Entity()
@Table(name = "users")
public class User implements UserDetails {
	private static final long serialVersionUID = 1L;

	public static final User[] EMPTY_LIST = new User[0];

	// TODO Address, Phone Number

	@Id @GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;

	@Column(name = "realm", nullable = false)
	private String realm;

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

	public User() {
		// do nothing
	}

	public User(
		final String realm,
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
		this.realm = realm;
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

	public User(final User that) {
		this.id = that.id;
		this.realm = that.realm;
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

	public String getRealm() {
		return this.realm;
	}
	public void setRealm(final String realm) {
		this.realm = realm;
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
			(o instanceof User that)
			&& Objects.equals(this.id, that.id)
			&& Objects.equals(this.realm, that.realm)
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
		return Objects.hash(
			this.id,
			this.realm,
			this.username,
			this.password,
			this.emailAddress,
			this.firstName,
			this.middleName,
			this.lastName,
			this.rolesAndPrivileges,
			this.isEnabled,
			this.isAccountNonExpired,
			this.isAccountNonLocked,
			this.isCredentialsNonExpired
		);
	}

	@Override public String toString() {
		try {
			final User baseUserWithRedactedPassword = new User(this);
			baseUserWithRedactedPassword.setPassword("*** REDACTED ***");
			return JsonUtil.toJson(baseUserWithRedactedPassword);
		} catch (JsonProcessingException e) {
			throw new RuntimeException(e);
		}
	}

	private static List<SimpleGrantedAuthority> csvToAuthorities(final String privileges) {
		return Arrays.stream(privileges.split(",")).map(p -> new SimpleGrantedAuthority(p)).toList();
	}
}