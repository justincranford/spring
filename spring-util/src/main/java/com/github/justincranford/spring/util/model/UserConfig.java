package com.github.justincranford.spring.util.model;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;

@Configuration
public class UserConfig {
	@Configuration
	@ConfigurationProperties
	public static class ConfiguredUsers {
		public Map<String, List<ConfiguredUser>> users;
		public Map<String, List<ConfiguredUser>> getUsers() {
			return this.users;
		}
		public void setUsers(final Map<String, List<ConfiguredUser>> realms) {
			this.users = realms;
		}
	}

	public static class ConfiguredUser {
		@Min(8) @Max(255) public String username;
		@Min(8) @Max(255) String password;
		@Min(3) @Max(64+1+255) String emailAddress;
		@Min(1) @Max(255) String firstName;
		@Min(1) @Max(255) String middleName;
		@Min(1) @Max(255) String lastName;
		@Min(1) @Max(255) Set<String> authorities = Collections.emptySet();
		Boolean isEnabled = false;
		Boolean isAccountNonExpired = false;
		Boolean isAccountNonLocked = false;
		Boolean isCredentialsNonExpired = false;

		public String getPassword() {
			return password;
		}
		public void setPassword(String password) {
			this.password = password;
		}
		public String getEmailAddress() {
			return emailAddress;
		}
		public void setEmailAddress(String emailAddress) {
			this.emailAddress = emailAddress;
		}
		public String getFirstName() {
			return firstName;
		}
		public void setFirstName(String firstName) {
			this.firstName = firstName;
		}
		public String getMiddleName() {
			return middleName;
		}
		public void setMiddleName(String middleName) {
			this.middleName = middleName;
		}
		public String getLastName() {
			return lastName;
		}
		public void setLastName(String lastName) {
			this.lastName = lastName;
		}
		public Set<String> getAuthorities() {
			return authorities;
		}
		public void setAuthorities(Set<String> authorities) {
			this.authorities = authorities;
		}
		public Boolean isEnabled() {
			return isEnabled;
		}
		public void setEnabled(Boolean isEnabled) {
			this.isEnabled = isEnabled;
		}
		public Boolean isAccountNonExpired() {
			return isAccountNonExpired;
		}
		public void setAccountNonExpired(Boolean isAccountNonExpired) {
			this.isAccountNonExpired = isAccountNonExpired;
		}
		public Boolean isAccountNonLocked() {
			return isAccountNonLocked;
		}
		public void setAccountNonLocked(Boolean isAccountNonLocked) {
			this.isAccountNonLocked = isAccountNonLocked;
		}
		public Boolean isCredentialsNonExpired() {
			return isCredentialsNonExpired;
		}
		public void setCredentialsNonExpired(Boolean isCredentialsNonExpired) {
			this.isCredentialsNonExpired = isCredentialsNonExpired;
		}
		public String getUsername() {
			return username;
		}
		public void setUsername(String username) {
			this.username = username;
		}

	}
}
