package com.github.justincranford.spring.authn.server.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.github.justincranford.spring.util.model.UserConfig.ConfiguredUser;
import com.github.justincranford.spring.util.model.UserConfig.ConfiguredUsers;

import jakarta.annotation.PostConstruct;

@Component
public class WellKnownUsers {
	public static record UsernameAndReam(String realm, String username) { }

	@Autowired
	private ConfiguredUsers configuredUsers;

	public List<String> realms;
	public List<String> usernames;
	public List<UsernameAndReam> usernameAndRealms;

	@PostConstruct
	private void postConstruct() {
		this.realms = new ArrayList<>();
		this.usernames = new ArrayList<>();
		this.usernameAndRealms = new ArrayList<>();
		for (final Map.Entry<String, Map<String, ConfiguredUser>> realmEntry : this.configuredUsers.getUsers().entrySet()) {
			final String realm = realmEntry.getKey();
			this.realms.add(realm);
			for (final String username : realmEntry.getValue().keySet()) {
				this.usernames.add(username);
				this.usernameAndRealms.add(new UsernameAndReam(realm, username));
			}
		}
		this.realms = Collections.unmodifiableList(this.realms);
		this.usernames = Collections.unmodifiableList(this.usernames);
		this.usernameAndRealms = Collections.unmodifiableList(this.usernameAndRealms);
	}

	public List<String> realms() {
		return this.realms;
	}

	public List<String> usernames() {
		return this.usernames;
	}

	public List<UsernameAndReam> usernameAndRealms() {
		return this.usernameAndRealms;
	}

	public static final String OPS = "ops";
	public static final String APP = "app";

	public static final String OPSADMIN = "opsadmin";
	public static final String OPSUSER = "opsuser";
	public static final String APPADMIN = "appadmin";
	public static final String APPUSER = "appuser";
}
