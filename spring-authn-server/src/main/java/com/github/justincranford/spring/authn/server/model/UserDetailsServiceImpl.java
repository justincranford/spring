package com.github.justincranford.spring.authn.server.model;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.github.justincranford.spring.util.model.BaseUser;

//public class UserDetailsServiceImpl implements UserDetailsManager, UserDetailsPasswordService {
public class UserDetailsServiceImpl implements UserDetailsService {

	private Logger logger = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

	private OpsUserCrudRepository opsUserCrudRepository;
	private AppUserCrudRepository appUserCrudRepository;

	public UserDetailsServiceImpl(final OpsUserCrudRepository opsUserCrudRepository, final AppUserCrudRepository appUserCrudRepository) {
		this.opsUserCrudRepository = opsUserCrudRepository;
		this.appUserCrudRepository = appUserCrudRepository;
	}

    // UserDetailsService

	@Override
	public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
		final List<? extends BaseUser> opsUsers = this.opsUserCrudRepository.findByUsername(username);
		this.printUsers("Found Operations users for username [" + username + "]", opsUsers);
		assert opsUsers != null;
		assert (opsUsers.size() == 0) || (opsUsers.size() == 1);
		if (opsUsers.isEmpty() == false) {
			logger.debug("Found Operations user for username [{}]", username);
			return opsUsers.get(0);
		}

		final List<? extends BaseUser> appUsers = this.appUserCrudRepository.findByUsername(username);
		this.printUsers("Found Application users for username [" + username + "]", appUsers);
		assert appUsers != null;
		assert (appUsers.size() == 0) || (appUsers.size() == 1);
		if (appUsers.isEmpty() == false) {
			logger.debug("Found Application user for username [{}]", username);
			return appUsers.get(0);
		}

		throw new UsernameNotFoundException("Username " + username + " not found");
	}

    // UserDetailsManager

//	@Override
//	public boolean userExists(final String username) {
//		return this.loadUserByUsername(username) != null;
//	}
//
//	@Override
//	public void createUser(final UserDetails user) {
//		throw new UsernameNotFoundException("Not supported");
//	}
//
//	@Override
//	public void updateUser(final UserDetails user) {
//		throw new UsernameNotFoundException("Not supported");
//	}
//
//	@Override
//	public void deleteUser(final String username) {
//		throw new UsernameNotFoundException("Not supported");
//	}
//
//	@Override
//	public void changePassword(final String oldPassword, final String newPassword) {
//		throw new UsernameNotFoundException("Not supported");
//	}

    // UserDetailsPasswordService

//	@Override
//	public UserDetails updatePassword(final UserDetails user, final String newPassword) {
//		throw new UsernameNotFoundException("Not supported");
//	}

    // Helper

	private void printUsers(final String message, final List<? extends BaseUser> baseUsers) {
		assert baseUsers != null;
		final StringBuilder sb = new StringBuilder(message).append("[").append(baseUsers.size()).append("]:\n");
		for (final BaseUser baseUser : baseUsers) {
			sb.append(baseUser).append('\n');
		}
		logger.trace(sb.toString());
	}
}
