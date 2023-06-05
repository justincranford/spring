package com.github.justincranford.spring.authn.server.model;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.github.justincranford.spring.util.model.User;

//public class UserDetailsServiceImpl implements UserDetailsManager, UserDetailsPasswordService {
public class UserDetailsServiceImpl implements UserDetailsService {

	private Logger logger = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

	private UserCrudRepository userCrudRepository;

	public UserDetailsServiceImpl(final UserCrudRepository userCrudRepository) {
		this.userCrudRepository = userCrudRepository;
	}

    // UserDetailsService

	@Override
	public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
		final List<? extends User> users = this.userCrudRepository.findByUsername(username);
		this.printUsers("Found users for username [" + username + "]", users);
		assert users != null;
		assert (users.size() == 0) || (users.size() == 1);
		if (users.isEmpty() == false) {
			logger.debug("Found user for username [{}]", username);
			return users.get(0);
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

	private void printUsers(final String message, final List<? extends User> baseUsers) {
		assert baseUsers != null;
		final StringBuilder sb = new StringBuilder(message).append("[").append(baseUsers.size()).append("]:\n");
		for (final User baseUser : baseUsers) {
			sb.append(baseUser).append('\n');
		}
		logger.trace(sb.toString());
	}
}
