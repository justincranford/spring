package com.github.justincranford.spring.util.model;

import java.util.Arrays;

public class UserUtils {
	public static Long[] userIds(final User... users) {
		return Arrays.stream(users).map(user -> user.getId()).toArray(Long[]::new);
	}
	public static String[] usernames(final User... users) {
		return Arrays.stream(users).map(user -> user.getUsername()).toArray(String[]::new);
	}
	public static String[] emailAddresses(final User... users) {
		return Arrays.stream(users).map(user -> user.getEmailAddress()).toArray(String[]::new);
	}
	public static String[] firstNames(final User... users) {
		return Arrays.stream(users).map(user -> user.getFirstName()).toArray(String[]::new);
	}
	public static String[] lastNames(final User... users) {
		return Arrays.stream(users).map(user -> user.getLastName()).toArray(String[]::new);
	}
}
