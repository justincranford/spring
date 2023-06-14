package com.github.justincranford.spring.authn.server.api.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.util.List;
import java.util.stream.LongStream;
import java.util.stream.Stream;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import com.github.justincranford.spring.authn.server.AbstractIT;
import com.github.justincranford.spring.util.model.User;

import io.restassured.http.Method;
import io.restassured.response.Response;

public class UserApiIT extends AbstractIT {
	private Logger logger = LoggerFactory.getLogger(UserApiIT.class);
	private static final String TEST_REALM = "Test";

	@Nested
	public class WellKnownRealmsAndUsers extends AbstractIT {
		private record Args(String realm, String username) { }
		static Stream<Args> args() {
			return Stream.of(new Args("ops", "opsadmin"), new Args("ops", "opsuser"), new Args("app", "appadmin"), new Args("app", "appuser"));
		}
		@ParameterizedTest @MethodSource("args")
		void testWellKnownUsernameWithRealm(final Args args) {
			verify(args, UserClient.getOrDeleteFiltered(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.GET, UserClient.parameters("realm", args.realm(), "username", args.username())));
		}
		@ParameterizedTest @MethodSource("args")
		void testWellKnownUsernameWithoutRealm(final Args args) {
			verify(args, UserClient.getOrDeleteFiltered(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.GET, UserClient.parameters("username", args.username())));
		}
		private void verify(final Args args, final User[] users) {
			assertThat(users).isNotNull();
			assertThat(users.length).isEqualTo(1);
			assertThat(users[0].getUsername()).isEqualTo(args.username());
			assertThat(users[0].getRealm()).isEqualTo(args.realm());
		}
	}

	@Nested
	public class AuthenticationErrors extends AbstractIT {
		@Test
		public void testAuthenticationRequiredButNoCreds() {
			final User user = UserClient.createOrUpdateUser(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.POST, constructUser(TEST_REALM));
			final Response response = this.restAssuredNoCreds.get(UserClient.userUrl(super.baseUrl, TEST_REALM, user.getId()));
			printResponseAndVerifyStatusCode(response, HttpStatus.UNAUTHORIZED);
		}
		@Test
		public void testAuthenticationRequiredButInvalidCreds() {
			final User user = UserClient.createOrUpdateUser(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.POST, constructUser(TEST_REALM));
			final Response response = this.restAssuredInvalidCreds.get(UserClient.userUrl(super.baseUrl, TEST_REALM, user.getId()));
			printResponseAndVerifyStatusCode(response, HttpStatus.UNAUTHORIZED);
		}
	}

	@Nested
	public class AuthorizationErrors extends AbstractIT {
		@Test
		public void testAuthenticatedButMissingRole() {
			final User user = UserClient.createOrUpdateUser(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.POST, constructUser(TEST_REALM));
			final Response response = super.restAssuredAppUserCreds().get(UserClient.userUrl(super.baseUrl, TEST_REALM, user.getId()));
			printResponseAndVerifyStatusCode(response, HttpStatus.FORBIDDEN);
		}
	}

	@Nested
	public class CrudErrors extends AbstractIT {
		private record Args(Integer count) { }
		static Stream<Args> args() {
			return Stream.of(new Args(1), new Args(3));
		}
		@ParameterizedTest @MethodSource("args")
		public void whenInvalidCreate_thenError(final Args args) {
			final List<User> invalid = LongStream.rangeClosed(1, args.count()).mapToObj((offset) -> constructUser(TEST_REALM)).toList();
			invalid.forEach(user -> user.setLastName(null));
			final List<User> created = UserClient.createOrUpdateUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.POST, invalid);
			assertThat(created).isEmpty();
		}
		@ParameterizedTest @MethodSource("args")
		public void whenInvalidRead_thenNotFound(final Args args) {
			final List<Long> invalidIds = LongStream.rangeClosed(1, args.count()).map((offset) -> UNIQUE_LONG.getAndIncrement()).boxed().toList();
			final List<User> get = UserClient.getOrDeleteUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.GET, invalidIds);
			assertThat(get).isEmpty();
		}
		@ParameterizedTest @MethodSource("args")
		public void whenInvalidUpdate_thenError(final Args args) {
			final List<User> created = UserClient.createOrUpdateUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final List<User> modified = created.stream().map((user) -> {
				final User copy = new User(user);
				copy.setLastName(null);
				return copy;
			}).toList();
			final List<User> updated = UserClient.createOrUpdateUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.PUT, modified);
			assertThat(updated).isEmpty();
		}
		@ParameterizedTest @MethodSource("args")
		public void whenInvalidDelete_thenError(final Args args) {
			final List<Long> invalidIds = LongStream.rangeClosed(1, args.count()).map((offset) -> UNIQUE_LONG.getAndIncrement()).boxed().toList();
			final List<User> delete = UserClient.getOrDeleteUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.DELETE, invalidIds);
			assertThat(delete).isEmpty();
		}
	}

	@Nested
	public class CrudSuccess extends AbstractIT {
		private record Args(Integer count) { }
		static Stream<Args> args() {
			return Stream.of(new Args(1), new Args(2));
		}
		@ParameterizedTest @MethodSource("args")
		public void whenCreate_thenCreated(final Args args) {
			assertDoesNotThrow(() -> UserClient.createOrUpdateUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count())));
		}
		@ParameterizedTest @MethodSource("args")
		public void whenReadByIds_thenOK(final Args args) {
			final List<User> created = UserClient.createOrUpdateUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final List<User> get = UserClient.getOrDeleteUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.GET, UserClient.userIds(created));
			assertThat(get).containsAll(created);
		}
		@ParameterizedTest @MethodSource("args")
		public void whenUpdate_thenOK(final Args args) {
			final List<User> created = UserClient.createOrUpdateUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final List<User> modified = created.stream().map((user) -> {
				final User copy = new User(user);
				copy.setLastName("newLastName");
				return copy;
			}).toList();
			final List<User> updated = UserClient.createOrUpdateUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.PUT, modified);
			updated.stream().forEach((user) -> assertThat(user.getLastName()).isEqualTo("newLastName"));
			final List<User> get = UserClient.getOrDeleteUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.GET, UserClient.userIds(created));
			assertThat(get).isEqualTo(updated);
			assertThat(get).isNotEqualTo(created);
		}
		@ParameterizedTest @MethodSource("args")
		public void whenDeleteByIds_thenOk(final Args args) {
			final List<User> created = UserClient.createOrUpdateUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final List<User> deleted = UserClient.getOrDeleteUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.DELETE, UserClient.userIds(created));
			assertThat(deleted).containsAll(created);
			final List<User> get = UserClient.getOrDeleteUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.GET, UserClient.userIds(created));
			assertThat(get).isEmpty();
		}
	}

	@Nested
	public class FilteredReads extends AbstractIT {
		private record Args(Integer count) { }
		static Stream<Args> args() {
			return Stream.of(new Args(1), new Args(2));
		}
		@ParameterizedTest @MethodSource("args")
		public void testGetAllUsers_thenOK(final Args args) {
			final List<User> created = UserClient.createOrUpdateUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final User[] got = UserClient.getOrDeleteFiltered(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.GET, UserClient.parameters("realm", TEST_REALM));
			assertThat(got).containsAll(created);
			UserClient.userIds(created).forEach(id -> assertThat(UserClient.getOrDeleteUser(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.GET, id)).isNotNull());
		}
		@ParameterizedTest @MethodSource("args")
		public void whenGetUsersByEmailAddresses_thenOK(final Args args) {
			final List<User> created = UserClient.createOrUpdateUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final User[] got = UserClient.getOrDeleteFiltered(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.GET, UserClient.parameters("realm", TEST_REALM, "username", UserClient.usernames(created)));
			assertThat(got).containsAll(created);
			UserClient.userIds(created).forEach(id -> assertThat(UserClient.getOrDeleteUser(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.GET, id)).isNotNull());
		}
		@ParameterizedTest @MethodSource("args")
		public void whenGetUsersByUserName_thenOK(final Args args) {
			final List<User> created = UserClient.createOrUpdateUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final User[] got = UserClient.getOrDeleteFiltered(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.GET, UserClient.parameters("realm", TEST_REALM, "emailAddress", UserClient.emailAddresses(created)));
			assertThat(got).containsAll(created);
			UserClient.userIds(created).forEach(id -> assertThat(UserClient.getOrDeleteUser(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.GET, id)).isNotNull());
		}
		@ParameterizedTest @MethodSource("args")
		public void whenGetUsersByFirstName_thenOK(final Args args) {
			final List<User> created = UserClient.createOrUpdateUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final User[] got = UserClient.getOrDeleteFiltered(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.GET, UserClient.parameters("realm", TEST_REALM, "firstName", UserClient.firstNames(created)));
			assertThat(got).containsAll(created);
			UserClient.userIds(created).forEach(id -> assertThat(UserClient.getOrDeleteUser(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.GET, id)).isNotNull());
		}
		@ParameterizedTest @MethodSource("args")
		public void whenGetUsersByLastName_thenOK(final Args args) {
			final List<User> created = UserClient.createOrUpdateUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final User[] got = UserClient.getOrDeleteFiltered(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.GET, UserClient.parameters("realm", TEST_REALM, "lastName", UserClient.lastNames(created)));
			assertThat(got).containsAll(created);
			UserClient.userIds(created).forEach(id -> assertThat(UserClient.getOrDeleteUser(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.GET, id)).isNotNull());
		}
	}

	@Nested
	public class FilteredDeletes extends AbstractIT {
		private record Args(Integer count) { }
		static Stream<Args> args() {
			return Stream.of(new Args(1), new Args(2));
		}
		@ParameterizedTest @MethodSource("args")
		public void testDeleteAllTestRealmUsers(final Args args) {
			final List<User> created = UserClient.createOrUpdateUsers(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final User[] deleted = UserClient.getOrDeleteFiltered(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.DELETE, UserClient.parameters("realm", TEST_REALM));
			assertThat(deleted).containsAll(created);
			UserClient.userIds(created).forEach(id -> assertThat(UserClient.getOrDeleteUser(super.baseUrl, super.restAssuredOpsAdminCreds(), Method.GET, id)).isNull());
		}
	}
	/////////////////////////////
	// Constructor helper methods
	/////////////////////////////

	private User constructUser(final String realm) {
		return constructUsers(realm, 1).get(0);
	}

	private List<User> constructUsers(final String realm, final int count) {
		return LongStream.range(0, count).mapToObj((index) -> constructUser(realm, index)).toList();
	}

	private User constructUser(final String realm, final long index) {
		final long uniqueSuffix = UNIQUE_LONG.getAndIncrement() + index;
		final String username = "Username " + uniqueSuffix;
		final String password = "Password " + uniqueSuffix;
		final String emailAddress = "Email" + uniqueSuffix + "@example.com";
		final String firstName = "FirstName " + uniqueSuffix;
		final String middleName = "MiddleName " + uniqueSuffix;
		final String lastName = "LastName " + uniqueSuffix;
		final String rolesAndPrivileges = "ROLE_" + uniqueSuffix + ",PRIVILEGE_" + uniqueSuffix;
		final boolean isEnabled = true;
		final boolean isAccountNonExpired = true;
		final boolean isAccountNonLocked = true;
		final boolean isCredentialsNonExpired = true;
		return new User(realm, username, password, emailAddress, firstName, middleName, lastName, rolesAndPrivileges, isEnabled, isAccountNonExpired, isAccountNonLocked, isCredentialsNonExpired);
	}

	/////////////////////
	// Other util methods
	/////////////////////

	private void printResponseAndVerifyStatusCode(final Response response, final HttpStatus httpStatus) {
		logger.info("Response:\n{}", response.asPrettyString());
		assertThat(response.getStatusCode()).isEqualTo(httpStatus.value());
	}
}