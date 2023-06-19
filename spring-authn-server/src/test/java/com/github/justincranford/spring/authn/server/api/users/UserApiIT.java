package com.github.justincranford.spring.authn.server.api.users;

import static com.github.justincranford.spring.util.model.UserUtils.emailAddresses;
import static com.github.justincranford.spring.util.model.UserUtils.firstNames;
import static com.github.justincranford.spring.util.model.UserUtils.lastNames;
import static com.github.justincranford.spring.util.model.UserUtils.userIds;
import static com.github.justincranford.spring.util.model.UserUtils.usernames;
import static com.github.justincranford.spring.util.rest.RestClient.merge;
import static com.github.justincranford.spring.util.rest.RestClient.parameters;
import static com.github.justincranford.spring.util.rest.RestClient.ApiType.SINGLE;
import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Arrays;
import java.util.stream.LongStream;
import java.util.stream.Stream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;

import com.github.justincranford.spring.authn.server.AbstractIT;
import com.github.justincranford.spring.authn.server.model.RestApi;
import com.github.justincranford.spring.authn.server.model.WellKnownRealmsAndUsers;
import com.github.justincranford.spring.util.model.User;
import com.github.justincranford.spring.util.rest.RestClient;
import com.github.justincranford.spring.util.rest.RestClient.HttpResponseException;

@SuppressWarnings({"unused"})
public class UserApiIT extends AbstractIT {
	private Logger logger = LoggerFactory.getLogger(UserApiIT.class);
	private static final String TEST_REALM = "Test";

	private RestApi<User> userApiOpsAdmin()     { return new RestApi<User>(User.class, super.restClientOpsAdmin());     }
	private RestApi<User> userApiOpsUser()      { return new RestApi<User>(User.class, super.restClientOpsUser());      }
	private RestApi<User> userApiAppAdmin()     { return new RestApi<User>(User.class, super.restClientAppAdmin());     }
	private RestApi<User> userApiAppUser()      { return new RestApi<User>(User.class, super.restClientAppUser());      }
	private RestApi<User> userApiNoCreds()      { return new RestApi<User>(User.class, super.restClientNoCreds());      }
	private RestApi<User> userApiInvalidCreds() { return new RestApi<User>(User.class, super.restClientInvalidCreds()); }

	@Nested
	@TestInstance(Lifecycle.PER_CLASS)
	public class FindWellKnownRealmsAndUsers extends AbstractIT {
		private record Args(String realm, String username) { }

		@Autowired
		private WellKnownRealmsAndUsers wellKnownRealmsAndUsers;

		public Stream<Args> args() {
			return this.wellKnownRealmsAndUsers.realmAndUsernamePairs().stream().map(pair -> new Args(pair.realm(), pair.username()));
		}
		@ParameterizedTest @MethodSource("args")
		void whenGetWellKnownUserByUserNameAndRealm_thenOK(final Args args) throws Exception {
			verify(args, userApiOpsAdmin().getOrDelete("GET", RestClient.parameters("realm", args.realm(), "username", args.username())));
		}
		@ParameterizedTest @MethodSource("args")
		void whenGetWellKnownUserByUserName_thenOK(final Args args) throws Exception {
			verify(args, userApiOpsAdmin().getOrDelete("GET", RestClient.parameters("username", args.username())));
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
		public void whenGetUserNoCredentials_thenUnauthorized() throws Exception {
			final User user = requireNonNull(userApiOpsAdmin().createOrUpdate("POST", constructUser(TEST_REALM), parameters("realm", TEST_REALM)));
			final HttpResponse<?> response = restClientNoCreds().doRequest(userApiNoCreds().url(SINGLE, parameters("id", user.getId())), "GET", null, BodyPublishers.noBody(), BodyHandlers.ofString());
			printResponseAndVerifyStatusCode(response, HttpStatus.UNAUTHORIZED);
		}
		@Test
		public void whenGetUserInvalidCredentials_thenUnauthorized() throws Exception {
			final User user = requireNonNull(userApiOpsAdmin().createOrUpdate("POST", constructUser(TEST_REALM), parameters("realm", TEST_REALM)));
			final HttpResponse<?> response = restClientNoCreds().doRequest(userApiNoCreds().url(SINGLE, merge(parameters("realm", TEST_REALM), "id", user.getId())), "GET", null, BodyPublishers.noBody(), BodyHandlers.ofString());
			printResponseAndVerifyStatusCode(response, HttpStatus.UNAUTHORIZED);
		}
	}

	@Nested
	public class AuthorizationErrors extends AbstractIT {
		@Test
		public void whenGetUserValidCredentialsInvalidAuthorities_thenForbidden() throws Exception {
			final User user = userApiOpsAdmin().createOrUpdate("POST", constructUser(TEST_REALM), parameters("realm", TEST_REALM));
			final HttpResponse<?> response = restClientAppUser().doRequest(userApiNoCreds().url(SINGLE, merge(parameters("realm", TEST_REALM), "id", user.getId())), "GET", null, BodyPublishers.noBody(), BodyHandlers.ofString());
			printResponseAndVerifyStatusCode(response, HttpStatus.FORBIDDEN);
		}
	}

	@Nested
	public class CrudErrors extends AbstractIT {
		private record Args(Integer count) { }
		static Stream<Args> args() {
			return Stream.of(new Args(1), new Args(2));
		}
		@ParameterizedTest @MethodSource("args")
		public void whenInvalidCreate_thenError(final Args args) throws Exception {
			final User[] invalid = LongStream.rangeClosed(1, args.count()).mapToObj((offset) -> constructUser(TEST_REALM)).toArray(User[]::new);
			Arrays.stream(invalid).forEach(user -> user.setLastName(null));
			final HttpResponseException e = assertThrows(HttpResponseException.class, () -> userApiOpsAdmin().createOrUpdate("POST", invalid, parameters("realm", TEST_REALM)));
			assertThat(e.statusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		}
		@ParameterizedTest @MethodSource("args")
		public void whenInvalidRead_thenNotFound(final Args args) throws Exception {
			final Long[] invalidIds = LongStream.rangeClosed(1, args.count()).map((offset) -> UNIQUE_LONG.getAndIncrement()).boxed().toArray(Long[]::new);
			final HttpResponseException e = assertThrows(HttpResponseException.class, () -> userApiOpsAdmin().getOrDelete("GET", invalidIds, parameters("realm", TEST_REALM)));
			assertThat(e.statusCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
		}
		@ParameterizedTest @MethodSource("args")
		public void whenInvalidUpdate_thenError(final Args args) throws Exception {
			final User[] created = userApiOpsAdmin().createOrUpdate("POST", constructUsers(TEST_REALM, args.count()), parameters("realm", TEST_REALM));
			final User[] modified = Arrays.stream(created).map((user) -> {
				final User copy = new User(user);
				copy.setLastName(null);
				return copy;
			}).toArray(User[]::new);
			final HttpResponseException e = assertThrows(HttpResponseException.class, () -> userApiOpsAdmin().createOrUpdate("PUT", modified, parameters("realm", TEST_REALM)));
			assertThat(e.statusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		}
		@ParameterizedTest @MethodSource("args")
		public void whenInvalidDelete_thenError(final Args args) throws Exception {
			final Long[] invalidIds = LongStream.rangeClosed(1, args.count()).map((offset) -> UNIQUE_LONG.getAndIncrement()).boxed().toArray(Long[]::new);
			final HttpResponseException e = assertThrows(HttpResponseException.class, () -> userApiOpsAdmin().getOrDelete("DELETE", invalidIds, parameters("realm", TEST_REALM)));
			assertThat(e.statusCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
		}
	}

	@Nested
	public class CrudSuccess extends AbstractIT {
		private record Args(Integer count) { }
		static Stream<Args> args() {
			return Stream.of(new Args(1), new Args(2));
		}
		@ParameterizedTest @MethodSource("args")
		public void whenCreate_thenCreated(final Args args) throws Exception {
			assertDoesNotThrow(() -> userApiOpsAdmin().createOrUpdate("POST", constructUsers(TEST_REALM, args.count()), parameters("realm", TEST_REALM)));
		}
		@ParameterizedTest @MethodSource("args")
		public void whenReadByIds_thenOK(final Args args) throws Exception {
			final User[] created = userApiOpsAdmin().createOrUpdate("POST", constructUsers(TEST_REALM, args.count()), parameters("realm", TEST_REALM));
			final User[] get = userApiOpsAdmin().getOrDelete("GET", userIds(created), parameters("realm", TEST_REALM));
			assertThat(get).contains(created);
		}
		@ParameterizedTest @MethodSource("args")
		public void whenUpdate_thenOK(final Args args) throws Exception {
			final User[] created = userApiOpsAdmin().createOrUpdate("POST", constructUsers(TEST_REALM, args.count()), parameters("realm", TEST_REALM));
			final User[] modified = Arrays.stream(created).map((user) -> {
				final User copy = new User(user);
				copy.setLastName("newLastName");
				return copy;
			}).toArray(User[]::new);
			final User[] updated = userApiOpsAdmin().createOrUpdate("PUT", modified, parameters("realm", TEST_REALM));
			Arrays.stream(updated).forEach((user) -> assertThat(user.getLastName()).isEqualTo("newLastName"));
			final User[] get = userApiOpsAdmin().getOrDelete("GET", userIds(created), parameters("realm", TEST_REALM));
			assertThat(get).isEqualTo(updated);
			assertThat(get).isNotEqualTo(created);
		}
		@ParameterizedTest @MethodSource("args")
		public void whenDeleteByIds_thenOk(final Args args) throws Exception {
			final User[] created = userApiOpsAdmin().createOrUpdate("POST", constructUsers(TEST_REALM, args.count()), parameters("realm", TEST_REALM));
			final User[] deleted = userApiOpsAdmin().getOrDelete("DELETE", userIds(created), parameters("realm", TEST_REALM));
			assertThat(deleted).contains(created);
			final HttpResponseException e = assertThrows(HttpResponseException.class, () -> userApiOpsAdmin().getOrDelete("GET", userIds(created), parameters("realm", TEST_REALM)));
			assertThat(e.statusCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
		}
	}

	@Nested
	public class FilteredReadsSuccess extends AbstractIT {
		private record Args(Integer count) { }
		static Stream<Args> args() {
			return Stream.of(new Args(1), new Args(2));
		}
		@ParameterizedTest @MethodSource("args")
		public void testGetAllUsers_thenOK(final Args args) throws Exception {
			final User[] created = userApiOpsAdmin().createOrUpdate("POST", constructUsers(TEST_REALM, args.count()), parameters("realm", TEST_REALM));
			final User[] got = userApiOpsAdmin().getOrDelete("GET", RestClient.parameters("realm", TEST_REALM));
			assertThat(got).contains(created);
			Arrays.stream(userIds(created)).forEach(id -> {
				try {
					assertThat(userApiOpsAdmin().getOrDelete("GET", id, parameters("realm", TEST_REALM))).isNotNull();
				} catch (Exception e) {
					Assertions.fail(e);
				}
			});
		}
		@ParameterizedTest @MethodSource("args")
		public void whenGetUsersByEmailAddresses_thenOK(final Args args) throws Exception {
			final User[] created = userApiOpsAdmin().createOrUpdate("POST", constructUsers(TEST_REALM, args.count()), parameters("realm", TEST_REALM));
			final User[] got = userApiOpsAdmin().getOrDelete("GET", merge(parameters("realm", TEST_REALM), "username", usernames(created)));
			assertThat(got).contains(created);
			Arrays.stream(userIds(created)).forEach(id -> {
				try {
					assertThat(userApiOpsAdmin().getOrDelete("GET", id, parameters("realm", TEST_REALM))).isNotNull();
				} catch (Exception e) {
					Assertions.fail(e);
				}
			});
		}
		@ParameterizedTest @MethodSource("args")
		public void whenGetUsersByUserName_thenOK(final Args args) throws Exception {
			final User[] created = userApiOpsAdmin().createOrUpdate("POST", constructUsers(TEST_REALM, args.count()), parameters("realm", TEST_REALM));
			final User[] got = userApiOpsAdmin().getOrDelete("GET", merge(parameters("realm", TEST_REALM), "emailAddress", emailAddresses(created)));
			assertThat(got).contains(created);
			Arrays.stream(userIds(created)).forEach(id -> {
				try {
					assertThat(userApiOpsAdmin().getOrDelete("GET", id, parameters("realm", TEST_REALM))).isNotNull();
				} catch (Exception e) {
					Assertions.fail(e);
				}
			});
		}
		@ParameterizedTest @MethodSource("args")
		public void whenGetUsersByFirstName_thenOK(final Args args) throws Exception {
			final User[] created = userApiOpsAdmin().createOrUpdate("POST", constructUsers(TEST_REALM, args.count()), parameters("realm", TEST_REALM));
			final User[] got = userApiOpsAdmin().getOrDelete("GET", merge(parameters("realm", TEST_REALM), "firstName", firstNames(created)));
			assertThat(got).contains(created);
			Arrays.stream(userIds(created)).forEach(id -> {
				try {
					assertThat(userApiOpsAdmin().getOrDelete("GET", id, parameters("realm", TEST_REALM))).isNotNull();
				} catch (Exception e) {
					Assertions.fail(e);
				}
			});
		}
		@ParameterizedTest @MethodSource("args")
		public void whenGetUsersByLastName_thenOK(final Args args) throws Exception {
			final User[] created = userApiOpsAdmin().createOrUpdate("POST", constructUsers(TEST_REALM, args.count()), parameters("realm", TEST_REALM));
			final User[] got = userApiOpsAdmin().getOrDelete("GET", merge(parameters("realm", TEST_REALM), "lastName", lastNames(created)));
			assertThat(got).contains(created);
			Arrays.stream(userIds(created)).forEach(id -> {
				try {
					assertThat(userApiOpsAdmin().getOrDelete("GET", id, parameters("realm", TEST_REALM))).isNotNull();
				} catch (Exception e) {
					Assertions.fail(e);
				}
			});
		}
	}

	@Nested
	public class FilteredDeletesSuccess extends AbstractIT {
		private record Args(Integer count) { }
		static Stream<Args> args() {
			return Stream.of(new Args(1), new Args(2));
		}
		@ParameterizedTest @MethodSource("args")
		public void testDeleteAllTestRealmUsers(final Args args) throws Exception {
			final User[] created = userApiOpsAdmin().createOrUpdate("POST", constructUsers(TEST_REALM, args.count()), parameters("realm", TEST_REALM));
			final User[] deleted = userApiOpsAdmin().getOrDelete("DELETE", RestClient.parameters("realm", TEST_REALM));
			assertThat(deleted).contains(created);
			Arrays.stream(userIds(created)).forEach(id -> {
				final HttpResponseException e = assertThrows(HttpResponseException.class, () -> userApiOpsAdmin().getOrDelete("GET", id, parameters("realm", TEST_REALM)));
				assertThat(e.statusCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
			});
		}
	}

	@Nested
	@TestInstance(Lifecycle.PER_CLASS)
	public class FilteredDeletesProtectedRealmErrors extends AbstractIT {
		private record Args(String realm) { }

		@Autowired
		private WellKnownRealmsAndUsers wellKnownRealmsAndUsers;

		public Stream<Args> args() {
			return this.wellKnownRealmsAndUsers.realms().stream().map(realm -> new Args(realm));
		}

		@ParameterizedTest @MethodSource("args")
		public void whenDeleteUsersByProtectedRealm_thenError(final Args args) throws Exception {
			final Exception e = assertThrows(Exception.class, () -> userApiOpsAdmin().getOrDelete("DELETE", RestClient.parameters("realm", args.realm())));
			logger.info("Exception: ", e);
			assertThat(e.getMessage()).contains("Delete by realm ['" + args.realm() + "'] not allowed.");
		}
		@ParameterizedTest @MethodSource("args")
		public void whenDeleteUserByProtectedRealm_thenError(final Args args) throws Exception {
			final User created = requireNonNull(userApiOpsAdmin().createOrUpdate("POST", constructUser(args.realm()), parameters("realm", args.realm())));
			final User[] deleted = assertDoesNotThrow(() -> userApiOpsAdmin().getOrDelete("DELETE", RestClient.parameters("realm", args.realm(), "username", created.getUsername())));
			assertThat(deleted).contains(created);
			final HttpResponseException e = assertThrows(HttpResponseException.class, () -> userApiOpsAdmin().getOrDelete("GET", userIds(created), parameters("realm", args.realm())));
			assertThat(e.statusCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
		}
	}

	@Nested
	public class FilteredDeletesUnknownValueErrors extends AbstractIT {
		@Test
		public void whenDeleteUsersByUnknownRealm_thenEmpty() throws Exception {
			final User[] deleted = userApiOpsAdmin().getOrDelete("DELETE", merge(parameters("realm", "doesNotExist")));
			assertThat(deleted).isEmpty();
		}
		@Test
		public void whenDeleteUsersByUnknownUsername_thenEmpty() throws Exception {
			final User[] deleted = userApiOpsAdmin().getOrDelete("DELETE", merge(parameters("realm", TEST_REALM, "username", "doesNotExist")));
			assertThat(deleted).isEmpty();
		}
	}

	/////////////////////////////
	// Constructor helper methods
	/////////////////////////////

	private User constructUser(final String realm) {
		return constructUsers(realm, 1)[0];
	}

	private User[] constructUsers(final String realm, final int count) {
		return LongStream.range(0, count).mapToObj((index) -> constructUser(realm, index)).toArray(User[]::new);
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

	private void printResponseAndVerifyStatusCode(HttpResponse<?> response, final HttpStatus httpStatus) {
		logger.info("Response:\n{}", response.body());
		assertThat(response.statusCode()).isEqualTo(httpStatus.value());
	}
}