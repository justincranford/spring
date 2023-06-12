package com.github.justincranford.spring.authn.server.api.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
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
import org.springframework.http.MediaType;
import org.springframework.web.util.UriComponentsBuilder;

import com.github.justincranford.spring.authn.server.AbstractIT;
import com.github.justincranford.spring.util.model.User;

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

		@ParameterizedTest
		@MethodSource("args")
		void testUsernameWithRealm(final Args args) throws Exception {
			final Response searchResponse = super.restAssuredOpsAdminCreds().get(usersFilteredUrl(args.realm(), List.of(args.username()), null, null, null));
			final User[] foundUsers = searchResponse.getBody().as(User[].class);
			logger.info("Search Response:\n{}", (Object[]) foundUsers);
			assertThat(searchResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			assertThat(foundUsers).isNotEmpty();
			assertThat(foundUsers.length).isEqualTo(1);
			assertThat(foundUsers[0].getUsername()).isEqualTo(args.username());
			assertThat(foundUsers[0].getRealm()).isEqualTo(args.realm());
		}

		@ParameterizedTest
		@MethodSource("args")
		void testUsernameWithoutRealm(final Args args) throws Exception {
			final Response searchResponse = super.restAssuredOpsAdminCreds().get(usersFilteredUrl(null, List.of(args.username()), null, null, null));
			final User[] foundUsers = searchResponse.getBody().as(User[].class);
			logger.info("Search Response:\n{}", (Object[]) foundUsers);
			assertThat(searchResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			assertThat(foundUsers).isNotEmpty();
			assertThat(foundUsers.length).isEqualTo(1);
			assertThat(foundUsers[0].getUsername()).isEqualTo(args.username());
		}
	}

	@Nested
	public class AuthenticationFailures extends AbstractIT {
		@Test
		public void testAuthenticationRequiredButNoCreds() throws Exception {
			final User user = createUser(constructUser(TEST_REALM));
			final Response response = this.restAssuredNoCreds.get(userUrl(TEST_REALM, user.getId()));
			logger.info("Response:\n{}", response.asPrettyString());
			assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
		}

		@Test
		public void testAuthenticationRequiredButInvalidCreds() throws Exception {
			final User user = createUser(constructUser(TEST_REALM));
			final Response response = this.restAssuredInvalidCreds.get(userUrl(TEST_REALM, user.getId()));
			logger.info("Response:\n{}", response.asPrettyString());
			assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
		}
	}

	@Nested
	public class AuthorizationFailures extends AbstractIT {
		@Test
		public void testAuthenticatedButMissingRole() throws Exception {
			final User user = createUser(constructUser(TEST_REALM));
			final Response response = super.restAssuredAppUserCreds().get(userUrl(TEST_REALM, user.getId()));
			logger.info("Response:\n{}", response.asPrettyString());
			assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
		}
	}

	@Nested
	public class SingleUsersTestRealm extends AbstractIT {
		@Test
		public void whenCreateNewUser_thenCreated() throws Exception {
			assertDoesNotThrow(() -> createUsers(constructUsers(TEST_REALM, 2)));
		}

		@Test
		public void whenGetUsersByIds_thenOK() throws Exception {
			final List<User> users = createUsers(constructUsers(TEST_REALM, 2));
			final Response response = super.restAssuredOpsAdminCreds().get(usersUrl(TEST_REALM, userIds(users)));
			final User[] getUsers = response.getBody().as(User[].class);
			logger.info("Get Response:\n{}", (Object[]) getUsers);
			assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			assertThat(getUsers).contains(users.toArray(new User[] { }));
		}

		@Test
		public void whenUpdateCreatedUser_thenUpdated() throws Exception {
			final User user = createUser(constructUser(TEST_REALM));
			user.setLastName("newLastName");
			final Response putResponse = super.restAssuredOpsAdminCreds().given().contentType(MediaType.APPLICATION_JSON_VALUE).body(user).put(userUrl(TEST_REALM, null));
			logger.info("Response:\n{}", putResponse.asPrettyString());
			assertThat(putResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			final Response getResponse = super.restAssuredOpsAdminCreds().get(userUrl(null, user.getId()));
			logger.info("Response:\n{}", getResponse.asPrettyString());
			assertThat(getResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			assertThat(getResponse.jsonPath().getString("lastName")).isEqualTo("newLastName");
		}

		@Test
		public void whenDeleteCreatedUser_thenOk() throws Exception {
			final User user = createUser(constructUser(TEST_REALM));
			final Response deleteResponse = super.restAssuredOpsAdminCreds().delete(userUrl(null, user.getId()));
			assertThat(deleteResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			final Response getResponse = super.restAssuredOpsAdminCreds().get(userUrl(null, user.getId()));
			logger.info("Response:\n{}", getResponse.asPrettyString());
			assertThat(getResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
		}

		@Test
		public void whenGetByNonExistingUserId_thenNotFound() throws Exception {
			final Response getResponse = super.restAssuredOpsAdminCreds().get(userUrl(null, UNIQUE_LONG.getAndIncrement()));
			logger.info("Response:\n{}", getResponse.asPrettyString());
			assertThat(getResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
		}

		@Test
		public void whenCreateUserInvalidLastName_thenError() throws Exception {
			final User user = constructUser(TEST_REALM);
			user.setLastName(null);
			final Response postResponse = super.restAssuredOpsAdminCreds().given().contentType(MediaType.APPLICATION_JSON_VALUE).body(user).post(userUrl(TEST_REALM, null));
			logger.info("Response:\n{}", postResponse.asPrettyString());
			assertThat(postResponse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		}
	}

	@Nested
	public class BulkUsersTestRealm extends AbstractIT {
		@Test
		public void testDeleteAllTestRealmUsers() throws Exception {
			final User user = createUser(constructUser(TEST_REALM));
			final Response deleteResponse = super.restAssuredOpsAdminCreds().delete(usersFilteredUrl(TEST_REALM, null, null, null, null));
			final User[] deletedUsers = deleteResponse.getBody().as(User[].class);
			logger.info("Delete Response:\n{}", (Object[]) deletedUsers);
			assertThat(deleteResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			final List<Long> deletedIds = Arrays.stream(deletedUsers).map(u -> u.getId()).toList();
			logger.info("Deleted IDs: {}", deletedIds);
			assertThat(deletedIds).contains(user.getId());
//			assertThat(deletedIds).isEqualTo(deleteResponse.jsonPath().getList("id"));
			for (final Long deletedId : deletedIds) {
				final Response getResponse = super.restAssuredOpsAdminCreds().get(userUrl(TEST_REALM, deletedId));
				assertThat(getResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
			}
		}

		@Test
		public void testFindAllTestRealmUsers() throws Exception {
			final User user = createUser(constructUser(TEST_REALM));
			final Response searchResponse = super.restAssuredOpsAdminCreds().get(usersFilteredUrl(TEST_REALM, null, null, null, null));
			final User[] foundUsers = searchResponse.getBody().as(User[].class);
			logger.info("Search Response:\n{}", (Object[]) foundUsers);
			assertThat(searchResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			final List<Long> foundIds = Arrays.stream(foundUsers).map(u -> u.getId()).toList();
			logger.info("Found IDs: {}", foundIds);
			assertThat(foundIds).contains(user.getId());
//			assertThat(foundIds).isEqualTo(searchResponse.jsonPath().getList("id"));
			for (final Long foundId : foundIds) {
				final Response getResponse = super.restAssuredOpsAdminCreds().get(userUrl(TEST_REALM, foundId));
				assertThat(getResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
				final User foundUser = getResponse.getBody().as(User.class);
				assertThat(foundUsers).contains(foundUser);
			}
		}

		@Test
		public void whenGetUsersFiltered_thenOK() throws Exception {
			final List<User> users = createUsers(constructUsers(TEST_REALM, 2));
			final Response response = super.restAssuredOpsAdminCreds().get(usersFilteredUrl(TEST_REALM, null, null, null, null));
			final User[] getUsers = response.getBody().as(User[].class);
			logger.info("Get Response:\n{}", (Object[]) getUsers);
			assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			assertThat(getUsers).contains(users.toArray(new User[] { }));
		}

		// TODO username
		// TODO emaiLAddress

		@Test
		public void whenGetUsersByFirstName_thenOK() throws Exception {
			final User user = createUser(constructUser(TEST_REALM));
			final Response searchResponse = super.restAssuredOpsAdminCreds().get(usersFilteredUrl(TEST_REALM, null, null, List.of(user.getFirstName()), null));
			logger.info("Response:\n{}", searchResponse.asPrettyString());
			assertThat(searchResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			@SuppressWarnings("unchecked")
			final List<User> getUsers = searchResponse.as(List.class);
			logger.info("Users: {}", getUsers);
			assertTrue(getUsers.size() > 0);
		}

		@Test
		public void whenGetUsersByLastName_thenOK() throws Exception {
			final User user = createUser(constructUser(TEST_REALM));
			final Response searchResponse = super.restAssuredOpsAdminCreds().get(usersFilteredUrl(TEST_REALM, null, null, null, List.of(user.getLastName())));
			logger.info("Response:\n{}", searchResponse.asPrettyString());
			assertThat(searchResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			@SuppressWarnings("unchecked")
			final List<User> getUsers = searchResponse.as(List.class);
			logger.info("Users: {}", getUsers);
			assertTrue(getUsers.size() > 0);
		}
	}

	//////////////////////////
	// URL path helper methods
	//////////////////////////

	private String userUrl(final String realm, final Long id) throws Exception {
		final String userUrl = super.baseUrl + "/api/user" + pathSuffix(id) + queryString(realm, (id == null? null : List.of(id)), null, null, null, null);
		logger.info("User URL: {}", userUrl);
		return userUrl;
	}

	private String usersUrl(final String realm, final List<Long> ids) throws Exception {
		final String usersUrl = super.baseUrl + "/api/users" + queryString(realm, ids, null, null, null, null);
		logger.info("Users URL: {}", usersUrl);
		return usersUrl;
	}

	private String usersFilteredUrl(
		final String realm,
		final List<String> usernames,
		final List<String> emailAddresses,
		final List<String> firstNames,
		final List<String> lastNames
	) throws Exception {
		final String usersFilteredUrl = super.baseUrl + "/api/users/filtered" + queryString(realm, null, usernames, emailAddresses, firstNames, lastNames);
		logger.info("Users filtered URL: {}", usersFilteredUrl);
		return usersFilteredUrl;
	}

	private String pathSuffix(final Long id) {
		return (id == null) ? "" : "/" + id;
	}

	//////////////////////////////
	// Query string helper methods
	//////////////////////////////

	private String queryString(
		final String realm,
		final List<Long> ids,
		final List<String> usernames,
		final List<String> emailAddresses,
		final List<String> firstNames,
		final List<String> lastNames
	) throws Exception {
	    final UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.newInstance();
		if (realm != null) {
			uriComponentsBuilder.queryParam("realm", realm);
		}
		putQueryParams(uriComponentsBuilder, "id", ids);
		putQueryParams(uriComponentsBuilder, "username", usernames);
		putQueryParams(uriComponentsBuilder, "emailAddress", emailAddresses);
		putQueryParams(uriComponentsBuilder, "firstName", firstNames);
		putQueryParams(uriComponentsBuilder, "lastName", lastNames);
		final String queryString = uriComponentsBuilder.build().getQuery();
		return (queryString == null) ? "" : "?" + queryString;
	}

	private void putQueryParams(
		final UriComponentsBuilder uriComponentsBuilder,
		final String name,
		final List<? extends Object> values
	) {
		if (values != null) {
			values.stream().forEach((value) -> {
				uriComponentsBuilder.queryParam(name, value);
			});
		}
	}

	//////////////////////
	// POST helper methods
	//////////////////////

	private User createUser(final User user) throws Exception {
		return createUsers(List.of(user)).get(0);
	}

	private List<User> createUsers(final List<User> users) throws Exception {
		assertNotNull(users);
		users.forEach(user -> { assertThat(user).isNotNull(); assertThat(user.getId()).isLessThanOrEqualTo(0L); });
		if (users.size() == 1) {
			final Response postResponse = super.restAssuredOpsAdminCreds().contentType(MediaType.APPLICATION_JSON_VALUE).body(users.get(0)).post(userUrl(null, null));
			assertThat(postResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED.value());
			final User createdUser = postResponse.as(User.class);
			logger.info("Created User: {}", createdUser);
			return List.of(createdUser);
		}
		final Response postResponse = super.restAssuredOpsAdminCreds().given().when().contentType(MediaType.APPLICATION_JSON_VALUE).body(users).post(usersUrl(null, null));
		assertThat(postResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED.value());
		List<User> createdUsers = postResponse.jsonPath().getList(".", User.class);
		logger.info("Created Users: {}", createdUsers);
		return createdUsers;
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

	///////////////////////
	// Other helper methods
	///////////////////////

	private List<Long> userIds(final List<User> users) {
		return users.stream().map(user -> user.getId()).toList();
	}
}