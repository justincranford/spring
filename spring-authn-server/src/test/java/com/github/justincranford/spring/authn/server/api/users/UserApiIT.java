package com.github.justincranford.spring.authn.server.api.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.LongStream;
import java.util.stream.Stream;

import org.apache.logging.log4j.util.Strings;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import com.github.justincranford.spring.authn.server.AbstractIT;
import com.github.justincranford.spring.util.model.User;

import io.restassured.path.json.JsonPath;
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
		void testUsernameWithRealm(final Args args) {
			final String url = super.baseUrl + "/api/users/filtered?realm=" + args.realm() + "&username=" + args.username();
			logger.info("Search URL: {}", url);
			final Response searchResponse = super.restAssuredOpsAdminCreds().get(url);
			final User[] foundUsers = searchResponse.getBody().as(User[].class);
			logger.info("Search Response:\n{}", (Object[]) foundUsers);
			assertThat(searchResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			assertThat(foundUsers).isNotEmpty();
			assertThat(foundUsers.length).isEqualTo(1);
			assertThat(foundUsers[0].getRealm()).isEqualTo(args.realm());
			assertThat(foundUsers[0].getUsername()).isEqualTo(args.username());
		}

		@ParameterizedTest
		@MethodSource("args")
		void testUsernameWithoutRealm(final Args args) {
			final String url = super.baseUrl + "/api/users/filtered?username=" + args.username();
			logger.info("Search URL: {}", url);
			final Response searchResponse = super.restAssuredOpsAdminCreds().get(url);
			final User[] foundUsers = searchResponse.getBody().as(User[].class);
			logger.info("Search Response:\n{}", (Object[]) foundUsers);
			assertThat(searchResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			assertThat(foundUsers).isNotEmpty();
			assertThat(foundUsers.length).isEqualTo(1);
			assertThat(foundUsers[0].getUsername()).isEqualTo(args.username());
		}
	}

	@Nested
	public class BulkUsersTestRealm extends AbstractIT {
		@Test
		public void testDeleteAllTestRealmUsers() {
			final User user = createUser(constructUser(TEST_REALM));
			final Response deleteResponse = super.restAssuredOpsAdminCreds().delete(usersFilteredUrl(TEST_REALM));
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
		public void testFindAllTestRealmUsers() {
			final User user = createUser(constructUser(TEST_REALM));
			final Response searchResponse = super.restAssuredOpsAdminCreds().get(usersFilteredUrl(TEST_REALM));
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
	}

	@Nested
	public class FailurePath extends AbstractIT {
		@Test
		public void testAuthenticationRequiredButNoCreds() {
			final User user = createUser(constructUser(TEST_REALM));
			final String url = super.baseUrl + "/api/user/" + user.getId();
			logger.info("URL: {}", url);
			final Response response = this.restAssuredNoCreds.get(super.baseUrl + "/api/user" + user.getId());
			logger.info("Response:\n{}", response.asPrettyString());
			assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
		}

		@Test
		public void testAuthenticationRequiredButInvalidCreds() {
			final User user = createUser(constructUser(TEST_REALM));
			final String url = super.baseUrl + "/api/user/" + user.getId();
			logger.info("URL: {}", url);
			final Response response = this.restAssuredInvalidCreds.get(super.baseUrl + "/api/user" + user.getId());
			logger.info("Response:\n{}", response.asPrettyString());
			assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
		}

		@Test
		public void testAuthenticatedButMissingRole() {
			final User user = createUser(constructUser(TEST_REALM));
			final String url = super.baseUrl + "/api/user/" + user.getId();
			logger.info("URL: {}", url);
			final Response response = super.restAssuredAppUserCreds().get(url);
			logger.info("Response:\n{}", response.asPrettyString());
			assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
		}
	}

	@Nested
	public class SingleUsersTestRealm extends AbstractIT {
		@Test
		public void whenCreateNewUser_thenCreated() {
			assertDoesNotThrow(() -> createUser(constructUser(TEST_REALM)));
		}

		@Test
		public void whenGetAllUsers_thenOK() {
			final User user = createUser(constructUser(TEST_REALM));
			final String url = super.baseUrl + "/api/users/filtered?realm=" + TEST_REALM;
			logger.info("URL: {}", url);
			final Response response = super.restAssuredOpsAdminCreds().get(url);
			logger.info("Response:\n{}", response.asPrettyString());
			assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());
		}

		@Test
		public void whenGetUsersByFirstName_thenOK() {
			final User user = createUser(constructUser(TEST_REALM));
			final String url = super.baseUrl + "/api/users/filtered?realm=" + TEST_REALM + "&firstName=" + user.getFirstName();
			logger.info("URL: {}", url);
			final Response searchResponse = super.restAssuredOpsAdminCreds().get(url);
			logger.info("Response:\n{}", searchResponse.asPrettyString());
			assertThat(searchResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			@SuppressWarnings("unchecked")
			final List<User> getUsers = searchResponse.as(List.class);
			logger.info("Users: {}", getUsers);
			assertTrue(getUsers.size() > 0);
		}

		@Test
		public void whenGetUsersByLastName_thenOK() {
			final User user = createUser(constructUser(TEST_REALM));
			final String url = super.baseUrl + "/api/users/filtered?realm=" + TEST_REALM + "&lastName=" + user.getLastName();
			logger.info("URL: {}", url);
			final Response searchResponse = super.restAssuredOpsAdminCreds().get(url);
			logger.info("Response:\n{}", searchResponse.asPrettyString());
			assertThat(searchResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			@SuppressWarnings("unchecked")
			final List<User> getUsers = searchResponse.as(List.class);
			logger.info("Users: {}", getUsers);
			assertTrue(getUsers.size() > 0);
		}

		@Test
		public void whenGetCreatedUsersById_thenOK() {
			final List<User> users = createUsers(constructUsers(TEST_REALM, 2));
			final String url = usersUrl(TEST_REALM, users.stream().map(user -> user.getId()).toList());
			logger.info("URL: {}", url);
			final Response getResponse = super.restAssuredOpsAdminCreds().get(url);
			logger.info("Response:\n{}", getResponse.asPrettyString());
			assertThat(getResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			for (int b = 0; b < users.size(); b++) {
				final User user = users.get(b);
				final JsonPath jsonPath = getResponse.jsonPath();
				assertThat(jsonPath.getString("[" + b + "].firstName")).isEqualTo(user.getFirstName());
				assertThat(jsonPath.getString("[" + b + "].lastName")).isEqualTo(user.getLastName());
			}
		}

		@Test
		public void whenGetNotExistingUserById_thenNotFound() {
			final String userUrl = super.baseUrl + "/api/user/" + UNIQUE_LONG.getAndIncrement();
			logger.info("URL: {}", userUrl);
			final Response getResponse = super.restAssuredOpsAdminCreds().get(userUrl);
			logger.info("Response:\n{}", getResponse.asPrettyString());
			assertThat(getResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
		}

		@Test
		public void whenInvalidUser_thenError() {
			final User user = constructUser(TEST_REALM);
			user.setLastName(null);
			final String userUrl = super.baseUrl + "/api/user";
			logger.info("URL: {}", userUrl);
			final Response postResponse = super.restAssuredOpsAdminCreds().given().contentType(MediaType.APPLICATION_JSON_VALUE).body(user).post(userUrl);
			logger.info("Response:\n{}", postResponse.asPrettyString());
			assertThat(postResponse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		}

		@Test
		public void whenUpdateCreatedUser_thenUpdated() {
			final User user = createUser(constructUser(TEST_REALM));
			user.setLastName("newLastName");
			final String updateUrl = super.baseUrl + "/api/user";
			logger.info("Update URL: {}", updateUrl);
			final Response putResponse = super.restAssuredOpsAdminCreds().given().contentType(MediaType.APPLICATION_JSON_VALUE).body(user).put(updateUrl);
			logger.info("Response:\n{}", putResponse.asPrettyString());
			assertThat(putResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			final String getUrl = userUrl(null, user.getId());
			logger.info("Get URL: {}", updateUrl);
			final Response getResponse = super.restAssuredOpsAdminCreds().get(getUrl);
			logger.info("Response:\n{}", getResponse.asPrettyString());
			assertThat(getResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			assertThat(getResponse.jsonPath().getString("lastName")).isEqualTo("newLastName");
		}

		@Test
		public void whenDeleteCreatedUser_thenOk() {
			final User user = createUser(constructUser(TEST_REALM));
			logger.info("User: {}", user);
			final String getUrl = userUrl(null, user.getId());
			logger.info("URL: {}", getUrl);
			final Response deleteResponse = super.restAssuredOpsAdminCreds().delete(getUrl);
			logger.info("Response:\n{}", deleteResponse.asPrettyString());
			assertThat(deleteResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			final Response getResponse = super.restAssuredOpsAdminCreds().get(getUrl);
			logger.info("Response:\n{}", getResponse.asPrettyString());
			assertThat(getResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
		}
	}

	/////////////////////
	// URL helper methods
	/////////////////////

	private String userUrl(final String realm, final Long id) {
		final String userUrl = super.baseUrl + "/api/user" + pathSuffix(id) + queryString(realm, null);
		logger.info("User URL: {}", userUrl);
		return userUrl;
	}

	private String usersUrl(final String realm, final List<Long> ids) {
		final String usersUrl = super.baseUrl + "/api/users" + queryString(realm, ids);
		logger.info("Users URL: {}", usersUrl);
		return usersUrl;
	}

	private String usersFilteredUrl(final String realm) {
		final String usersFilteredUrl = super.baseUrl + "/api/users/filtered" + queryString(realm, null);
		logger.info("Users filtered URL: {}", usersFilteredUrl);
		return usersFilteredUrl;
	}

	private String pathSuffix(final Long id) {
		return (id == null) ? "" : "/" + id;
	}

	private String queryString(final String realm, final List<Long> ids) {
		final List<String> queryParams = new ArrayList<>();
		if (realm != null) {
			queryParams.add("realm=" + URLEncoder.encode(realm, StandardCharsets.UTF_8));
		}
		if (ids != null) {
			ids.stream().forEach((id) -> {
				assertThat(id).isNotNull();
				queryParams.add("id=" + id); // ASSUME: Long.toString() is URL safe
			});
		}
		return queryParams.isEmpty() ? "" : "?" + Strings.join(queryParams, '&');
	}

	//////////////////////
	// POST helper methods
	//////////////////////

	private User createUser(final User user) {
		return createUsers(List.of(user)).get(0);
	}

	private List<User> createUsers(final List<User> users) {
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
}