package com.github.justincranford.spring.authn.server.api.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

public class UserApiIT {
	private Logger logger = LoggerFactory.getLogger(UserApiIT.class);

	@Nested
	public class WellKnownRealmsAndUsers extends AbstractIT {
		private record Args(String realm, String username) { }
		public static Stream<Args> args() {
			return Stream.of(new Args("ops", "opsadmin"), new Args("ops", "opsuser"), new Args("app", "appadmin"), new Args("app", "appuser"));
		}

		@ParameterizedTest
		@MethodSource("args")
		public void testUsernameWithRealm(final Args args) {
			final String realm = args.realm();
			final String username = args.username();
			final String url = super.baseUrl + "/api/users/filtered?realm=" + realm + "&username=" + username;
			logger.info("Search URL: {}", url);
			final Response searchResponse = super.restAssuredOpsAdminCreds().get(url);
			final User[] foundUsers = searchResponse.getBody().as(User[].class);
			logger.info("Search Response:\n{}", (Object[]) foundUsers);
			assertThat(searchResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			assertThat(foundUsers).isNotEmpty();
			assertThat(foundUsers.length).isEqualTo(1);
			assertThat(foundUsers[0].getRealm()).isEqualTo(realm);
			assertThat(foundUsers[0].getUsername()).isEqualTo(username);
		}

		@ParameterizedTest
		@MethodSource("args")
		public void testUsernameWithoutRealm(final Args args) {
			final String username = args.username();
			final String url = super.baseUrl + "/api/users/filtered?username=" + username;
			logger.info("Search URL: {}", url);
			final Response searchResponse = super.restAssuredOpsAdminCreds().get(url);
			final User[] foundUsers = searchResponse.getBody().as(User[].class);
			logger.info("Search Response:\n{}", (Object[]) foundUsers);
			assertThat(searchResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			assertThat(foundUsers).isNotEmpty();
			assertThat(foundUsers.length).isEqualTo(1);
			assertThat(foundUsers[0].getUsername()).isEqualTo(username);
		}
	}

	@Nested
	public class UseTestRealm extends AbstractIT {
		private static final String REALM = "Test";

		@Test
		public void testDeleteAllTestRealmUsers() {
			final User user = postUser(constructUser());
			final String deleteUrl = super.baseUrl + "/api/users/filtered?realm=" + REALM;
			logger.info("Delete URL: {}", deleteUrl);
			final Response deleteResponse = super.restAssuredOpsAdminCreds().delete(deleteUrl);
			final User[] deletedUsers = deleteResponse.getBody().as(User[].class);
			logger.info("Delete Response:\n{}", (Object[]) deletedUsers);
			assertThat(deleteResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			final List<Long> deletedIds = Arrays.stream(deletedUsers).map(u -> u.getId()).toList();
			logger.info("Deleted IDs: {}", deletedIds);
			assertThat(deletedIds).contains(user.getId());
//			assertThat(deletedIds).isEqualTo(deleteResponse.jsonPath().getList("id"));
			for (final Long deletedId : deletedIds) {
				final String getUrl = super.baseUrl + "/api/user/" + deletedId;
				logger.info("Get URL: {}", getUrl);
				final Response getResponse = super.restAssuredOpsAdminCreds().get(getUrl);
				assertThat(getResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
			}
		}

		@Test
		public void testFindAllTestRealmUsers() {
			final User user = postUser(constructUser());
			final String searchUrl = super.baseUrl + "/api/users/filtered?realm=" + REALM;
			logger.info("Search URL: {}", searchUrl);
			final Response searchResponse = super.restAssuredOpsAdminCreds().get(searchUrl);
			final User[] foundUsers = searchResponse.getBody().as(User[].class);
			logger.info("Search Response:\n{}", (Object[]) foundUsers);
			assertThat(searchResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			final List<Long> foundIds = Arrays.stream(foundUsers).map(u -> u.getId()).toList();
			logger.info("Found IDs: {}", foundIds);
			assertThat(foundIds).contains(user.getId());
//			assertThat(foundIds).isEqualTo(searchResponse.jsonPath().getList("id"));
			for (final Long foundId : foundIds) {
				final String getUrl = super.baseUrl + "/api/user/" + foundId;
				logger.info("Get URL: {}", getUrl);
				final Response getResponse = super.restAssuredOpsAdminCreds().get(getUrl);
				assertThat(getResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
				final User foundUser = getResponse.getBody().as(User.class);
				assertThat(foundUsers).contains(foundUser);
			}
		}

		@Test
		public void testAuthenticationRequiredButNoCreds() {
			final User user = postUser(constructUser());
			final String url = super.baseUrl + "/api/user/" + user.getId();
			logger.info("URL: {}", url);
			final Response response = this.restAssuredNoCreds.get(super.baseUrl + "/api/user" + user.getId());
			logger.info("Response:\n{}", response.asPrettyString());
			assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
		}

		@Test
		public void testAuthenticationRequiredButInvalidCreds() {
			final User user = postUser(constructUser());
			final String url = super.baseUrl + "/api/user/" + user.getId();
			logger.info("URL: {}", url);
			final Response response = this.restAssuredInvalidCreds.get(super.baseUrl + "/api/user" + user.getId());
			logger.info("Response:\n{}", response.asPrettyString());
			assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
		}

		@Test
		public void testAuthenticatedButMissingRole() {
			final User user = postUser(constructUser());
			final String url = super.baseUrl + "/api/user/" + user.getId();
			logger.info("URL: {}", url);
			final Response response = super.restAssuredAppUserCreds().get(url);
			logger.info("Response:\n{}", response.asPrettyString());
			assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
		}

		@Test
		public void whenGetAllUsers_thenOK() {
			final User user = postUser(constructUser());
			final String url = super.baseUrl + "/api/users/filtered?realm=" + REALM;
			logger.info("URL: {}", url);
			final Response response = super.restAssuredOpsAdminCreds().get(url);
			logger.info("Response:\n{}", response.asPrettyString());
			assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());
		}

		@Test
		public void whenGetUsersByFirstName_thenOK() {
			final User user = postUser(constructUser());
			final String url = super.baseUrl + "/api/users/filtered?realm=" + REALM + "&firstName=" + user.getFirstName();
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
			final User user = postUser(constructUser());
			final String url = super.baseUrl + "/api/users/filtered?realm=" + REALM + "&lastName=" + user.getLastName();
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
			final List<User> users = postUsers(constructUsers(1)); // TODO 3 users
			logger.info("Users: {}", users);
			final String url = urlGetUsersByIds(users);
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
		public void whenCreateNewUser_thenCreated() {
			final User user = constructUser();
			final String userUrl = super.baseUrl + "/api/user";
			logger.info("URL: {}", userUrl);
			final Response postResponse = super.restAssuredOpsAdminCreds().given().contentType(MediaType.APPLICATION_JSON_VALUE).body(user).post(userUrl);
			logger.info("Response:\n{}", postResponse.asPrettyString());
			assertThat(postResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED.value());
		}

		@Test
		public void whenInvalidUser_thenError() {
			final User user = constructUser();
			user.setLastName(null);
			final String userUrl = super.baseUrl + "/api/user";
			logger.info("URL: {}", userUrl);
			final Response postResponse = super.restAssuredOpsAdminCreds().given().contentType(MediaType.APPLICATION_JSON_VALUE).body(user).post(userUrl);
			logger.info("Response:\n{}", postResponse.asPrettyString());
			assertThat(postResponse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		}

		@Test
		public void whenUpdateCreatedUser_thenUpdated() {
			final User user = postUser(constructUser());
			user.setLastName("newLastName");
			final String url = super.baseUrl + "/api/user";
			logger.info("URL: {}", url);
			final Response putResponse = super.restAssuredOpsAdminCreds().given().contentType(MediaType.APPLICATION_JSON_VALUE).body(user).put(url);
			logger.info("Response:\n{}", putResponse.asPrettyString());
			assertThat(putResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			final Response getResponse = super.restAssuredOpsAdminCreds().get(urlGetUserById(user));
			logger.info("Response:\n{}", getResponse.asPrettyString());
			assertThat(getResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			assertThat(getResponse.jsonPath().getString("lastName")).isEqualTo("newLastName");
		}

		@Test
		public void whenDeleteCreatedUser_thenOk() {
			final User user = postUser(constructUser());
			logger.info("User: {}", user);
			final String url = urlGetUserById(user);
			logger.info("URL: {}", url);
			final Response deleteResponse = super.restAssuredOpsAdminCreds().delete(url);
			logger.info("Response:\n{}", deleteResponse.asPrettyString());
			assertThat(deleteResponse.getStatusCode()).isEqualTo(HttpStatus.OK.value());
			final Response getResponse = super.restAssuredOpsAdminCreds().get(url);
			logger.info("Response:\n{}", getResponse.asPrettyString());
			assertThat(getResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND.value());
		}

		private User postUser(final User user) {
			assertNotNull(user);
			assertTrue(user.getId() <= 0);
			final String url = super.baseUrl + "/api/user";
			logger.info("URL: {}", url);
			final Response response = super.restAssuredOpsAdminCreds().contentType(MediaType.APPLICATION_JSON_VALUE).body(user).post(url);
			logger.info("Response:\n{}", response.asPrettyString());
			final User createdUser = response.as(User.class);
			logger.info("User: {}", createdUser);
			return createdUser;
//			logger.info("Response:\n{}", response.asPrettyString());
//			return super.baseUrl + "/api/user" + "/" + response.jsonPath().getLong("id");
		}

		private List<User> constructUsers(final int count) {
			return LongStream.range(0, count).mapToObj(this::contructUser).toList();
		}

		private List<User> postUsers(final List<User> users) {
			final Response response = super.restAssuredOpsAdminCreds().given().when().contentType(MediaType.APPLICATION_JSON_VALUE).body(users).post(super.baseUrl + "/api/users");
			logger.info("Response:\n{}", response.asPrettyString());
			return response.jsonPath().getList(".", User.class);
//			return Arrays.asList(response.as(User[].class));
//			final List<Integer> ids = response.jsonPath().getList("id");
		}

		private String urlGetUsersByIds(final List<User> users) {
			final List<String> queryParams = users.stream().map(user -> "id=" + user.getId()).toList();
			return super.baseUrl + "/api/users?" + Strings.join(queryParams, '&');
		}

		private String urlGetUserById(final User user) {
			assertNotNull(user);
			assertTrue(user.getId() > 0L);
			return super.baseUrl + "/api/user/" + user.getId();
		}

		private User contructUser(final long offset) {
			final long uniqueSuffix = UNIQUE_LONG.getAndIncrement() + offset;
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
			return new User(REALM, username, password, emailAddress, firstName, middleName, lastName, rolesAndPrivileges, isEnabled, isAccountNonExpired, isAccountNonLocked, isCredentialsNonExpired);
		}

		private User constructUser() {
			final long uniqueSuffix = UNIQUE_LONG.getAndIncrement();
			return contructUser(uniqueSuffix);
		}
	}
}