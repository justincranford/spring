package com.github.justincranford.spring.authn.server.api.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
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
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import com.github.justincranford.spring.authn.server.AbstractIT;
import com.github.justincranford.spring.util.model.User;

import io.restassured.http.Method;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

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
			verify(args, getOrDeleteFiltered(super.restAssuredOpsAdminCreds(), Method.GET, parameters("realm", args.realm(), "username", args.username())));
		}
		@ParameterizedTest @MethodSource("args")
		void testWellKnownUsernameWithoutRealm(final Args args) {
			verify(args, getOrDeleteFiltered(super.restAssuredOpsAdminCreds(), Method.GET, parameters("username", args.username())));
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
			final User user = createOrUpdateUser(super.restAssuredOpsAdminCreds(), Method.POST, constructUser(TEST_REALM));
			final Response response = this.restAssuredNoCreds.get(userUrl(TEST_REALM, user.getId()));
			logger.info("Response:\n{}", response.asPrettyString());
			assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
		}
		@Test
		public void testAuthenticationRequiredButInvalidCreds() {
			final User user = createOrUpdateUser(super.restAssuredOpsAdminCreds(), Method.POST, constructUser(TEST_REALM));
			final Response response = this.restAssuredInvalidCreds.get(userUrl(TEST_REALM, user.getId()));
			logger.info("Response:\n{}", response.asPrettyString());
			assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
		}
	}

	@Nested
	public class AuthorizationErrors extends AbstractIT {
		@Test
		public void testAuthenticatedButMissingRole() {
			final User user = createOrUpdateUser(super.restAssuredOpsAdminCreds(), Method.POST, constructUser(TEST_REALM));
			final Response response = super.restAssuredAppUserCreds().get(userUrl(TEST_REALM, user.getId()));
			logger.info("Response:\n{}", response.asPrettyString());
			assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
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
			final List<User> created = createOrUpdateUsers(super.restAssuredOpsAdminCreds(), Method.POST, invalid);
			assertThat(created).isEmpty();
		}
		@ParameterizedTest @MethodSource("args")
		public void whenInvalidRead_thenNotFound(final Args args) {
			final List<Long> invalidIds = LongStream.rangeClosed(1, args.count()).map((offset) -> UNIQUE_LONG.getAndIncrement()).boxed().toList();
			final List<User> get = getOrDeleteUsers(super.restAssuredOpsAdminCreds(), Method.GET, invalidIds);
			assertThat(get).isEmpty();
		}
		@ParameterizedTest @MethodSource("args")
		public void whenInvalidUpdate_thenError(final Args args) {
			final List<User> created = createOrUpdateUsers(super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final List<User> modified = created.stream().map((user) -> {
				final User copy = new User(user);
				copy.setLastName(null);
				return copy;
			}).toList();
			final List<User> updated = createOrUpdateUsers(super.restAssuredOpsAdminCreds(), Method.PUT, modified);
			assertThat(updated).isEmpty();
		}
		@ParameterizedTest @MethodSource("args")
		public void whenInvalidDelete_thenError(final Args args) {
			final List<Long> invalidIds = LongStream.rangeClosed(1, args.count()).map((offset) -> UNIQUE_LONG.getAndIncrement()).boxed().toList();
			final List<User> delete = getOrDeleteUsers(super.restAssuredOpsAdminCreds(), Method.DELETE, invalidIds);
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
			assertDoesNotThrow(() -> createOrUpdateUsers(super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count())));
		}
		@ParameterizedTest @MethodSource("args")
		public void whenReadByIds_thenOK(final Args args) {
			final List<User> created = createOrUpdateUsers(super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final List<User> get = getOrDeleteUsers(super.restAssuredOpsAdminCreds(), Method.GET, userIds(created));
			assertThat(get).containsAll(created);
		}
		@ParameterizedTest @MethodSource("args")
		public void whenUpdate_thenOK(final Args args) {
			final List<User> created = createOrUpdateUsers(super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final List<User> modified = created.stream().map((user) -> {
				final User copy = new User(user);
				copy.setLastName("newLastName");
				return copy;
			}).toList();
			final List<User> updated = createOrUpdateUsers(super.restAssuredOpsAdminCreds(), Method.PUT, modified);
			updated.stream().forEach((user) -> assertThat(user.getLastName()).isEqualTo("newLastName"));
			final List<User> get = getOrDeleteUsers(super.restAssuredOpsAdminCreds(), Method.GET, userIds(created));
			assertThat(get).isEqualTo(updated);
			assertThat(get).isNotEqualTo(created);
		}
		@ParameterizedTest @MethodSource("args")
		public void whenDeleteByIds_thenOk(final Args args) {
			final List<User> created = createOrUpdateUsers(super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final List<User> deleted = getOrDeleteUsers(super.restAssuredOpsAdminCreds(), Method.DELETE, userIds(created));
			assertThat(deleted).containsAll(created);
			final List<User> get = getOrDeleteUsers(super.restAssuredOpsAdminCreds(), Method.GET, userIds(created));
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
			final List<User> created = createOrUpdateUsers(super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final User[] got = getOrDeleteFiltered(super.restAssuredOpsAdminCreds(), Method.GET, parameters("realm", TEST_REALM));
			assertThat(got).containsAll(created);
			userIds(created).forEach(id -> assertThat(getOrDeleteUser(super.restAssuredOpsAdminCreds(), Method.GET, id)).isNotNull());
		}
		@ParameterizedTest @MethodSource("args")
		public void whenGetUsersByEmailAddresses_thenOK(final Args args) {
			final List<User> created = createOrUpdateUsers(super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final User[] got = getOrDeleteFiltered(super.restAssuredOpsAdminCreds(), Method.GET, parameters("realm", TEST_REALM, "username", usernames(created)));
			assertThat(got).containsAll(created);
			userIds(created).forEach(id -> assertThat(getOrDeleteUser(super.restAssuredOpsAdminCreds(), Method.GET, id)).isNotNull());
		}
		@ParameterizedTest @MethodSource("args")
		public void whenGetUsersByUserName_thenOK(final Args args) {
			final List<User> created = createOrUpdateUsers(super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final User[] got = getOrDeleteFiltered(super.restAssuredOpsAdminCreds(), Method.GET, parameters("realm", TEST_REALM, "emailAddress", emailAddresses(created)));
			assertThat(got).containsAll(created);
			userIds(created).forEach(id -> assertThat(getOrDeleteUser(super.restAssuredOpsAdminCreds(), Method.GET, id)).isNotNull());
		}
		@ParameterizedTest @MethodSource("args")
		public void whenGetUsersByFirstName_thenOK(final Args args) {
			final List<User> created = createOrUpdateUsers(super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final User[] got = getOrDeleteFiltered(super.restAssuredOpsAdminCreds(), Method.GET, parameters("realm", TEST_REALM, "firstName", firstNames(created)));
			assertThat(got).containsAll(created);
			userIds(created).forEach(id -> assertThat(getOrDeleteUser(super.restAssuredOpsAdminCreds(), Method.GET, id)).isNotNull());
		}
		@ParameterizedTest @MethodSource("args")
		public void whenGetUsersByLastName_thenOK(final Args args) {
			final List<User> created = createOrUpdateUsers(super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final User[] got = getOrDeleteFiltered(super.restAssuredOpsAdminCreds(), Method.GET, parameters("realm", TEST_REALM, "lastName", lastNames(created)));
			assertThat(got).containsAll(created);
			userIds(created).forEach(id -> assertThat(getOrDeleteUser(super.restAssuredOpsAdminCreds(), Method.GET, id)).isNotNull());
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
			final List<User> created = createOrUpdateUsers(super.restAssuredOpsAdminCreds(), Method.POST, constructUsers(TEST_REALM, args.count()));
			final User[] deleted = getOrDeleteFiltered(super.restAssuredOpsAdminCreds(), Method.DELETE, parameters("realm", TEST_REALM));
			assertThat(deleted).containsAll(created);
			userIds(created).forEach(id -> assertThat(getOrDeleteUser(super.restAssuredOpsAdminCreds(), Method.GET, id)).isNull());
		}
	}

	//////////////////////////
	// URL path helper methods
	//////////////////////////

	private String userUrl(final String realm, final Long id) {
		final String userUrl = super.baseUrl + "/api/user" + pathSuffix(id) + queryString(parameters("realm", realm));
		logger.info("User URL: {}", userUrl);
		return userUrl;
	}

	private String usersUrl(final String realm, final List<Long> ids) {
		final String usersUrl = super.baseUrl + "/api/users" + queryString(parameters("realm", realm, "id", ids));
		logger.info("Users URL: {}", usersUrl);
		return usersUrl;
	}

	private String usersFilteredUrl(final MultiValueMap<String, String> parameters) {
		final String usersFilteredUrl = super.baseUrl + "/api/users/filtered" + queryString(parameters);
		logger.info("Users filtered URL: {}", usersFilteredUrl);
		return usersFilteredUrl;
	}

	private String queryString(final MultiValueMap<String, String> parameters) {
		final String queryString = UriComponentsBuilder.newInstance().queryParams(parameters).build().getQuery();
		return (Strings.isEmpty(queryString) ? "" : "?" + queryString);
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
	) {
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
	// HTML helper methods
	//////////////////////

	private User createOrUpdateUser(final RequestSpecification restAssuredRequestSpecification, final Method postOrPut, final User user) {
		return createOrUpdateUsers(restAssuredRequestSpecification, postOrPut, List.of(user)).get(0);
	}

	private List<User> createOrUpdateUsers(final RequestSpecification restAssuredRequestSpecification, final Method postOrPut, final List<User> users) {
		assertThat(postOrPut).isIn(Method.POST, Method.PUT);
		assertNotNull(users);
		users.forEach(user -> {
			assertThat(user).isNotNull();
			if (postOrPut.equals(Method.POST)) {
				assertThat(user.getId()).isLessThanOrEqualTo(0L);
			} else {
				assertThat(user.getId()).isGreaterThan(0L);
			}
		});
		final HttpStatus expectedHttpStatus = postOrPut.equals(Method.POST) ? HttpStatus.CREATED : HttpStatus.OK;
		final String createdOrUpdated = postOrPut.equals(Method.POST) ? "Created" : "Updated";
		if (users.size() == 1) {
			final Response response = super.restAssuredOpsAdminCreds().contentType(MediaType.APPLICATION_JSON_VALUE).body(users.get(0)).request(postOrPut, userUrl(null, null));
			assertThat(response.getStatusCode()).isIn(expectedHttpStatus.value(), HttpStatus.BAD_REQUEST.value());
			if (response.getStatusCode() == HttpStatus.BAD_REQUEST.value()) {
				logger.info("{} User: Bad request");
				return Collections.emptyList();
			}
			final User createdOrUpdatedUser = response.as(User.class);
			logger.info("{} User: {}", createdOrUpdated, createdOrUpdatedUser);
			return List.of(createdOrUpdatedUser);
		}
		final Response response = restAssuredRequestSpecification.given().when().contentType(MediaType.APPLICATION_JSON_VALUE).body(users).request(postOrPut, usersUrl(null, null));
		assertThat(response.getStatusCode()).isIn(expectedHttpStatus.value(), HttpStatus.BAD_REQUEST.value());
		if (response.getStatusCode() == HttpStatus.BAD_REQUEST.value()) {
			logger.info("{} User: Bad request");
			return Collections.emptyList();
		}
		List<User> createdOrUpdatedUsers = response.jsonPath().getList(".", User.class);
		logger.info("{} Users: {}", createdOrUpdated, createdOrUpdatedUsers);
		return createdOrUpdatedUsers;
	}

	private User getOrDeleteUser(RequestSpecification restAssuredRequestSpecification, final Method getOrDelete, final Long id) {
		final List<User> users = getOrDeleteUsers(restAssuredRequestSpecification, getOrDelete, List.of(id));
		return users.isEmpty() ? null : users.get(0);
	}

	private List<User> getOrDeleteUsers(final RequestSpecification restAssuredRequestSpecification, final Method getOrDelete, final List<Long> ids) {
		assertThat(getOrDelete).isIn(Method.GET, Method.DELETE);
		assertNotNull(ids);
		ids.forEach(id -> {
			assertThat(id).isNotNull();
			assertThat(id).isGreaterThan(0L);
		});
		final String gotOrDeleted = getOrDelete.equals(Method.GET) ? "Got" : "Deleted";
		if (ids.size() == 1) {
			final Response response = restAssuredRequestSpecification.request(getOrDelete, userUrl(null, ids.get(0)));
			assertThat(response.getStatusCode()).isIn(HttpStatus.OK.value(), HttpStatus.NOT_FOUND.value());
			if (response.getStatusCode() == HttpStatus.NOT_FOUND.value()) {
				logger.info("{} User: Not found", gotOrDeleted);
				return Collections.emptyList();
			}
			final User getOrDeletedUser = response.as(User.class);
			logger.info("{} User: {}", gotOrDeleted, getOrDeletedUser);
			return List.of(getOrDeletedUser);
		}
		final Response response = restAssuredRequestSpecification.given().when().request(getOrDelete, usersUrl(null, ids));
		assertThat(response.getStatusCode()).isIn(HttpStatus.OK.value(), HttpStatus.NOT_FOUND.value());
		if (response.getStatusCode() == HttpStatus.NOT_FOUND.value()) {
			logger.info("{} Users: Not found", gotOrDeleted);
			return Collections.emptyList();
		}
		// TODO Return User[]
		List<User> getOrDeletedUsers = response.jsonPath().getList(".", User.class);
		logger.info("{} Users: {}", gotOrDeleted, getOrDeletedUsers);
		return getOrDeletedUsers;
	}

	private User[] getOrDeleteFiltered(final RequestSpecification restAssuredRequestSpecification, final Method method, final MultiValueMap<String, String> parameters) {
		final Response response = restAssuredRequestSpecification.request(method, usersFilteredUrl(parameters));
		final User[] users = response.as(User[].class);
		logger.info("Filter Response:\n{}", (Object[]) users);
		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK.value());
		return users;
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

	private Long[] userIds(final User... users) {
		return Arrays.stream(users).map(user -> user.getId()).toArray(Long[]::new);
	}

	private List<Long> userIds(final List<User> users) {
		return users.stream().map(user -> user.getId()).toList();
	}

	private List<String> usernames(final List<User> users) {
		return users.stream().map(user -> user.getUsername()).toList();
	}

	private List<String> emailAddresses(final List<User> users) {
		return users.stream().map(user -> user.getEmailAddress()).toList();
	}

	private List<String> firstNames(final List<User> users) {
		return users.stream().map(user -> user.getFirstName()).toList();
	}

	private List<String> lastNames(final List<User> users) {
		return users.stream().map(user -> user.getLastName()).toList();
	}

	private LinkedMultiValueMap<String, String> parameters(final Object... objects) {
		assertThat(objects).isNotEmpty();
		assertThat(objects.length % 2).isEqualTo(0);
		final LinkedMultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		for (int i=0; i<objects.length; i+=2) {
			if (objects[i+1] != null) {
				if (objects[i+1] instanceof Collection<?> collection) {
					for (final Object value : collection) {
						parameters.add(objects[i].toString(), value.toString());
					}
				} else {
					parameters.add(objects[i].toString(), objects[i+1].toString());
				}
			}
		}
		return parameters;
	}
}