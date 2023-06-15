package com.github.justincranford.spring.authn.server.api.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.logging.log4j.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import com.github.justincranford.spring.util.model.User;

import io.restassured.http.Method;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

public class UserClient {
	private static Logger logger = LoggerFactory.getLogger(UserApiIT.class);

	// TODO Use this in all methods. Make methods non static.
	private final String baseUrl;
	private final RequestSpecification restAssuredRequestSpecification;
	public UserClient(final String baseUrl, final RequestSpecification restAssuredRequestSpecification) {
		this.baseUrl = baseUrl;
		this.restAssuredRequestSpecification = restAssuredRequestSpecification;
	}

	public static User createOrUpdateUser(final String baseUrl, final RequestSpecification restAssuredRequestSpecification, final Method postOrPut, final User user) {
		return createOrUpdateUsers(baseUrl, restAssuredRequestSpecification, postOrPut, List.of(user)).get(0);
	}

	public static List<User> createOrUpdateUsers(final String baseUrl, final RequestSpecification restAssuredRequestSpecification, final Method postOrPut, final List<User> users) {
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
			final Response response = restAssuredRequestSpecification.contentType(MediaType.APPLICATION_JSON_VALUE).body(users.get(0)).request(postOrPut, userUrl(baseUrl, null, null));
			assertThat(response.getStatusCode()).isIn(expectedHttpStatus.value(), HttpStatus.BAD_REQUEST.value());
			if (response.getStatusCode() == HttpStatus.BAD_REQUEST.value()) {
				logger.info("{} User: Bad request");
				return Collections.emptyList();
			}
			final User createdOrUpdatedUser = response.as(User.class);
			logger.info("{} User: {}", createdOrUpdated, createdOrUpdatedUser);
			return List.of(createdOrUpdatedUser);
		}
		final Response response = restAssuredRequestSpecification.given().when().contentType(MediaType.APPLICATION_JSON_VALUE).body(users).request(postOrPut, usersUrl(baseUrl, null, null));
		assertThat(response.getStatusCode()).isIn(expectedHttpStatus.value(), HttpStatus.BAD_REQUEST.value());
		if (response.getStatusCode() == HttpStatus.BAD_REQUEST.value()) {
			logger.info("{} User: Bad request");
			return Collections.emptyList();
		}
		List<User> createdOrUpdatedUsers = response.jsonPath().getList(".", User.class);
		logger.info("{} Users: {}", createdOrUpdated, createdOrUpdatedUsers);
		return createdOrUpdatedUsers;
	}

	public static User getOrDeleteUser(final String baseUrl, final RequestSpecification restAssuredRequestSpecification, final Method getOrDelete, final Long id) {
		final List<User> users = getOrDeleteUsers(baseUrl, restAssuredRequestSpecification, getOrDelete, List.of(id));
		return users.isEmpty() ? null : users.get(0);
	}

	public static List<User> getOrDeleteUsers(final String baseUrl, final RequestSpecification restAssuredRequestSpecification, final Method getOrDelete, final List<Long> ids) {
		assertThat(getOrDelete).isIn(Method.GET, Method.DELETE);
		assertNotNull(ids);
		ids.forEach(id -> {
			assertThat(id).isNotNull();
			assertThat(id).isGreaterThan(0L);
		});
		final String gotOrDeleted = getOrDelete.equals(Method.GET) ? "Got" : "Deleted";
		if (ids.size() == 1) {
			final Response response = restAssuredRequestSpecification.request(getOrDelete, userUrl(baseUrl, null, ids.get(0)));
			assertThat(response.getStatusCode()).isIn(HttpStatus.OK.value(), HttpStatus.NOT_FOUND.value());
			if (response.getStatusCode() == HttpStatus.NOT_FOUND.value()) {
				logger.info("{} User: Not found", gotOrDeleted);
				return Collections.emptyList();
			}
			final User getOrDeletedUser = response.as(User.class);
			logger.info("{} User: {}", gotOrDeleted, getOrDeletedUser);
			return List.of(getOrDeletedUser);
		}
		final Response response = restAssuredRequestSpecification.given().when().request(getOrDelete, usersUrl(baseUrl, null, ids));
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

	public static User[] getOrDeleteFiltered(final String baseUrl, final RequestSpecification restAssuredRequestSpecification, final Method method, final MultiValueMap<String, String> parameters) throws Exception {
		final Response response = restAssuredRequestSpecification.request(method, usersFilteredUrl(baseUrl, parameters));
		assertThat(response.getStatusCode()).isIn(HttpStatus.OK.value(), HttpStatus.BAD_REQUEST.value());
		if (response.getStatusCode() == HttpStatus.OK.value()) {
			final User[] users = response.as(User[].class);
			logger.info("Filter Response:\n{}", (Object[]) users);
			return users;
		}
		throw new Exception(response.print());
	}

	///////////////////////
	// Other helper methods
	///////////////////////

	public static Long[] userIds(final User... users) {
		return Arrays.stream(users).map(user -> user.getId()).toArray(Long[]::new);
	}

	public static List<Long> userIds(final List<User> users) {
		return users.stream().map(user -> user.getId()).toList();
	}

	public static List<String> usernames(final List<User> users) {
		return users.stream().map(user -> user.getUsername()).toList();
	}

	public static List<String> emailAddresses(final List<User> users) {
		return users.stream().map(user -> user.getEmailAddress()).toList();
	}

	public static List<String> firstNames(final List<User> users) {
		return users.stream().map(user -> user.getFirstName()).toList();
	}

	public static List<String> lastNames(final List<User> users) {
		return users.stream().map(user -> user.getLastName()).toList();
	}

	public static LinkedMultiValueMap<String, String> parameters(final Object... objects) {
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

	//////////////////////////
	// URL path helper methods
	//////////////////////////

	public  static String userUrl(final String baseUrl, final String realm, final Long id) {
		final String userUrl = baseUrl + "/api/user" + pathSuffix(id) + queryString(parameters("realm", realm));
		logger.info("User URL: {}", userUrl);
		return userUrl;
	}

	public  static String usersUrl(final String baseUrl, final String realm, final List<Long> ids) {
		final String usersUrl = baseUrl + "/api/users" + queryString(parameters("realm", realm, "id", ids));
		logger.info("Users URL: {}", usersUrl);
		return usersUrl;
	}

	public  static String usersFilteredUrl(final String baseUrl, final MultiValueMap<String, String> parameters) {
		final String usersFilteredUrl = baseUrl + "/api/users/filtered" + queryString(parameters);
		logger.info("Users filtered URL: {}", usersFilteredUrl);
		return usersFilteredUrl;
	}

	private static String queryString(final MultiValueMap<String, String> parameters) {
		final String queryString = UriComponentsBuilder.newInstance().queryParams(parameters).build().getQuery();
		return (Strings.isEmpty(queryString) ? "" : "?" + queryString);
	}

	private static String pathSuffix(final Long id) {
		return (id == null) ? "" : "/" + id;
	}
}
