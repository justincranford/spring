package com.github.justincranford.spring.authz.server.api.users.ops;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.LongStream;

import org.apache.logging.log4j.util.Strings;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import com.github.justincranford.spring.authz.server.SpringBootTestHelper;
import com.github.justincranford.spring.authz.server.model.OpsUser;

import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

public class OpsUserApiTests extends SpringBootTestHelper {
	private Logger logger = LoggerFactory.getLogger(OpsUserApiTests.class);

	@BeforeEach
	public void beforeEach() throws Exception {
		super.beforeEach();
//		this.deleteAll();
//		this.printAll();
	}

	@AfterEach
	public void afterEach() throws Exception {
		super.afterEach();
//		this.deleteAll();
//		this.printAll();
	}

	@SuppressWarnings("unused")
	private void deleteAll() {
		this.logger.info("URL: {}", super.baseUrl + "/api/ops/users");
		final Response deleteResponse = this.restAssuredOpsAdminCreds.delete(super.baseUrl + "/api/ops/users");
		this.logger.info("Response:\n{}", deleteResponse.asPrettyString());
		assertEquals(HttpStatus.OK.value(), deleteResponse.getStatusCode());
		final List<Integer> deletedIds = deleteResponse.jsonPath().getList("id");
		this.logger.info("Deleted IDs: {}", deletedIds);
	}

	@SuppressWarnings("unused")
	private void printAll() {
		this.logger.info("URL: {}", super.baseUrl + "/api/ops/users/search");
		final Response getResponse = this.restAssuredOpsAdminCreds.get(super.baseUrl + "/api/ops/users/search");
		this.logger.info("Response:\n{}", getResponse.asPrettyString());
		assertEquals(HttpStatus.OK.value(), getResponse.getStatusCode());
//		final List<Integer> ids = getResponse.jsonPath().getList("id");
//		assertTrue(ids.isEmpty());
	}

	@Test
	public void testAuthenticationRequiredButNoCreds() {
		final Response response = this.restAssuredNoCreds.get(super.baseUrl + "/api/ops/user");
		this.logger.info("Response:\n{}", response.asPrettyString());
		assertEquals(HttpStatus.UNAUTHORIZED.value(), response.getStatusCode());
	}

	@Test
	public void testAuthenticationRequiredButInvalidCreds() {
		final Response response = this.restAssuredInvalidCreds.get(super.baseUrl + "/api/ops/user");
		this.logger.info("Response:\n{}", response.asPrettyString());
		assertEquals(HttpStatus.UNAUTHORIZED.value(), response.getStatusCode());
	}

	@Test
	public void testAuthenticatedButMissingRole() {
		final Response response = this.restAssuredAppAdminCreds.get(super.baseUrl + "/api/ops/user");
		this.logger.info("Response:\n{}", response.asPrettyString());
		assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatusCode());
	}

	@Test
	public void whenGetAllUsers_thenOK() {
		final Response response = this.restAssuredOpsAdminCreds.get(super.baseUrl + "/api/ops/users/search");
		this.logger.info("Response:\n{}", response.asPrettyString());
		assertEquals(HttpStatus.OK.value(), response.getStatusCode());
	}

	@Test
	public void whenGetUsersByFirstName_thenOK() {
		final OpsUser user = postUser(constructUser());
		final Response searchResponse = this.restAssuredOpsAdminCreds.get(super.baseUrl + "/api/ops/users/search" + "?firstName=" + user.getFirstName());
		this.logger.info("Response:\n{}", searchResponse.asPrettyString());
		assertEquals(HttpStatus.OK.value(), searchResponse.getStatusCode());
		@SuppressWarnings("unchecked")
		final List<OpsUser> getUsers = searchResponse.as(List.class);
		this.logger.info("Users: {}", getUsers);
		assertTrue(getUsers.size() > 0);
	}

	@Test
	public void whenGetUsersByLastName_thenOK() {
		final OpsUser user = postUser(constructUser());
		final Response searchResponse = this.restAssuredOpsAdminCreds.get(super.baseUrl + "/api/ops/users/search" + "?lastName=" + user.getLastName());
		this.logger.info("Response:\n{}", searchResponse.asPrettyString());
		assertEquals(HttpStatus.OK.value(), searchResponse.getStatusCode());
		@SuppressWarnings("unchecked")
		final List<OpsUser> getUsers = searchResponse.as(List.class);
		this.logger.info("Users: {}", getUsers);
		assertTrue(getUsers.size() > 0);
	}

//	@Test
//	public void whenGetUsersByFirstNameAndLastName_thenOK() {
//		final User user = postUser(constructUser());
//		final Response getResponse = REST_ASSURED.get(super.baseUrl + "/api/ops/users/search" + "?firstName=" + user.getFirstName() + "&lastName=" + user.getLastName());
//		this.logger.info("Response:\n{}", getResponse.asPrettyString());
//		assertEquals(HttpStatus.OK.value(), getResponse.getStatusCode());
//		assertTrue(getResponse.as(List.class).size() > 0);
//	}

	@Test
	public void whenGetCreatedUserById_thenOK() {
		final OpsUser user = postUser(constructUser());
		final Response getResponse = this.restAssuredOpsAdminCreds.get(url(user));
		this.logger.info("Response:\n{}", getResponse.asPrettyString());
		assertEquals(HttpStatus.OK.value(), getResponse.getStatusCode());
		assertEquals(user.getFirstName(), getResponse.jsonPath().getString("firstName"));
		assertEquals(user.getLastName(), getResponse.jsonPath().getString("lastName"));
	}

	@Test
	public void whenGetCreatedUsersById_thenOK() {
		final List<OpsUser> users = postUsers(constructUsers(1)); // TODO 3 users
		this.logger.info("Users: {}", users);
		final Response getResponse = this.restAssuredOpsAdminCreds.get(url(users));
		this.logger.info("Response:\n{}", getResponse.asPrettyString());
		assertEquals(HttpStatus.OK.value(), getResponse.getStatusCode());
		for (int b = 0; b < users.size(); b++) {
			final OpsUser user = users.get(b);
			final JsonPath jsonPath = getResponse.jsonPath();
			assertEquals(user.getFirstName(), jsonPath.getString("[" + b + "].firstName"));
			assertEquals(user.getLastName(), jsonPath.getString("[" + b + "].lastName"));
		}
	}

	@Test
	public void whenGetNotExistUserById_thenNotFound() {
		final String userUrl = super.baseUrl + "/api/ops/user" + "/" + UNIQUE_LONG.getAndIncrement();
		this.logger.info("URL: {}", userUrl);
		final Response getResponse = this.restAssuredOpsAdminCreds.get(userUrl);
		this.logger.info("Response:\n{}", getResponse.asPrettyString());
		assertEquals(HttpStatus.NOT_FOUND.value(), getResponse.getStatusCode());
	}

	@Test
	public void whenCreateNewUser_thenCreated() {
		final OpsUser user = constructUser();
		final String userUrl = super.baseUrl + "/api/ops/user";
		this.logger.info("URL: {}", userUrl);
		final Response postResponse = this.restAssuredOpsAdminCreds.given().contentType(MediaType.APPLICATION_JSON_VALUE).body(user).post(userUrl);
		this.logger.info("Response:\n{}", postResponse.asPrettyString());
		assertEquals(HttpStatus.CREATED.value(), postResponse.getStatusCode());
	}

	@Test
	public void whenInvalidUser_thenError() {
		final OpsUser user = constructUser();
		user.setLastName(null);
		final String userUrl = super.baseUrl + "/api/ops/user";
		this.logger.info("URL: {}", userUrl);
		final Response postResponse = this.restAssuredOpsAdminCreds.given().contentType(MediaType.APPLICATION_JSON_VALUE).body(user).post(userUrl);
		this.logger.info("Response:\n{}", postResponse.asPrettyString());
		assertEquals(HttpStatus.BAD_REQUEST.value(), postResponse.getStatusCode());
	}

	@Test
	public void whenUpdateCreatedUser_thenUpdated() {
		final OpsUser user = postUser(constructUser());
		user.setLastName("newLastName");
		final Response putResponse = this.restAssuredOpsAdminCreds.given().contentType(MediaType.APPLICATION_JSON_VALUE).body(user).put(super.baseUrl + "/api/ops/user");
		this.logger.info("Response:\n{}", putResponse.asPrettyString());
		assertEquals(HttpStatus.OK.value(), putResponse.getStatusCode());
		final Response getResponse = this.restAssuredOpsAdminCreds.get(url(user));
		this.logger.info("Response:\n{}", getResponse.asPrettyString());
		assertEquals(HttpStatus.OK.value(), getResponse.getStatusCode());
		assertEquals("newLastName", getResponse.jsonPath().getString("lastName"));
	}

	@Test
	public void whenDeleteCreatedUser_thenOk() {
		final OpsUser user = postUser(constructUser());
		this.logger.info("User: {}", user);
		final Response deleteResponse = this.restAssuredOpsAdminCreds.delete(url(user));
		this.logger.info("Response:\n{}", deleteResponse.asPrettyString());
		assertEquals(HttpStatus.OK.value(), deleteResponse.getStatusCode());
		final Response getResponse = this.restAssuredOpsAdminCreds.get(url(user));
		this.logger.info("Response:\n{}", getResponse.asPrettyString());
		assertEquals(HttpStatus.NOT_FOUND.value(), getResponse.getStatusCode());
	}

	private OpsUser postUser(final OpsUser user) {
		assertNotNull(user);
		assertTrue(user.getId() <= 0);
		RequestSpecification request = this.restAssuredOpsAdminCreds.given().contentType(MediaType.APPLICATION_JSON_VALUE).body(user);
		this.logger.info("Request:\n{}", request.toString());
		final Response response = request.post(super.baseUrl + "/api/ops/user");
		this.logger.info("Response:\n{}", response.asPrettyString());
		final OpsUser createdUser = response.as(OpsUser.class);
		this.logger.info("User: {}", createdUser);
		return createdUser;
//		this.logger.info("Response:\n{}", response.asPrettyString());
//		return super.baseUrl + "/api/ops/user" + "/" + response.jsonPath().getLong("id");
	}

	private List<OpsUser> constructUsers(final int count) {
		return LongStream.range(0, count).mapToObj(this::contructUser).toList();
	}

	private List<OpsUser> postUsers(final List<OpsUser> users) {
		final Response response = this.restAssuredOpsAdminCreds.given().when().contentType(MediaType.APPLICATION_JSON_VALUE).body(users).post(super.baseUrl + "/api/ops/users");
		this.logger.info("Response:\n{}", response.asPrettyString());
		return response.jsonPath().getList(".", OpsUser.class);
//		return Arrays.asList(response.as(User[].class));
//		final List<Integer> ids = response.jsonPath().getList("id");
	}

	private String url(final List<OpsUser> users) {
		final List<String> queryParams = users.stream().map(user -> "id=" + user.getId()).toList();
		return super.baseUrl + "/api/ops/users" + "?" + Strings.join(queryParams, '&');
	}

	private String url(final OpsUser user) {
		assertNotNull(user);
		assertTrue(user.getId() > 0L);
		return super.baseUrl + "/api/ops/user" + "/" + user.getId();
	}

	private OpsUser contructUser(final long offset) {
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
		return new OpsUser(username, password, emailAddress, firstName, middleName, lastName, rolesAndPrivileges, isEnabled, isAccountNonExpired, isAccountNonLocked, isCredentialsNonExpired);
	}

	private OpsUser constructUser() {
		final long uniqueSuffix = UNIQUE_LONG.getAndIncrement();
		return contructUser(uniqueSuffix);
	}
}