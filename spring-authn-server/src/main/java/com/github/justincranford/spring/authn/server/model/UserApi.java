package com.github.justincranford.spring.authn.server.model;

import static com.github.justincranford.spring.util.util.ArrayUtil.array;
import static com.github.justincranford.spring.util.util.ArrayUtil.firstOrNull;
import static com.github.justincranford.spring.util.util.JsonUtil.fromJson;
import static com.github.justincranford.spring.util.util.JsonUtil.toJson;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.util.MultiValueMap;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.github.justincranford.spring.util.model.User;
import com.github.justincranford.spring.util.rest.RestClient;

// TODO Generic
public class UserApi extends RestClient {
	private static Logger logger = LoggerFactory.getLogger(UserApi.class);

	public UserApi(final RestClient restClient) {
		super(restClient);
	}

	public User createOrUpdateUser(final String method, final String realm, final User user) throws URISyntaxException, IOException, InterruptedException, HttpResponseException {
		return firstOrNull(createOrUpdateUsers(method, realm, array(user)));
	}
	public User getOrDeleteUser(final String method, final String realm, final Long id) throws URISyntaxException, IOException, InterruptedException, HttpResponseException {
		return firstOrNull(getOrDeleteUsers(method, realm, array(id)));
	}
	public User[] createOrUpdateUsers(final String method, final String realm, final User[] users) throws URISyntaxException, IOException, InterruptedException, HttpResponseException {
		final String url = (users.length == 1) ? crudUrl(parameters("realm", realm)) : crudsUrl(parameters("realm", realm));
		final BodyPublisher body = (users.length == 1) ? BodyPublishers.ofString(toJson(users[0])) : BodyPublishers.ofString(toJson(users));
		final HttpResponse<String> response = super.doRequest(url, method, POST_OR_PUT_HEADERS, body, BodyHandlers.ofString());
		return parse(method, response, users.length == 1);
	}
	public User[] getOrDeleteUsers(final String method, final String realm, final Long[] ids) throws URISyntaxException, IOException, InterruptedException, HttpResponseException  {
		final String url = (ids.length == 1) ? crudUrl(parameters("realm", realm, "id", ids[0])) : crudsUrl(parameters("realm", realm, "id", ids));
		final HttpResponse<String> response = super.doRequest(url, method, POST_OR_PUT_HEADERS, BodyPublishers.noBody(), BodyHandlers.ofString());
		return parse(method, response, ids.length == 1);
	}
	public User[] getOrDeleteFiltered(final String method, final MultiValueMap<String, String> parameters) throws URISyntaxException, IOException, InterruptedException, HttpResponseException {
		final HttpResponse<String> response = super.doRequest(filteredUrl(parameters), method, POST_OR_PUT_HEADERS, BodyPublishers.noBody(), BodyHandlers.ofString());
		return parse(method, response, false);
	}

	private User[] parse(final String method, final HttpResponse<String> response, final boolean isSingle) throws JsonProcessingException, JsonMappingException, HttpResponseException {
		if ((response.statusCode() == HttpStatus.CREATED.value()) || (response.statusCode() == HttpStatus.OK.value())) {
			final User[] returned = isSingle ? array(fromJson(response.body(), User.class)) : fromJson(response.body(), User[].class);
			logger.info("{} User{}: {}", method, isSingle ? "" : "s", (Object[]) returned);
			return returned;
		}
		throw new HttpResponseException(response);
	}

	public String crudUrl(final MultiValueMap<String, String> parameters) {
		final String crudUrl = "/api/user" +  RestClient.queryString(parameters);
		logger.info("User relative URL: {}", crudUrl);
		return crudUrl;
	}
	public  String crudsUrl(final MultiValueMap<String, String> parameters) {
		final String crudsUrl = "/api/users" + RestClient.queryString(parameters);
		logger.info("Users relative URL: {}", crudsUrl);
		return crudsUrl;
	}
	public  String filteredUrl(final MultiValueMap<String, String> parameters) {
		final String filteredUrl = "/api/users/filtered" + RestClient.queryString(parameters);
		logger.info("Users filtered relative URL: {}", filteredUrl);
		return filteredUrl;
	}
}
