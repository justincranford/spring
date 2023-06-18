package com.github.justincranford.spring.authn.server.model;

import static com.github.justincranford.spring.util.rest.RestClient.ApiType.BULK;
import static com.github.justincranford.spring.util.rest.RestClient.ApiType.FILTERED;
import static com.github.justincranford.spring.util.rest.RestClient.ApiType.SINGLE;
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

	public User createOrUpdate(final String method, final User user, final MultiValueMap<String, String> additionalParameters) throws URISyntaxException, IOException, InterruptedException, HttpResponseException {
		return firstOrNull(createOrUpdate(method, array(user), additionalParameters));
	}
	public User[] createOrUpdate(final String method, final User[] users, final MultiValueMap<String, String> additionalParameters) throws URISyntaxException, IOException, InterruptedException, HttpResponseException {
		final String url = url((users.length == 1) ? SINGLE : BULK, additionalParameters);
		final BodyPublisher body = (users.length == 1) ? BodyPublishers.ofString(toJson(users[0])) : BodyPublishers.ofString(toJson(users));
		final HttpResponse<String> response = super.doRequest(url, method, HEADERS, body, BodyHandlers.ofString());
		return parse(method, response, users.length == 1);
	}
	public User getOrDelete(final String method, final Long id, final MultiValueMap<String, String> additionalParameters) throws URISyntaxException, IOException, InterruptedException, HttpResponseException {
		return firstOrNull(getOrDelete(method, array(id), additionalParameters));
	}
	public User[] getOrDelete(final String method, final Long[] ids, final MultiValueMap<String, String> additionalParameters) throws URISyntaxException, IOException, InterruptedException, HttpResponseException  {
		final String url = url((ids.length == 1) ? SINGLE : BULK, merge(additionalParameters, "id", ids));
		final HttpResponse<String> response = super.doRequest(url, method, HEADERS, BodyPublishers.noBody(), BodyHandlers.ofString());
		return parse(method, response, ids.length == 1);
	}
	public User[] getOrDelete(final String method, final MultiValueMap<String, String> parameters) throws URISyntaxException, IOException, InterruptedException, HttpResponseException {
		final HttpResponse<String> response = super.doRequest(url(FILTERED, parameters), method, HEADERS, BodyPublishers.noBody(), BodyHandlers.ofString());
		return parse(method, response, false);
	}

	private User[] parse(final String method, final HttpResponse<String> response, final boolean isOne) throws JsonProcessingException, JsonMappingException, HttpResponseException {
		if ((response.statusCode() == HttpStatus.OK.value()) || (response.statusCode() == HttpStatus.CREATED.value())) {
			final User[] returned = isOne ? array(fromJson(response.body(), User.class)) : fromJson(response.body(), User[].class);
			logger.info("{} User{}: {}", method, isOne ? "" : "s", (Object[]) returned);
			return returned;
		}
		throw new HttpResponseException(response);
	}

	public String url(final ApiType apiType, final MultiValueMap<String, String> parameters) {
		final String url;
		switch(apiType) {
			case SINGLE:   url = "/api/user"           + RestClient.queryString(parameters); break;
			case BULK:     url = "/api/users"          + RestClient.queryString(parameters); break;
			case FILTERED: url = "/api/users/filtered" + RestClient.queryString(parameters); break;
			default: throw new IllegalArgumentException("Invalid API_TYPE " + apiType);
		}
		logger.info("User{} relative URL: {}", (SINGLE.equals(apiType) ? "" : "s"), url);
		return url;
 	}
}
