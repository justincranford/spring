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
import com.github.justincranford.spring.util.model.PluralName;
import com.github.justincranford.spring.util.rest.RestClient;

public class RestApi<ENTITY extends PluralName> extends RestClient {
	private static Logger logger = LoggerFactory.getLogger(RestApi.class);

	private final Class<ENTITY> clazz;
	private final String entitySingleName;
	private final String entityPluralName;

	public RestApi(final Class<ENTITY> clazz, final RestClient restClient) {
		super(restClient);
		this.clazz = clazz;
		this.entitySingleName = this.clazz.getSimpleName();
		try {
			this.entityPluralName = (String) clazz.getMethod("pluralName").invoke(null);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public ENTITY createOrUpdate(final String method, final ENTITY entity, final MultiValueMap<String, String> additionalParameters) throws URISyntaxException, IOException, InterruptedException, HttpResponseException {
		return firstOrNull(createOrUpdate(method, array(entity), additionalParameters));
	}
	public ENTITY[] createOrUpdate(final String method, final ENTITY[] entities, final MultiValueMap<String, String> additionalParameters) throws URISyntaxException, IOException, InterruptedException, HttpResponseException {
		final String url = url((entities.length == 1) ? SINGLE : BULK, additionalParameters);
		final BodyPublisher body = (entities.length == 1) ? BodyPublishers.ofString(toJson(entities[0])) : BodyPublishers.ofString(toJson(entities));
		final HttpResponse<String> response = super.doRequest(url, method, HEADERS, body, BodyHandlers.ofString());
		return parse(method, response, entities.length == 1);
	}
	public ENTITY getOrDelete(final String method, final Long id, final MultiValueMap<String, String> additionalParameters) throws URISyntaxException, IOException, InterruptedException, HttpResponseException {
		return firstOrNull(getOrDelete(method, array(id), additionalParameters));
	}
	public ENTITY[] getOrDelete(final String method, final Long[] ids, final MultiValueMap<String, String> additionalParameters) throws URISyntaxException, IOException, InterruptedException, HttpResponseException  {
		final String url = url((ids.length == 1) ? SINGLE : BULK, merge(additionalParameters, "id", ids));
		final HttpResponse<String> response = super.doRequest(url, method, HEADERS, BodyPublishers.noBody(), BodyHandlers.ofString());
		return parse(method, response, ids.length == 1);
	}
	public ENTITY[] getOrDelete(final String method, final MultiValueMap<String, String> parameters) throws URISyntaxException, IOException, InterruptedException, HttpResponseException {
		final HttpResponse<String> response = super.doRequest(url(FILTERED, parameters), method, HEADERS, BodyPublishers.noBody(), BodyHandlers.ofString());
		return parse(method, response, false);
	}

	private ENTITY[] parse(final String method, final HttpResponse<String> response, final boolean isOne) throws JsonProcessingException, JsonMappingException, HttpResponseException {
		if ((response.statusCode() == HttpStatus.OK.value()) || (response.statusCode() == HttpStatus.CREATED.value())) {
			@SuppressWarnings("unchecked")
			final ENTITY[] returned = isOne ? array(fromJson(response.body(), this.clazz)) : (ENTITY[]) fromJson(response.body(), this.clazz.arrayType());
			logger.info("{} ENTITY{}: {}", method, isOne ? "" : "s", (Object[]) returned);
			return returned;
		}
		throw new HttpResponseException(response);
	}

	public String url(final ApiType apiType, final MultiValueMap<String, String> parameters) {
		final String url;
		switch(apiType) {
			case SINGLE:   url = "/api/" + this.entitySingleName.toLowerCase()               + RestClient.queryString(parameters); break;
			case BULK:     url = "/api/" + this.entityPluralName.toLowerCase()               + RestClient.queryString(parameters); break;
			case FILTERED: url = "/api/" + this.entityPluralName.toLowerCase() + "/filtered" + RestClient.queryString(parameters); break;
			default: throw new IllegalArgumentException("Invalid API_TYPE " + apiType);
		}
		logger.info("{}{} relative URL: {}", (SINGLE.equals(apiType) ? this.entitySingleName : this.entityPluralName), (FILTERED.equals(apiType) ? " filtered" : ""), url);
		return url;
 	}
}
