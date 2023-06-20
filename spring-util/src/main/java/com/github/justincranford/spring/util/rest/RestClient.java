package com.github.justincranford.spring.util.rest;

import static com.github.justincranford.spring.util.util.Slf4jUtil.format;

import java.io.IOException;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;

import org.apache.logging.log4j.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

public class RestClient {
	@SuppressWarnings("unused")
	private static Logger logger = LoggerFactory.getLogger(RestClient.class);

	public static final String CONTENT_TYPE = "Content-Type";
	public static final String APPLICATION_JSON_UTF8 = "application/json; charset=UTF-8";
	public static final MultiValueMap<String, String> HEADERS = RestClient.parameters(CONTENT_TYPE, APPLICATION_JSON_UTF8);

	public static enum ApiType { SINGLE, BULK, FILTERED }

	protected final String baseUrl;
	protected final UsernamePasswordAuthenticationToken credentials;
	protected final SSLContext sslContext;

	public RestClient(final String baseUrl, final UsernamePasswordAuthenticationToken credentials, final SSLContext sslContext) {
		this.baseUrl = baseUrl;
		this.credentials = credentials;
		this.sslContext = sslContext;
	}

	public RestClient(final RestClient restClient) {
		this.baseUrl = restClient.baseUrl;
		this.credentials = restClient.credentials;
		this.sslContext = restClient.sslContext;
	}

	public UsernamePasswordAuthenticationToken credentials() {
		return this.credentials;
	}

	public SSLContext sslContext() {
		return this.sslContext;
	}

	// TODO Don't return HttpResponse object, return record of statusCode, headers, and body
	public <T> HttpResponse<T> doRequest(
		final String relativeUri,
		final String method,
		final MultiValueMap<String, String> headers,
		final BodyPublisher bodyPublisher,
		final BodyHandler<T> bodyHandler
	) throws URISyntaxException, IOException, InterruptedException {
		final HttpClient.Builder clientBuilder = HttpClient.newBuilder()
			.connectTimeout(Duration.of(3, ChronoUnit.SECONDS))
			.followRedirects(Redirect.NEVER);
		if (this.credentials != null) {
			clientBuilder.authenticator(new Authenticator() {
				@Override protected PasswordAuthentication getPasswordAuthentication() {
					return new PasswordAuthentication(credentials.getName(), (char[]) credentials.getCredentials());
				}
			});
		}
		if (sslContext != null) {
			clientBuilder.sslContext(this.sslContext);
		}
		final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
			.uri(new URI(this.baseUrl + relativeUri))
			.method(method, bodyPublisher);
		if (headers != null) {
			for (final Map.Entry<String, List<String>> entry : headers.entrySet()) {
				for (final String value : entry.getValue()) {
					requestBuilder.header(entry.getKey(), value);
				}
			}
		}
		return clientBuilder.build().send(requestBuilder.build(), bodyHandler);
	}

	public static MultiValueMap<String, String> merge(final MultiValueMap<String, String> additionalParameters, final Object... objects) {
		return merge(additionalParameters, parameters(objects));
	}

	@SafeVarargs
	public static MultiValueMap<String, String> merge(final MultiValueMap<String, String>... maps) {
		final MultiValueMap<String, String> merged = new LinkedMultiValueMap<String, String>();
		Arrays.stream(maps).forEach(map -> merged.putAll(map));
		return merged;
	}

	public static MultiValueMap<String, String> parameters(final Object... objects) {
		if ((objects == null) || (objects.length == 0)) {
			throw new IllegalArgumentException("Key value objects must not be null");
		} else if (objects.length % 2 == 1) {
			throw new IllegalArgumentException("Key value objects must be even number");
		}
		final LinkedMultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		for (int i=0; i<objects.length; i+=2) {
			if (objects[i+1] != null) {
				if (objects[i+1] instanceof Collection<?> collection) {
					for (final Object value : collection) {
						parameters.add(objects[i].toString(), value.toString());
					}
				} else if (objects[i+1] instanceof String[] array) {
					for (final Object value : array) {
						parameters.add(objects[i].toString(), value.toString());
					}
				} else if (objects[i+1] instanceof Object[] array) {
					for (final Object value : array) {
						parameters.add(objects[i].toString(), value.toString());
					}
				} else {
					parameters.add(objects[i].toString(), objects[i+1].toString());
				}
			}
		}
		return parameters;
	}

	public static String queryString(final MultiValueMap<String, String> parameters) {
		final String queryString = UriComponentsBuilder.newInstance().queryParams(parameters).encode().build().getQuery();
		return (Strings.isEmpty(queryString) ? "" : "?" + queryString);
	}

	public static String pathSuffix(final Long id) {
		return (id == null) ? "" : "/" + id;
	}

	public static class HttpResponseException extends Exception {
		private static final long serialVersionUID = 1L;
		private final int statusCode;
		private final String headers;
		private final String body;
		public HttpResponseException(final HttpResponse<?> response) {
			super(format("Unexpected response, status: {}, \nheaders: {}, \nbody: {}", response.statusCode(), response.headers(), response.body()));
			this.statusCode = response.statusCode();
			this.headers = response.headers().toString();
			this.body = response.body().toString();
		}
		public int statusCode() {
			return this.statusCode;
		}
		public String headers() {
			return this.headers;
		}
		public String body() {
			return this.body;
		}
	}
}
