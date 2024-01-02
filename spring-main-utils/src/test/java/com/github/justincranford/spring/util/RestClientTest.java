package com.github.justincranford.spring.util;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

public class RestClientTest {
	@Test
	public void withoutEncode() {
		final MultiValueMap<String, String> queryParameters = new LinkedMultiValueMap<>();
		queryParameters.add("fullname", "First Last");
		assertThat(UriComponentsBuilder.newInstance().queryParams(queryParameters).build().getQuery()).isEqualTo("fullname=First Last");
	}

	@Test
	public void withEncode() {
		final MultiValueMap<String, String> queryParameters = new LinkedMultiValueMap<>();
		queryParameters.add("fullname", "First Last");
		assertThat(UriComponentsBuilder.newInstance().queryParams(queryParameters).encode().build().getQuery()).isEqualTo("fullname=First%20Last");
	}
}
