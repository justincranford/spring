package com.github.justincranford.spring.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonUtil {
	public static String pojoToJsonString(final Object o) {
		try {
			final ObjectMapper objectMapper = new ObjectMapper();
			return objectMapper.writeValueAsString(o);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
			return o.toString();
		}
	}
}
