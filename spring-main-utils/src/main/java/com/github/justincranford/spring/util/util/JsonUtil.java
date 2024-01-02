package com.github.justincranford.spring.util.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonUtil {
	public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	public static String toJson(final Object o) throws JsonProcessingException {
		return OBJECT_MAPPER.writeValueAsString(o);
	}

	public static <O> O fromJson(final Class<O> c, final String string) throws JsonProcessingException, JsonMappingException {
		return OBJECT_MAPPER.readValue(string, c);
	}
}
