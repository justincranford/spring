package com.github.justincranford.spring.util.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonUtil {
	public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
	public static String pojoToJsonString(final Object o) {
		try {
			return OBJECT_MAPPER.writeValueAsString(o);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
			return o.toString();
		}
	}
}
