package com.github.justincranford.spring.util.util;

import org.slf4j.helpers.MessageFormatter;

public class Slf4jUtil {
	public static String format(final String message, Object... args) {
		return MessageFormatter.arrayFormat(message, args).getMessage();
	}
}
