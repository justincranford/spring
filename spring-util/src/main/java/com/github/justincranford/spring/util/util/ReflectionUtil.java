package com.github.justincranford.spring.util.util;

public class ReflectionUtil {
	public static Object invokeStaticMethod(final Class<?> clazz, final String staticMethodName, final Object... args) {
		try {
			return clazz.getMethod(staticMethodName).invoke(null, args);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
