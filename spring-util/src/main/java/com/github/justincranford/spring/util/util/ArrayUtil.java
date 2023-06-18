package com.github.justincranford.spring.util.util;

public class ArrayUtil {
	public static <O> O firstOrNull(final O[] array) {
		return (array != null) && (array.length > 0) ? array[0] : null;
	}

	@SafeVarargs
	public static <O> O[] array(final O... array) {
		return array;
	}
}
