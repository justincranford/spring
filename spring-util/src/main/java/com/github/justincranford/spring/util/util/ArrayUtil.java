package com.github.justincranford.spring.util.util;

import java.lang.reflect.Array;
import java.util.stream.IntStream;

public class ArrayUtil {
	public static <O> O firstOrNull(final O[] array) {
		return (array != null) && (array.length > 0) ? array[0] : null;
	}

	@SuppressWarnings("unchecked")
	@SafeVarargs
	public static <O> O[] array(final O... array) {
		if ((array != null) && (array.length != 0)) {
			final Class<O> clazz = (Class<O>) array[0].getClass();
			final O[] array2 = (O[]) Array.newInstance(clazz, array.length);
			IntStream.range(0, array.length).forEach(i -> array2[i] = array[i]);
			return array2;
		}
		return array;
	}
}
