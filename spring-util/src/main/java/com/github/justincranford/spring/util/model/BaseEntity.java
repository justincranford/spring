package com.github.justincranford.spring.util.model;

public interface BaseEntity {
	// implementations must override these static methods
	public static String singleName() {
		throw new UnsupportedOperationException();
	}
	public static String pluralName() {
		throw new UnsupportedOperationException();
	}
}
