package com.github.justincranford.spring.model;

public class OpsUserNotFoundException extends RuntimeException {
	private static final long serialVersionUID = 1L;

	public OpsUserNotFoundException(final String message, final Throwable cause) {
        super(message, cause);
    }

	public OpsUserNotFoundException(final Throwable cause) {
        super(cause);
    }

	public OpsUserNotFoundException() {
        super();
    }
}