package com.github.justincranford.spring.authn.server.model;

public class UserNotFoundException extends RuntimeException {
	private static final long serialVersionUID = 1L;

	public UserNotFoundException(final String message, final Throwable cause) {
        super(message, cause);
    }

	public UserNotFoundException(final Throwable cause) {
        super(cause);
    }

	public UserNotFoundException() {
        super();
    }
}