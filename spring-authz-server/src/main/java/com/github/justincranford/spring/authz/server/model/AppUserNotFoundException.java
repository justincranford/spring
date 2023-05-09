package com.github.justincranford.spring.authz.server.model;

public class AppUserNotFoundException extends RuntimeException {
	private static final long serialVersionUID = 1L;

	public AppUserNotFoundException(final String message, final Throwable cause) {
        super(message, cause);
    }

	public AppUserNotFoundException(final Throwable cause) {
        super(cause);
    }

	public AppUserNotFoundException() {
        super();
    }
}