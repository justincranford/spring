package com.github.justincranford.spring.model.exception;

public class BaseException extends RuntimeException {
	private static final long serialVersionUID = 1L;

	public BaseException(final String message, final Throwable cause) {
        super(message, cause);
    }

	public BaseException(final Throwable cause) {
        super(cause);
    }

	public BaseException() {
        super();
    }
}