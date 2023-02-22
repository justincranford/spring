package com.github.justincranford.spring.model.exception;

public class BadRequestException extends BaseException {
	private static final long serialVersionUID = 1L;

	public BadRequestException(final String message, final Throwable cause) {
        super(message, cause);
    }

	public BadRequestException(final Throwable cause) {
        super(cause);
    }

	public BadRequestException() {
        super();
    }
}