package com.github.justincranford.spring.util.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
public class UserExceptionControllerAdvice extends ResponseEntityExceptionHandler {
	@ExceptionHandler({ CredentialsExpiredException.class })
	public ResponseEntity<Object> handleUserDisabledException(final Exception ex, final WebRequest request) {
		return handleExceptionInternal(ex, ex.getLocalizedMessage(), new HttpHeaders(), HttpStatus.UNAUTHORIZED, request);
	}
	@ExceptionHandler({ DisabledException.class, LockedException.class, AccountExpiredException.class })
	public ResponseEntity<Object> handleUserForbiddenException(final Exception ex, final WebRequest request) {
		return handleExceptionInternal(ex, ex.getLocalizedMessage(), new HttpHeaders(), HttpStatus.FORBIDDEN, request);
	}
}