package com.github.justincranford.spring.authn.server.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import com.github.justincranford.spring.authn.server.model.AppUserNotFoundException;
import com.github.justincranford.spring.authn.server.model.OpsUserNotFoundException;

@ControllerAdvice
public class UserControllerAdvice extends ResponseEntityExceptionHandler {
	@ExceptionHandler({ OpsUserNotFoundException.class, AppUserNotFoundException.class })
	protected ResponseEntity<Object> handleNotFound(final Exception ex, final WebRequest request) {
		return handleExceptionInternal(ex, ex.getLocalizedMessage(), new HttpHeaders(), HttpStatus.NOT_FOUND, request);
	}
}