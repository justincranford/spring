package com.github.justincranford.spring.util.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

@Configuration
public class EventsConfig {

	public static class Event<T> extends ApplicationEvent {
		private static final long serialVersionUID = 1L;
	    public Event(final T t) { super(t); }
	}

	@Bean
	public AuthenticationEventPublisher authenticationEventPublisher(final ApplicationEventPublisher applicationEventPublisher) {
	    final DefaultAuthenticationEventPublisher defaultAuthenticationEventPublisher = new DefaultAuthenticationEventPublisher(applicationEventPublisher);
	    defaultAuthenticationEventPublisher.setDefaultAuthenticationFailureEvent(NonMappedAuthenticationFailureEvent.class);
	    return defaultAuthenticationEventPublisher;
	}

	public static class NonMappedAuthenticationFailureEvent extends AbstractAuthenticationFailureEvent {
		private static final long serialVersionUID = 1L;
	    public NonMappedAuthenticationFailureEvent(final Authentication authentication, final AuthenticationException exception) {
	    	super(authentication, exception);
    	}
	}

	@Bean
	public ApplicationListener<AbstractAuthenticationEvent> allAuthenticationEventsListener() {
		return new ApplicationListener<AbstractAuthenticationEvent>() {
			private Logger logger = LoggerFactory.getLogger("AllAuthenticationEventsListener");
		    @Override public void onApplicationEvent(AbstractAuthenticationEvent event) {
		    	if (event instanceof AbstractAuthenticationFailureEvent failure) {
			    	// DefaultAuthenticationEventPublisher wraps exceptions in these events, and then publishes them
		    		//  AuthenticationFailureBadCredentialsEvent
		    		//  AuthenticationFailureCredentialsExpiredEvent
		    		//  AuthenticationFailureDisabledEvent
		    		//  AuthenticationFailureExpiredEvent
		    		//  AuthenticationFailureLockedEvent
		    		//  AuthenticationFailureProviderNotFoundEvent
		    		//  AuthenticationFailureProxyUntrustedEvent
		    		//  AuthenticationFailureServiceExceptionEvent
			        this.logger.warn("{} [source={}]", event.getClass().getSimpleName(), event.getSource(), failure.getException());
		    	} else {
			    	// DefaultAuthenticationEventPublisher has helpers for publishing some of these events
		    		//  AuthenticationSuccessEvent
		    		//  AuthenticationSwitchUserEvent
		    		//  InteractiveAuthenticationSuccessEvent
		    		//  LogoutSuccessEvent
		    		//  SessionFixationProtectionEvent
			        this.logger.info("{} [source={}]", event.getClass().getSimpleName(), event.getSource());
		    	}
		    }
		};
	}

	@Bean
	public ApplicationListener<ApplicationEvent> allApplicationEventsListener() {
		return new ApplicationListener<ApplicationEvent>() {
			private Logger logger = LoggerFactory.getLogger("AllApplicationEventsListener");
		    @Override public void onApplicationEvent(ApplicationEvent event) {
		        this.logger.trace("{} [source={}]", event.getClass().getSimpleName(), event.getSource());
		    }
		};
	}
}
