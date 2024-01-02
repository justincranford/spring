package com.github.justincranford.spring.util;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationListener;

import com.github.justincranford.spring.AbstractIT;
import com.github.justincranford.spring.util.config.EventsConfig;

public class EventIT extends AbstractIT {
	@Autowired
    private ApplicationEventPublisher applicationEventPublisher;

	@SpyBean
	@Qualifier("allApplicationEventsListener")
	public ApplicationListener<ApplicationEvent> allApplicationEventsListener;

	@Test
	public void testPublishListenEvent() throws Exception {
        final EventsConfig.Event<String> event = new EventsConfig.Event<>("testPublishListenEvent");
		this.applicationEventPublisher.publishEvent(event);
		verify(this.allApplicationEventsListener, times(1)).onApplicationEvent(event);
    }
}
