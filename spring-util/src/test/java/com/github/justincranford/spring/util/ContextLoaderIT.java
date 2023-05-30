package com.github.justincranford.spring.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.github.justincranford.spring.AbstractIT;

public class ContextLoaderIT extends AbstractIT {
	private Logger logger = LoggerFactory.getLogger(ContextLoaderIT.class);

	@Autowired
	private Map<String,Object> metaProperties;

	@Test
	public void testLoadProperties() throws Exception {
    	@SuppressWarnings("unchecked")
		final Map<String,Object> allProperties = (Map<String, Object>) this.metaProperties.get("allProperties");
    	final StringBuilder sb = new StringBuilder("Properties[" + allProperties.size() + "]:");
		for (final Map.Entry<String,Object> entry : allProperties.entrySet()) {
    		sb.append("\n - ").append(entry.getKey()).append(": ").append(entry.getValue());
    	}
    	this.logger.info(sb.toString());
    	assertEquals(allProperties.get("spring.application.name"),   super.springApplicationName);
//		assertEquals(allProperties.get("local.server.port"),         super.localServerPort);
//		assertEquals(allProperties.get("local.management.port"),     super.localManagementPort);
		assertEquals(allProperties.get("server.address"),            super.serverAddress);
//		assertEquals(allProperties.get("server.port"),               super.serverPort);			// Overridden by @SpringBootTest(webEnvironment=WebEnvironment.RANDOM_PORT)
//		assertEquals(allProperties.get("management.server.port"),    super.managementServerPort);	// Overridden by @SpringBootTest(webEnvironment=WebEnvironment.RANDOM_PORT)
//		assertEquals(allProperties.get("management.port"),           Integer.toString(super.managementPort));
//		assertEquals(allProperties.get("management.server.address"), super.managementServerAddress);

		this.logger.info("${spring.application.name}="   + super.springApplicationName);
//		this.logger.info("${local.server.port}="         + super.localServerPort);
//		this.logger.info("${local.management.port}="     + super.localManagementPort);
		this.logger.info("${server.address}="            + super.serverAddress);
		this.logger.info("${server.port}="               + super.serverPort);
//		this.logger.info("${management.port}="           + super.managementPort);
//		this.logger.info("${management.server.address="  + super.managementServerAddress);
//		this.logger.info("${management.server.port="     + super.managementServerPort);

		this.logger.info("servletWebServerApplicationContext.getWebServer().getPort()=" + super.servletWebServerApplicationContext.getWebServer().getPort());
    }

    @Test public void testLoadBeans() throws Exception {
		assertThat(super.environment,                        is(notNullValue()));
		assertThat(super.servletWebServerApplicationContext, is(notNullValue()));
		assertThat(super.restTemplate,                       is(notNullValue()));
		assertThat(super.passwordEncoder,                    is(notNullValue()));
    }
}
