package com.github.justincranford.spring;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ContextLoaderTests extends SpringBootTestHelper {
	private Logger logger = LoggerFactory.getLogger(ContextLoaderTests.class);

    @Test public void testLoadProperties() throws Exception {
    	final Map<String, Object> map = super.allProperties(super.environment);
    	assertEquals(map.get("spring.application.name"),   super.springApplicationName);
		assertEquals(map.get("local.server.port"),         super.localServerPort);
		assertEquals(map.get("local.management.port"),     super.localManagementPort);
		assertEquals(map.get("server.address"),            super.serverAddress);
//		assertEquals(map.get("server.port"),               super.serverPort);			// Overridden by @SpringBootTest(webEnvironment=WebEnvironment.RANDOM_PORT)
//		assertEquals(map.get("management.server.port"),    super.managementServerPort);	// Overridden by @SpringBootTest(webEnvironment=WebEnvironment.RANDOM_PORT)
		assertEquals(map.get("management.port"),           Integer.toString(super.managementPort));
		assertEquals(map.get("management.server.address"), super.managementServerAddress);

		this.logger.info("${spring.application.name}="   + super.springApplicationName);
		this.logger.info("${local.server.port}="         + super.localServerPort);
		this.logger.info("${local.management.port}="     + super.localManagementPort);
		this.logger.info("${server.address}="            + super.serverAddress);
		this.logger.info("${server.port}="               + super.serverPort);
		this.logger.info("${management.port}="           + super.managementPort);
		this.logger.info("${management.server.address="  + super.managementServerAddress);
		this.logger.info("${management.server.port="     + super.managementServerPort);

		this.logger.info("servletWebServerApplicationContext.getWebServer().getPort()=" + super.servletWebServerApplicationContext.getWebServer().getPort());

    	final StringBuilder sb = new StringBuilder("Properties[" + map.size() + "]:");
    	for (final Map.Entry<String,Object> entry : map.entrySet()) {
    		sb.append("\n - ").append(entry.getKey()).append(": ").append(entry.getValue());
    	}
    	this.logger.info(sb.toString());
    }

    @Test public void testLoadBeans() throws Exception {
		assertThat(super.environment,                        is(notNullValue()));
		assertThat(super.servletWebServerApplicationContext, is(notNullValue()));
		assertThat(super.restTemplate,                       is(notNullValue()));
		assertThat(super.uptimeFactory,                      is(notNullValue()));
		assertThat(super.userDetailsService,                 is(notNullValue()));
		assertThat(super.opsUserController,                  is(notNullValue()));
//		assertThat(super.appUserController,                  is(notNullValue()));
		assertThat(super.opsUserCrudRepository,              is(notNullValue()));
		assertThat(super.appUserCrudRepository,              is(notNullValue()));
		assertThat(super.clientRegistrationRepository,       is(notNullValue()));
		assertThat(super.oauth2AuthorizedClientRepository,   is(notNullValue()));
		assertThat(super.oauth2AuthorizedClientService,      is(notNullValue()));
    }
}
