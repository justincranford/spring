package com.github.justincranford.spring.util.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import com.github.justincranford.spring.util.AbstractIT;
import com.github.justincranford.spring.util.config.UserDetailsTestConfig;
import com.github.justincranford.spring.util.config.UserDetailsTestConfig.TestUser;
import com.github.justincranford.spring.util.model.Uptime;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

public class UptimeIT extends AbstractIT {
    @Nested
    static class SuccessPath extends AbstractIT {
    	private Logger logger = LoggerFactory.getLogger(UptimeIT.class);
        public static Stream<TestUser> validTestUsers() {
            return UserDetailsTestConfig.TEST_USERS.stream();
        }

        @ParameterizedTest
        @MethodSource("validTestUsers")
    	public void testUptimeValidUser(final TestUser testUser) {
        	final RequestSpecification requestSpec = RestAssured.given().config(super.restAssuredConfig).auth().basic(UserDetailsTestConfig.APP_USER.username(), UserDetailsTestConfig.APP_USER.password());
    		final Response currentResponse = requestSpec.get(super.baseUrl + "/api/uptime");
    		this.logger.info("Uptime Response:\n{}", currentResponse.asPrettyString());
    		assertEquals(HttpStatus.OK.value(), currentResponse.getStatusCode());
    		assertTrue(currentResponse.jsonPath().getLong("nanos")   > 0L);
    		assertTrue(currentResponse.jsonPath().getFloat("micros") > 0F);
    		assertTrue(currentResponse.jsonPath().getFloat("millis") > 0F);
    		assertTrue(currentResponse.jsonPath().getFloat("secs")   > 0F);

    		Uptime currentUptime = currentResponse.as(Uptime.class);
    		Uptime previousUptime;
    		for (int i=0; i<2; i++) {
    			previousUptime = currentUptime;
    			currentUptime = requestSpec.get(super.baseUrl + "/api/uptime").as(Uptime.class);
    			assertTrue(currentUptime.nanos()  > previousUptime.nanos());
    			assertTrue(currentUptime.micros() > previousUptime.micros());
    			assertTrue(currentUptime.millis() > previousUptime.millis());
    			assertTrue(currentUptime.secs()   > previousUptime.secs());
    		}
    	}
    }

    @Nested
    static class FailurePath extends AbstractIT {
    	private Logger logger = LoggerFactory.getLogger(UptimeIT.class);
    	
        @Test
    	public void testUptimeNoCredentials() {
    		final Response currentResponse = super.restAssuredNoCreds.get(super.baseUrl + "/api/uptime");
    		this.logger.info("Uptime Response:\n{}", currentResponse.asPrettyString());
    		assertEquals(HttpStatus.UNAUTHORIZED.value(), currentResponse.getStatusCode());
    	}

        @Test
    	public void testUptimeInvalidCredentials() {
    		final Response currentResponse = super.restAssuredInvalidCreds.get(super.baseUrl + "/api/uptime");
    		this.logger.info("Uptime Response:\n{}", currentResponse.asPrettyString());
    		assertEquals(HttpStatus.UNAUTHORIZED.value(), currentResponse.getStatusCode());
    	}
    }
}