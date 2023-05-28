package com.github.justincranford.spring.util;

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

import com.github.justincranford.spring.util.AbstractConfig.TestUser;
import com.github.justincranford.spring.util.model.Uptime;

import io.restassured.response.Response;

public class UptimeIT extends AbstractIT {
	private Logger logger = LoggerFactory.getLogger(UptimeIT.class);

    @Nested
    class SuccessPath extends AbstractIT {
        public static Stream<TestUser> validTestUsers() {
            return AbstractConfig.TEST_USERS.stream();
        }

        @ParameterizedTest
        @MethodSource("validTestUsers")
    	public void testUptimeValidUser(final TestUser testUser) {
        	final Response currentResponse = super.restAssuredUptimeCreds.get(super.baseUrl + "/api/uptime");
    		UptimeIT.this.logger.info("Uptime Response:\n{}", currentResponse.asPrettyString());
    		assertEquals(HttpStatus.OK.value(), currentResponse.getStatusCode());
    		assertTrue(currentResponse.jsonPath().getLong("nanos")   > 0L);
    		assertTrue(currentResponse.jsonPath().getFloat("micros") > 0F);
    		assertTrue(currentResponse.jsonPath().getFloat("millis") > 0F);
    		assertTrue(currentResponse.jsonPath().getFloat("secs")   > 0F);

    		Uptime currentUptime = currentResponse.as(Uptime.class);
    		Uptime previousUptime;
    		for (int i=0; i<2; i++) {
    			previousUptime = currentUptime;
    			currentUptime = super.restAssuredUptimeCreds.get(super.baseUrl + "/api/uptime").as(Uptime.class);
    			assertTrue(currentUptime.nanos()  > previousUptime.nanos());
    			assertTrue(currentUptime.micros() > previousUptime.micros());
    			assertTrue(currentUptime.millis() > previousUptime.millis());
    			assertTrue(currentUptime.secs()   > previousUptime.secs());
    		}
    	}
    }

    @Nested
    class FailurePath extends AbstractIT {
        @Test
    	public void testUptimeNoCredentials() {
    		final Response currentResponse = super.restAssuredNoCreds.get(super.baseUrl + "/api/uptime");
    		UptimeIT.this.logger.info("Uptime Response:\n{}", currentResponse.asPrettyString());
    		assertEquals(HttpStatus.UNAUTHORIZED.value(), currentResponse.getStatusCode());
    	}

        @Test
    	public void testUptimeInvalidCredentials() {
    		final Response currentResponse = super.restAssuredInvalidCreds.get(super.baseUrl + "/api/uptime");
    		UptimeIT.this.logger.info("Uptime Response:\n{}", currentResponse.asPrettyString());
    		assertEquals(HttpStatus.UNAUTHORIZED.value(), currentResponse.getStatusCode());
    	}
    }
}