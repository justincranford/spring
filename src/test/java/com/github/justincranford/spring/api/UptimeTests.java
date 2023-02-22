package com.github.justincranford.spring.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import com.github.justincranford.spring.Application.Uptime;
import com.github.justincranford.spring.SpringBootTestHelper;

import io.restassured.response.Response;

public class UptimeTests extends SpringBootTestHelper {
	private Logger logger = LoggerFactory.getLogger(UptimeTests.class);

	@Test
	public void testUptime() {
		Response currentResponse = this.restAssuredOpsUserCreds.get(super.baseUrl + "/api/uptime");
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
			currentUptime = this.restAssuredOpsUserCreds.get(super.baseUrl + "/api/uptime").as(Uptime.class);
			assertTrue(currentUptime.nanos()  > previousUptime.nanos());
			assertTrue(currentUptime.micros() > previousUptime.micros());
			assertTrue(currentUptime.millis() > previousUptime.millis());
			assertTrue(currentUptime.secs()   > previousUptime.secs());
		}
	}
}