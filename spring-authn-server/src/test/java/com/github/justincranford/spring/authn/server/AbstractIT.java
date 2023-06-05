package com.github.justincranford.spring.authn.server;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;

import com.github.justincranford.spring.authn.server.controller.UserController;
import com.github.justincranford.spring.authn.server.model.UserCrudRepository;
import com.github.justincranford.spring.util.config.RestConfig;

import io.restassured.RestAssured;
import io.restassured.specification.RequestSpecification;

@SpringBootTest(classes={RestConfig.class, SpringAuthnServer.class}, webEnvironment=WebEnvironment.RANDOM_PORT, properties={"spring.main.allow-bean-definition-overriding=true"})
@TestPropertySource(properties = {"management.port=0"})
@ComponentScan(basePackages={"com.github.justincranford.spring"})
@ContextConfiguration
//@ActiveProfiles(profiles = { "default","test" })
public class AbstractIT extends com.github.justincranford.spring.AbstractIT {
	@Autowired protected UserController     userController;
	@Autowired protected UserDetailsService userDetailsService;
	@Autowired protected UserCrudRepository userCrudRepository;

	protected final RequestSpecification restAssuredOpsAdminCreds = RestAssured.given().config(this.restAssuredConfig).auth().basic("opsadmin", "opsadmin");
	protected final RequestSpecification restAssuredOpsUserCreds  = RestAssured.given().config(this.restAssuredConfig).auth().basic("opsuser",  "opsuser");
	protected final RequestSpecification restAssuredAppAdminCreds = RestAssured.given().config(this.restAssuredConfig).auth().basic("appadmin", "appadmin");
	protected final RequestSpecification restAssuredAppUserCreds  = RestAssured.given().config(this.restAssuredConfig).auth().basic("appuser",  "appuser");
}
