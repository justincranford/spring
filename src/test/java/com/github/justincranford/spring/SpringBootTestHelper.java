package com.github.justincranford.spring;

import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.TestPropertySource;

import com.github.justincranford.spring.Application.UptimeFactory;
import com.github.justincranford.spring.controller.api.user.ops.OpsUserController;
import com.github.justincranford.spring.model.user.app.AppUserCrudRepository;
import com.github.justincranford.spring.model.user.ops.OpsUserCrudRepository;
import com.github.justincranford.spring.security.PasswordEncoderTestConfiguration;

import io.restassured.RestAssured;
import io.restassured.config.RestAssuredConfig;
import io.restassured.config.SSLConfig;
import io.restassured.specification.RequestSpecification;

@SpringBootTest(classes={Application.class,PasswordEncoderTestConfiguration.class}, webEnvironment=WebEnvironment.RANDOM_PORT, properties={"spring.main.allow-bean-definition-overriding=true"})
@TestPropertySource(properties = {"management.port=0"})
//@ActiveProfiles(profiles = { "default","test" })
public class SpringBootTestHelper {
	@SuppressWarnings("unused")
	private Logger logger = LoggerFactory.getLogger(SpringBootTestHelper.class);

	protected static final AtomicLong UNIQUE_LONG = new AtomicLong(System.nanoTime());

	@Autowired protected Environment environment;
    @Autowired protected ServletWebServerApplicationContext servletWebServerApplicationContext;
	@Autowired protected TestRestTemplate restTemplate;
	@Autowired protected UptimeFactory uptimeFactory;
	@Autowired protected UserDetailsService userDetailsService;
	@Autowired protected OpsUserController opsUserController;
//	@Autowired protected AppUserController appUserController;
	@Autowired protected OpsUserCrudRepository opsUserCrudRepository;
	@Autowired protected AppUserCrudRepository appUserCrudRepository;
	// Oauth2 Client
	@Autowired protected ClientRegistrationRepository     clientRegistrationRepository;
	@Autowired protected OAuth2AuthorizedClientService    oauth2AuthorizedClientService;
	@Autowired protected OAuth2AuthorizedClientRepository oauth2AuthorizedClientRepository;
	// Oauth2 Authorization Server
	@Autowired protected RegisteredClientRepository       registeredClientRepository;

    @Value(value="${spring.application.name}")   protected String springApplicationName;
    @Value(value="${local.server.port}")         protected int    localServerPort;		// same as @LocalServerPort
    @Value(value="${local.management.port}")     protected int    localManagementPort;	// same as @LocalManagementPort
	@Value(value="${server.address}")            protected String serverAddress;
    @Value(value="${server.port}")               protected int    serverPort;
    @Value(value="${management.port}")           protected int    managementPort;
    @Value(value="${management.server.address}") protected String managementServerAddress;
    @Value(value="${management.server.port}")    protected String managementServerPort;

    // TODO: Remove relaxedHTTPSValidation(), replace with trustStore()
    // TODO: Remove allowALlHostnames()
    protected final RestAssuredConfig x = RestAssuredConfig.newConfig().sslConfig(SSLConfig.sslConfig().relaxedHTTPSValidation().allowAllHostnames());
	protected final RequestSpecification restAssuredNoCreds       = RestAssured.given().config(x);
	protected final RequestSpecification restAssuredInvalidCreds  = RestAssured.given().config(x).auth().basic("invalid",  "invalid");
	protected final RequestSpecification restAssuredOpsAdminCreds = RestAssured.given().config(x).auth().basic("opsadmin", "opsadmin");
	protected final RequestSpecification restAssuredOpsUserCreds  = RestAssured.given().config(x).auth().basic("opsuser",  "opsuser");
	protected final RequestSpecification restAssuredAppAdminCreds = RestAssured.given().config(x).auth().basic("appadmin", "appadmin");
	protected final RequestSpecification restAssuredAppUserCreds  = RestAssured.given().config(x).auth().basic("appuser",  "appuser");

	@BeforeAll public static void beforeClass() {
		// do nothing
	}

	@AfterAll public static void afterClass() {
		// do nothing
	}

	protected String baseUrl;
	@BeforeEach public void beforeEach() throws Exception {
		this.baseUrl = "https://localhost:" + this.localServerPort; // random port
	}

	@AfterEach public void afterEach() throws Exception {
		// do nothing
	}

	protected static Map<String, Object> allProperties(final Environment environment) {
	    final Map<String, Object> map = new TreeMap<>();
	    if (environment instanceof ConfigurableEnvironment) {
	        for (PropertySource<?> propertySource : ((ConfigurableEnvironment) environment).getPropertySources()) {
	            if (propertySource instanceof EnumerablePropertySource) {
	                for (String key : ((EnumerablePropertySource<?>) propertySource).getPropertyNames()) {
	                    map.put(key, propertySource.getProperty(key));
	                }
	            }
	        }
	    }
	    return map;
	}
}
