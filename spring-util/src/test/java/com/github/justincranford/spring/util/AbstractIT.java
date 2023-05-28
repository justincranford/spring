package com.github.justincranford.spring.util;

import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;

import com.github.justincranford.spring.util.config.PasswordEncoderITConfig;
import com.github.justincranford.spring.util.config.PropertiesITConfig;
import com.github.justincranford.spring.util.config.RestITConfig;
import com.github.justincranford.spring.util.config.UserDetailsITConfig;

import io.restassured.RestAssured;
import io.restassured.config.RestAssuredConfig;
import io.restassured.config.SSLConfig;
import io.restassured.specification.RequestSpecification;

@SpringBootTest(classes={RestITConfig.class, PropertiesITConfig.class, PasswordEncoderITConfig.class, UserDetailsITConfig.class}, webEnvironment=WebEnvironment.RANDOM_PORT, properties={"spring.main.allow-bean-definition-overriding=true"})
@TestPropertySource(properties = {"management.port=0"})
@ComponentScan(basePackages={"com.github.justincranford.spring.util"})
@ContextConfiguration
//@ActiveProfiles(profiles = { "default","test" })
public class AbstractIT {
	@SuppressWarnings("unused")
	private Logger logger = LoggerFactory.getLogger(AbstractIT.class);

	protected static final AtomicLong UNIQUE_LONG = new AtomicLong(System.nanoTime());

	@Value("${spring.profiles.active:}") protected String profilesActive;
	@Autowired protected Environment environment;
    @Autowired protected ServletWebServerApplicationContext servletWebServerApplicationContext;
	@Autowired protected TestRestTemplate restTemplate;
	@Autowired protected PasswordEncoder passwordEncoder;

    @Value(value="${spring.application.name}")                     protected String  springApplicationName;
    @Value(value="${local.server.port}")                           protected int     localServerPort;		// same as @LocalServerPort
//	@Value(value="${local.management.port}")                       protected int     localManagementPort;	// same as @LocalManagementPort
	@Value(value="${server.address}")                              protected String  serverAddress;
    @Value(value="${server.port}")                                 protected int     serverPort;
//	@Value(value="${management.port}")                             protected int     managementPort;
//	@Value(value="${management.server.address}")                   protected String  managementServerAddress;
//	@Value(value="${management.server.port}")                      protected String  managementServerPort;
    @Value(value="${server.ssl.enabled:false}")                    protected boolean serverSslEnabled;
    @Value(value="${server.ssl.auto-generate-certificates:false}") protected boolean serverSslAutoGenerateCertificates;

    // TODO: Remove relaxedHTTPSValidation(), replace with trustStore()
    // TODO: Remove allowALlHostnames()
    protected final RestAssuredConfig    restAssuredConfig       = RestAssuredConfig.newConfig().sslConfig(SSLConfig.sslConfig().relaxedHTTPSValidation().allowAllHostnames());
	protected final RequestSpecification restAssuredNoCreds      = RestAssured.given().config(restAssuredConfig);
	protected final RequestSpecification restAssuredInvalidCreds = RestAssured.given().config(restAssuredConfig).auth().basic("invalid", "invalid");
	protected final RequestSpecification restAssureAppUserCreds  = RestAssured.given().config(restAssuredConfig).auth().basic(UserDetailsITConfig.APP_USER.username(), UserDetailsITConfig.APP_USER.password());
	protected final RequestSpecification restAssureAppAdminCreds = RestAssured.given().config(restAssuredConfig).auth().basic(UserDetailsITConfig.APP_ADMIN.username(), UserDetailsITConfig.APP_ADMIN.password());
	protected final RequestSpecification restAssureOpsUserCreds  = RestAssured.given().config(restAssuredConfig).auth().basic(UserDetailsITConfig.OPS_USER.username(), UserDetailsITConfig.OPS_USER.password());
	protected final RequestSpecification restAssureOpsAdminCreds = RestAssured.given().config(restAssuredConfig).auth().basic(UserDetailsITConfig.OPS_ADMIN.username(), UserDetailsITConfig.OPS_ADMIN.password());
}
