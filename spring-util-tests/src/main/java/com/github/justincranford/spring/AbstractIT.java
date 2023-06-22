package com.github.justincranford.spring;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;

import com.github.justincranford.spring.AbstractIT.AbstractConfig;

import io.restassured.RestAssured;
import io.restassured.config.RestAssuredConfig;
import io.restassured.config.SSLConfig;
import io.restassured.specification.RequestSpecification;

@SpringBootTest(classes={AbstractConfig.class}, webEnvironment=WebEnvironment.RANDOM_PORT, properties={"spring.main.allow-bean-definition-overriding=true"})
@TestPropertySource(properties = {"management.port=0"})
@ComponentScan(basePackages={"com.github.justincranford.spring"})
@ContextConfiguration
//@ActiveProfiles(profiles = { "default","test" })
@SuppressWarnings("deprecation")
public class AbstractIT {
	protected static final AtomicLong UNIQUE_LONG = new AtomicLong(System.nanoTime());

	@Value("${spring.profiles.active:}") protected String profilesActive;
	@Autowired protected Environment environment;
    @Autowired protected ServletWebServerApplicationContext servletWebServerApplicationContext;
	@Autowired protected TestRestTemplate restTemplate;
	@Autowired protected PasswordEncoder passwordEncoder;
	@Autowired protected String baseUrl;

    @Value(value="${spring.application.name}")              protected String  springApplicationName;
    @Value(value="${local.server.port}")                    protected int     localServerPort;		// same as @LocalServerPort
//	@Value(value="${local.management.port}")                protected int     localManagementPort;	// same as @LocalManagementPort
	@Value(value="${server.address}")                       protected String  serverAddress;
    @Value(value="${server.port}")                          protected int     serverPort;
//	@Value(value="${management.port}")                      protected int     managementPort;
//	@Value(value="${management.server.address}")            protected String  managementServerAddress;
//	@Value(value="${management.server.port}")               protected String  managementServerPort;
    @Value(value="${server.ssl.enabled:false}")             protected boolean serverSslEnabled;
    @Value(value="${server.ssl.auto-config.enabled:false}") protected boolean serverSslAutoConfigEnabled;

	protected final RequestSpecification restAssuredNoCreds      = RestAssured.given().config(restAssuredConfig());
	protected final RequestSpecification restAssuredInvalidCreds = RestAssured.given().config(restAssuredConfig()).auth().basic("invalid", "invalid");
	protected final RequestSpecification restAssuredUptimeCreds  = RestAssured.given().config(restAssuredConfig()).auth().basic("uptime",  "uptime");

	protected RestAssuredConfig restAssuredConfig() {
	    // TODO: Remove relaxedHTTPSValidation(), replace with trustStore()
	    // TODO: Remove allowALlHostnames()
		return RestAssuredConfig.newConfig().sslConfig(SSLConfig.sslConfig().relaxedHTTPSValidation().allowAllHostnames());
	}

	@SpringBootApplication
	@Profile({"default"})
	@ComponentScan({"com.github.justincranford.spring.*"})
	@ConfigurationPropertiesScan({"com.github.justincranford.spring.*"})
	@EnableWebSecurity
	public static class SpringUtilTestApplication {
	}

	@TestConfiguration
	//@Profile("!default")
	public static class AbstractConfig {
		public record TestUser(String username, String password, Collection<String> roles) { }

		public static final TestUser UPTIME_USER  = new TestUser("uptime", "uptime",  Collections.emptySet());
		public static final Set<TestUser> TEST_USERS = Set.of(UPTIME_USER);

		@Bean
		@ConditionalOnMissingBean
		public UserDetailsService users(final PasswordEncoder passwordEncoder) {
			final UserBuilder builder = User.builder().passwordEncoder(passwordEncoder::encode);
			final Collection<UserDetails> users = new ArrayList<>(TEST_USERS.size());
			for (final TestUser u : TEST_USERS) {
				users.add(builder.username(u.username()).password(u.password()).roles(u.roles().toArray(new String[0])).build());
			}
			return new InMemoryUserDetailsManager(users);
		}

		@Bean
		@ConditionalOnMissingBean
		public PasswordEncoder passwordEncoder() {
			return new DelegatingPasswordEncoder("sha256", Collections.singletonMap("sha256", new MessageDigestPasswordEncoder("SHA-256")));
		}

		@Bean
		@ConditionalOnMissingBean
		public String baseUrl() {
			return "";
		}
	}
}
