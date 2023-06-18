package com.github.justincranford.spring.authn.server;

import javax.net.ssl.SSLContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;

import com.github.justincranford.spring.authn.server.controller.UserController;
import com.github.justincranford.spring.authn.server.model.UserCrudRepository;
import com.github.justincranford.spring.util.config.RestConfig;
import com.github.justincranford.spring.util.rest.RestClient;

@SpringBootTest(classes={RestConfig.class, SpringAuthnServer.class}, webEnvironment=WebEnvironment.RANDOM_PORT, properties={"spring.main.allow-bean-definition-overriding=true"})
@TestPropertySource(properties = {"management.port=0"})
@ComponentScan(basePackages={"com.github.justincranford.spring"})
@ContextConfiguration
//@ActiveProfiles(profiles = { "default","test" })
public class AbstractIT extends com.github.justincranford.spring.AbstractIT {
	@Autowired protected UserController     userController;
	@Autowired protected UserDetailsService userDetailsService;
	@Autowired protected UserCrudRepository userCrudRepository;

	protected SSLContext sslContext = RestClient.createClientSslContext();
	static {
		System.getProperties().setProperty("jdk.internal.httpclient.disableHostnameVerification", Boolean.TRUE.toString());
	}

	protected RestClient restClientOpsAdmin() {
		return new RestClient(super.baseUrl, new UsernamePasswordAuthenticationToken("opsadmin", "opsadmin".toCharArray()), sslContext);
	}
	protected RestClient restClientOpsUser() {
		return new RestClient(super.baseUrl, new UsernamePasswordAuthenticationToken("opsuser", "opsuser".toCharArray()), sslContext);
	}
	protected RestClient restClientAppAdmin() {
		return new RestClient(super.baseUrl, new UsernamePasswordAuthenticationToken("appadmin", "appadmin".toCharArray()), sslContext);
	}
	protected RestClient restClientAppUser() {
		return new RestClient(super.baseUrl, new UsernamePasswordAuthenticationToken("appuser", "appuser".toCharArray()), sslContext);
	}
	protected RestClient restClientInvalidCreds() {
		return new RestClient(super.baseUrl, new UsernamePasswordAuthenticationToken("invalid" , "invalid".toCharArray()), sslContext);
	}
	protected RestClient restClientNoCreds() {
		return new RestClient(super.baseUrl, null, sslContext);
	}
}
