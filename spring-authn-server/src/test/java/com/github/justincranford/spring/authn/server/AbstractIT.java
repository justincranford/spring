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
import com.github.justincranford.spring.util.config.TlsConfig.TlsSettings;
import com.github.justincranford.spring.util.rest.RestClient;

@SpringBootTest(classes={SpringAuthnServer.class}, webEnvironment=WebEnvironment.RANDOM_PORT, properties={"spring.main.allow-bean-definition-overriding=true"})
@TestPropertySource(properties = {"management.port=0"})
@ComponentScan(basePackages={"com.github.justincranford.spring"})
@ContextConfiguration
//@ActiveProfiles(profiles = { "default","test" })
public class AbstractIT extends com.github.justincranford.spring.AbstractIT {
	@Autowired                 protected UserController     userController;
	@Autowired                 protected UserDetailsService userDetailsService;
	@Autowired                 protected UserCrudRepository userCrudRepository;
	@Autowired(required=false) protected SSLContext         clientSslContext;
	@Autowired                 protected TlsSettings        tlsSettings;

	protected RestClient restClientOpsAdmin() {
		return new RestClient(super.baseUrl, new UsernamePasswordAuthenticationToken("opsadmin", "opsadmin".toCharArray()), clientSslContext);
	}
	protected RestClient restClientOpsUser() {
		return new RestClient(super.baseUrl, new UsernamePasswordAuthenticationToken("opsuser", "opsuser".toCharArray()), clientSslContext);
	}
	protected RestClient restClientAppAdmin() {
		return new RestClient(super.baseUrl, new UsernamePasswordAuthenticationToken("appadmin", "appadmin".toCharArray()), clientSslContext);
	}
	protected RestClient restClientAppUser() {
		return new RestClient(super.baseUrl, new UsernamePasswordAuthenticationToken("appuser", "appuser".toCharArray()), clientSslContext);
	}
	protected RestClient restClientInvalidCreds() {
		return new RestClient(super.baseUrl, new UsernamePasswordAuthenticationToken("invalid" , "invalid".toCharArray()), clientSslContext);
	}
	protected RestClient restClientNoCreds() {
		return new RestClient(super.baseUrl, null, clientSslContext);
	}
}
