package com.github.justincranford.spring.authz.server;

import javax.net.ssl.SSLContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;

import com.github.justincranford.spring.util.config.TlsConfig.TlsSettings;
import com.github.justincranford.spring.util.rest.RestClient;

@SpringBootTest(classes={SpringAuthzServer.class}, webEnvironment=WebEnvironment.RANDOM_PORT, properties={"spring.main.allow-bean-definition-overriding=true"})
@TestPropertySource(properties = {"management.port=0"})
@ComponentScan(basePackages={"com.github.justincranford.spring"})
@ContextConfiguration
//@ActiveProfiles(profiles = { "default","test" })
public class AbstractIT extends com.github.justincranford.spring.AbstractIT {
	@Autowired                 protected ClientRegistrationRepository  clientRegistrationRepository;
	@Autowired                 protected OAuth2AuthorizedClientService oAuth2AuthorizedClientService;
	@Autowired                 protected OAuth2AuthorizationService    oAuth2AuthorizationService;
	@Autowired                 protected UserDetailsService            userDetailsService;
	@Autowired(required=false) protected SSLContext                    clientSslContext;
	@Autowired                 protected TlsSettings                   tlsSettings;
}
