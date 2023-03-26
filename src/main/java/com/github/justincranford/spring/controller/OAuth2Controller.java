package com.github.justincranford.spring.controller;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins={"http://127.0.0.1:8080"})
@RestController
@RequestMapping(path="/api/oauth2", produces={APPLICATION_JSON_VALUE})
public class OAuth2Controller {
	@SuppressWarnings("unused")
	private Logger logger = LoggerFactory.getLogger(OAuth2Controller.class);

	@Autowired private ClientRegistrationRepository     clientRegistrationRepository;		// InMemoryReactiveClientRegistrationRepository
	@Autowired private OAuth2AuthorizedClientService    oauth2AuthorizedClientService;		// InMemoryReactiveOAuth2AuthorizedClientService
	@SuppressWarnings("unused")
	@Autowired private OAuth2AuthorizedClientRepository oauth2AuthorizedClientRepository;
//	@Autowired private OAuth2AuthorizedClientManager    oauth2AuthorizedClientManager;

	@GetMapping(path="/client/{registrationId}")
	public ClientRegistration clientRegistration(@PathVariable final String registrationId) {
		return this.clientRegistrationRepository.findByRegistrationId(registrationId);
	}

	// OAuth2AuthorizedClient = {OAuth2AccessToken,OAuth2RefreshToken} => {ClientRegistration, Resource Owner}
	// ServerOAuth2AuthorizedClientRepository => Persist OAuth2AuthorizedClient between requests.
	// Whereas, the primary role of ReactiveOAuth2AuthorizedClientService is to manage OAuth2AuthorizedClient(s) at the application-level.

	@GetMapping(path="/accesstoken/{registrationId}")
	public String index(final Authentication authentication, @PathVariable final String registrationId) {
//		this.oauth2AuthorizedClientRepository.loadAuthorizedClient(registrationId, authentication, (HttpServletRequest) null);
		final OAuth2AuthorizedClient oauth2AuthorizedClient = this.oauth2AuthorizedClientService.loadAuthorizedClient(registrationId, authentication.getName());
		final OAuth2AccessToken      oauth2AccessToken      = oauth2AuthorizedClient.getAccessToken();
		return oauth2AccessToken.getTokenValue();
	}

//	@GetMapping("/accesstoken2/{registrationId}")
//	public String index2(final Authentication authentication, @PathVariable final String registrationId) {
//		final OAuth2AuthorizeRequest oauth2AuthorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(registrationId).principal(authentication).build();
//
//		final OAuth2AuthorizedClient oauth2AuthorizedClient = this.oauth2AuthorizedClientManager.authorize(oauth2AuthorizeRequest);
//		final OAuth2AccessToken      oauth2AccessToken      = oauth2AuthorizedClient.getAccessToken();
//		return oauth2AccessToken.getTokenValue();
//	}

}
