package com.github.justincranford.spring.security;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.test.context.junit.jupiter.EnabledIf;

import com.github.justincranford.spring.SpringBootTestHelper;

public class TestOauth2Config extends SpringBootTestHelper {
	private Logger logger = LoggerFactory.getLogger(TestOauth2Config.class);

	@BeforeEach
	public void beforeEach() throws Exception {
		super.beforeEach();
	}

	@AfterEach
	public void afterEach() throws Exception {
		super.afterEach();
	}

	@EnabledIf(expression = "#{environment.acceptsProfiles('oauth2')}", loadContext = true)
	@Test
	public void testClientRegistrationRepository() {
//		Assumptions.assumeThat(super.profilesActive.split(",")).contains("oauth2");
//		ClientRegistration clientRegistration1 = ClientRegistrations.fromIssuerLocation("https://idp.example.com/issuer").build();
//		ClientRegistration clientRegistration2 = ClientRegistrations.fromOidcIssuerLocation("").build();

		// Bean: ClientRegistrationRepository
		// Prop: spring.security.oauth2.client.registration.[registrationId].* => ClientRegistration => ClientRegistrationRepository (InMemoryClientRegistrationRepository)
		// OAuth2ClientProperties
		assertThat(super.clientRegistrationRepository, is(notNullValue()));
		assertThat(super.clientRegistrationRepository.findByRegistrationId("facebook-login"), is(notNullValue()));
		final ClientRegistration facebook = super.clientRegistrationRepository.findByRegistrationId("facebook-login");
		assertThat(facebook, is(notNullValue()));
		assertThat(facebook.getRegistrationId(), is(equalTo("facebook-login")));
		assertThat(facebook.getClientAuthenticationMethod(), is(equalTo(ClientAuthenticationMethod.CLIENT_SECRET_POST)));
		assertThat(facebook.getClientId(), is(notNullValue()));
		assertThat(facebook.getClientName(), is(notNullValue()));
		assertThat(facebook.getClientSecret(), is(notNullValue()));
		assertThat(facebook.getAuthorizationGrantType(), is(equalTo(AuthorizationGrantType.AUTHORIZATION_CODE)));
		assertThat(facebook.getScopes(), hasItems("email", "public_profile"));
//		assertThat(facebook.getScopes(), hasItems("openid", "email", "profile"));
		assertThat(facebook.getRedirectUri(), is(notNullValue()));
		assertThat(facebook.getProviderDetails(), is(notNullValue()));
		assertThat(facebook.getProviderDetails().getAuthorizationUri(), is(equalTo("https://www.facebook.com/v2.8/dialog/oauth")));
		assertThat(facebook.getProviderDetails().getTokenUri(), is(equalTo("https://graph.facebook.com/v2.8/oauth/access_token")));
		assertThat(facebook.getProviderDetails().getJwkSetUri(), is(nullValue()));	// TODO
		assertThat(facebook.getProviderDetails().getIssuerUri(), is(nullValue()));
		assertThat(facebook.getProviderDetails().getUserInfoEndpoint(), is(notNullValue()));

		assertThat(facebook.getProviderDetails().getConfigurationMetadata(), is(notNullValue()));
		assertThat(facebook.getProviderDetails().getUserInfoEndpoint().getUri(), is(equalTo("https://graph.facebook.com/me?fields=id,name,email")));
		assertThat(facebook.getProviderDetails().getUserInfoEndpoint().getAuthenticationMethod(), is(AuthenticationMethod.HEADER));
		assertThat(facebook.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName(), is(equalTo("email")));

		//facebook {"clientAuthenticationMethod":{"value":"client_secret_post"}, "redirectUri":"{baseUrl}/{action}/oauth2/code/{registrationId}","scopes":["public_profile","email"],    "providerDetails":{"clientName":"Facebook"}
		//okta     {"clientAuthenticationMethod":{"value":"client_secret_basic"},"redirectUri":"{baseUrl}/{action}/oauth2/code/{registrationId}","scopes":["openid","profile","email"],  "providerDetails":{"issuerUri":null,"configurationMetadata":{}},"clientName":"Okta"}
		//google   {"clientAuthenticationMethod":{"value":"client_secret_basic"},"redirectUri":"{baseUrl}/{action}/oauth2/code/{registrationId}","scopes":["openid","profile","email"],  "providerDetails":{"issuerUri":"https://accounts.google.com","configurationMetadata":{}},"clientName":"Google"}
		//github   {"clientAuthenticationMethod":{"value":"client_secret_basic"},"redirectUri":"{baseUrl}/{action}/oauth2/code/{registrationId}","scopes":["read:user"],                 "providerDetails":{:null,"configurationMetadata":{}},"clientName":"GitHub"}

		// - idp.example.com/issuer/.well-known/openid-configuration
		// - idp.example.com/.well-known/openid-configuration/issuer
		// - idp.example.com/.well-known/oauth-authorization-server/issuer

//		ClientRegistration google = this.clientRegistrationRepository.findByRegistrationId("google").block();
//		ClientRegistration github = this.clientRegistrationRepository.findByRegistrationId("github").block();
//		ClientRegistration okta = this.clientRegistrationRepository.findByRegistrationId("okta").block();
		// {baseUrl}/{action}/oauth2/code/{registrationId}
	}

	@Test
	public void testOauth2AuthorizedClientRepository() {
		assertThat(super.oauth2AuthorizedClientService, is(notNullValue()));
		final OAuth2AuthorizedClient facebook = super.oauth2AuthorizedClientService.loadAuthorizedClient("facebook-login", "justincranford@hotmail.com");
		assertThat(facebook, is(nullValue()));
//		assertThat(facebook, is(notNullValue()));
//		assertThat(facebook.getClientRegistration(), is(notNullValue()));
//		assertThat(facebook.getPrincipalName(),      is(notNullValue()));
//		assertThat(facebook.getAccessToken(),        is(notNullValue()));
//		assertThat(facebook.getRefreshToken(),       is(notNullValue()));
	}
}
