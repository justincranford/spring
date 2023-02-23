package com.github.justincranford.spring.configuration.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.reactive.function.client.WebClient;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityFilterChainConfiguration {
	private Logger logger = LoggerFactory.getLogger(SecurityFilterChainConfiguration.class);

	public static final String OPS_ADMIN       = "OPS_ADMIN";
	public static final String OPS_USER_ADMIN  = "OPS_USER_ADMIN";
	public static final String OPS_USER        = "OPS_USER";
	public static final String APP_ADMIN       = "APP_ADMIN";
	public static final String APP_USER_ADMIN  = "APP_USER_ADMIN";
	public static final String APP_USER	       = "APP_USER";
	public static final String OAUTH2_USER     = "OAUTH2_USER";
	public static final String OIDC_USER       = "OIDC_USER";

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {
		//TODO de-duplicate SecurityFilterChainConfiguration and OAuth2ServerConfiguration
//		final PortMapperImpl portMapper = new PortMapperImpl();
//		portMapper.setPortMappings(Collections.singletonMap("8080", "8443"));
//		final PortResolverImpl portResolver = new PortResolverImpl();
//		portResolver.setPortMapper(portMapper);
//		final LoginUrlAuthenticationEntryPoint entryPoint = new LoginUrlAuthenticationEntryPoint("/login");
//		entryPoint.setPortMapper(portMapper);
//		entryPoint.setPortResolver(portResolver);

//		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

		http.authorizeHttpRequests()
				.requestMatchers(PathRequest.toH2Console()).hasAnyAuthority(OPS_ADMIN,APP_ADMIN)	// Default path: /h2-console
				.requestMatchers("/api/uptime/**").hasAnyAuthority(OPS_ADMIN,OPS_USER,OPS_USER_ADMIN,APP_ADMIN,APP_USER,OAUTH2_USER,OIDC_USER)
				.requestMatchers("/api/profile**").hasAnyAuthority(OPS_ADMIN,OPS_USER,OPS_USER_ADMIN,APP_ADMIN,APP_USER,OAUTH2_USER,OIDC_USER)
				.requestMatchers("/api/ops/**").hasAnyAuthority(OPS_ADMIN,OPS_USER,OPS_USER_ADMIN)
				.requestMatchers("/api/app/**").hasAnyAuthority(APP_ADMIN,APP_USER_ADMIN,APP_USER)
//				.requestMatchers("/", "/ui/index", "/ui/error", "/ui/login/prompt", "/ui/login/verify").permitAll()
				.requestMatchers("/", "/index", "/login", "/error").permitAll()
				.anyRequest().authenticated()
			.and()
//				.formLogin().loginPage("/ui/login/prompt").loginProcessingUrl("/us/login/verify").defaultSuccessUrl("/authenticated", true).failureUrl("/login?error=true").permitAll()	// Request parameters => username=value1&password=value2
				.formLogin()	// Request parameters => username=value1&password=value2
			.and()
				.httpBasic()				// Request header => Authorization: Basic Base64(username:password)
			.and()
				.formLogin().permitAll()	// Request parameters => username=value1&password=value2
			.and()
				.x509().subjectPrincipalRegex("CN=(.*?)(?:,|$)") // "CN=(.*?),"
			.and()
				.oauth2Login()
//				    	.loginPage("/login/oauth2")
//				        .authorizationEndpoint().baseUri("/oauth2/authorization")
	                //.loginProcessingUrl("/login")//.defaultSuccessUrl("/").failureUrl("/")
//			.and()
//				.oauth2Client(oauth2 -> oauth2
//					.clientRegistrationRepository(this.clientRegistrationRepository())
//					.authorizedClientRepository(this.authorizedClientRepository())
//					.authorizationRequestRepository(this.authorizationRequestRepository())
//					.authenticationConverter(this.authenticationConverter())
//					.authenticationManager(this.authenticationManager())
//				)
			.and()
				.logout().deleteCookies("JSESSIONID").invalidateHttpSession(true).logoutSuccessUrl("/").permitAll()
//				.logoutUrl("/")
			.and()
				.csrf().requireCsrfProtectionMatcher(new AntPathRequestMatcher("/ui/**"))
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
			.and()
				.csrf().disable()
			// Enable OpenID Connect 1.0
//			.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults())
			// Accept access tokens for User Info and/or Client Registration
//			.and()
//			.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
			// Login HTTP => HTTPS port mapping
//			.exceptionHandling((exceptions) -> exceptions.authenticationEntryPoint(entryPoint))
//			.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
//			.apply(authorizationServerConfigurer)
			;


		// OAuth2
//		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		return http.build();
	}

	// spring security core
	@Bean
	SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

	// spring security core
	@Bean
	HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}

	// spring security oauth2 core
	@Bean 
	public JWKSource<SecurityContext> jwkSource() {
		try {
			final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", Security.getProvider("SunRsaSign"));
			keyPairGenerator.initialize(2048);
			final KeyPair keyPair = keyPairGenerator.generateKeyPair();
			final RSAPublicKey  publicKey  = (RSAPublicKey)  keyPair.getPublic();
			final RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
			final RSAKey        rsaKey     = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
			return new ImmutableJWKSet<>(new JWKSet(rsaKey));
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	// spring security oauth2 core
	@Bean 
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	// spring security oauth2 authorization server
	@Bean 
	public RegisteredClientRepository registeredClientRepository() {
		final RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
			.clientIdIssuedAt(Instant.now())
			.clientId("internal-oauth2-login")
			.clientName("internal-oauth2-login")
			.clientSecret("{noop}secret")
			.clientSecretExpiresAt(null)
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.redirectUri("https://127.0.0.1:8443/login/oauth2/code/internal-oauth2-login")
			.redirectUri("https://127.0.0.1:8443")
			.scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE).scope("message.read").scope("message.write")
			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//			.tokenSettings(TokenSettings.builder().authorizationCodeTimeToLive(Duration.ofMinutes(5)).build())
			.build();

		final InMemoryRegisteredClientRepository inMemoryRegisteredClientRepository = new InMemoryRegisteredClientRepository(registeredClient);
//		inMemoryRegisteredClientRepository.save(registeredClient);
		return inMemoryRegisteredClientRepository;
	}

	// spring security oauth2 authorization server
//	@Bean
//	public AuthorizationServerSettings authorizationServerSettings() {
//		return AuthorizationServerSettings.builder()
//			.issuer("https://localhost:8443")
//			.authorizationEndpoint("https://localhost:8443/oauth2/v1/authorize")
//			.tokenEndpoint("https://localhost:8443/oauth2/v1/token")
//			.tokenIntrospectionEndpoint("https://localhost:8443/oauth2/v1/introspect")
//			.tokenRevocationEndpoint("https://localhost:8443/oauth2/v1/revoke")
//			.jwkSetEndpoint("https://localhost:8443/oauth2/v1/jwks")
//			.oidcUserInfoEndpoint("https://localhost:8443/connect/v1/userinfo")
//			.oidcClientRegistrationEndpoint("https://localhost:8443/connect/v1/register")
//			.build();
//	}

	// https://docs.spring.io/spring-authorization-server/docs/current/reference/html/configuration-model.html#configuring-authorization-server-settings
	// @Import(OAuth2AuthorizationServerConfiguration.class) automatically registers an AuthorizationServerSettings @Bean, if not already provided.
	// If the issuer identifier is not configured in AuthorizationServerSettings.builder().issuer(String), it is resolved from the current request.
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder()
			.authorizationEndpoint("/oauth2/authorize")
			.tokenEndpoint("/oauth2/token")
			.tokenIntrospectionEndpoint("/oauth2/introspect")
			.tokenRevocationEndpoint("/oauth2/revoke")
			.jwkSetEndpoint("/oauth2/jwks")
			.oidcUserInfoEndpoint("/userinfo")
			.oidcClientRegistrationEndpoint("/connect/register")
			.build();
	}

	// spring security oauth2 authorization server
	@Bean
	public OAuth2AuthorizationService authorizationService(OAuth2Authorization... authorizations) {
		return new InMemoryOAuth2AuthorizationService(authorizations);
	}

	// spring security oauth2 authorization server
	@Bean
	public OAuth2AuthorizationConsentService authorizationConsentService(OAuth2AuthorizationConsent... authorizationConsents) {
		return new InMemoryOAuth2AuthorizationConsentService(authorizationConsents);
	}

	// spring security oauth2 client
	@Bean
	public WebClient webClient(ClientRegistrationRepository clients, OAuth2AuthorizedClientRepository authz) {
		final ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 = new ServletOAuth2AuthorizedClientExchangeFilterFunction(clients, authz);
		return WebClient.builder().filter(oauth2).build();
	}

	// spring security oauth2 client
	@Bean
	public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService(final WebClient webClient) {
		final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
		return request -> {
			OAuth2User user = delegate.loadUser(request);
//			if (!"github".equals(request.getClientRegistration().getRegistrationId())) {
//				return user;
//			}
			final String login = user.getAttribute("login");
			this.logger.info("OAuth2 login: {}", login);
			return user;

//			OAuth2AuthorizedClient client = new OAuth2AuthorizedClient(request.getClientRegistration(), user.getName(), request.getAccessToken());
//			String url = user.getAttribute("organizations_url");
//			List<Map<String, Object>> orgs = rest
//					.get().uri(url)
//					.attributes(oauth2AuthorizedClient(client))
//					.retrieve()
//					.bodyToMono(List.class)
//					.block();
//
//			if (orgs.stream().anyMatch(org -> "spring-projects".equals(org.get("login")))) {
//				return user;
//			}
//
//			throw new OAuth2AuthenticationException(new OAuth2Error("invalid_token", "Not in Spring Team", ""));
		};
	}

	// spring security oauth2 resource server

//	@Bean
//	SecurityWebFilterChain springSecurityFilterChain(final ServerHttpSecurity serverHttpSecurity) {
//		serverHttpSecurity
//			.authorizeExchange(exchanges -> exchanges.anyExchange().authenticated())
//			.oauth2ResourceServer(ServerHttpSecurity.OAuth2ResourceServerSpec::opaqueToken);
//		return serverHttpSecurity.build();
//	}
}