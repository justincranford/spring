package com.github.justincranford.spring.configuration.security;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Scanner;
import java.util.UUID;

import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
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
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.client.RestTemplate;
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

	public static final String OPS_ADMIN = "OPS_ADMIN";
	public static final String OPS_USER_ADMIN = "OPS_USER_ADMIN";
	public static final String OPS_USER = "OPS_USER";
	public static final String APP_ADMIN = "APP_ADMIN";
	public static final String APP_USER_ADMIN = "APP_USER_ADMIN";
	public static final String APP_USER = "APP_USER";
	public static final String OAUTH2_USER = "OAUTH2_USER";
	public static final String OIDC_USER = "OIDC_USER";

//	@Bean
//	@Order(1)
//	public SecurityFilterChain authorizationServerSecurityFilterChain(final HttpSecurity http) throws Exception {
////		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
//		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
////		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
////		http.exceptionHandling((exceptions) -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
////		http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
//		return http.build();
//	}

	@Bean
	@Order(2)
	public SecurityFilterChain defaultSecurityFilterChain(final HttpSecurity http) throws Exception {
		// TODO de-duplicate SecurityFilterChainConfiguration and
		// OAuth2ServerConfiguration
//		final PortMapperImpl portMapper = new PortMapperImpl();
//		portMapper.setPortMappings(Collections.singletonMap("8080", "8443"));
//		final PortResolverImpl portResolver = new PortResolverImpl();
//		portResolver.setPortMapper(portMapper);
//		final LoginUrlAuthenticationEntryPoint entryPoint = new LoginUrlAuthenticationEntryPoint("/login");
//		entryPoint.setPortMapper(portMapper);
//		entryPoint.setPortResolver(portResolver);

//		org.springframework.security.web.session.DisableEncodeUrlFilter
//		org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter
//		org.springframework.security.web.context.SecurityContextHolderFilter
//		org.springframework.security.web.header.HeaderWriterFilter
//		org.springframework.security.web.authentication.logout.LogoutFilter
//		org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter
//		org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter
//		org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter
//		org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
//		org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter
//		org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter
//		org.springframework.security.web.authentication.www.BasicAuthenticationFilter
//		org.springframework.security.web.savedrequest.RequestCacheAwareFilter
//		org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
//		org.springframework.security.web.authentication.AnonymousAuthenticationFilter
//		org.springframework.security.web.access.ExceptionTranslationFilter
//		org.springframework.security.web.access.intercept.AuthorizationFilter

		http.authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests.requestMatchers(PathRequest.toH2Console()).hasAnyAuthority(OPS_ADMIN, APP_ADMIN) // Default path: /h2-console
			.requestMatchers("/api/uptime/**", "/api/profile**").hasAnyAuthority(OPS_ADMIN, OPS_USER, OPS_USER_ADMIN, APP_ADMIN, APP_USER, OAUTH2_USER, OIDC_USER)
			.requestMatchers("/api/ops/**", "/api/app/**").hasAnyAuthority(OPS_ADMIN, OPS_USER, OPS_USER_ADMIN)
//			.requestMatchers("/", "/ui/index", "/ui/error", "/ui/login/prompt", "/ui/login/verify").permitAll()
			.requestMatchers("/", "/index", "/login", "/error").permitAll().anyRequest().authenticated())
		// Request parameters => username=value1&password=value2
//		.loginPage("/login")
			.formLogin().permitAll()// .defaultSuccessUrl("/authenticated",
									// true).failureUrl("/login?error").permitAll() // Request parameters =>
									// username=value1&password=value2
//		.and()
//			.x509().subjectPrincipalRegex("CN=(.*?)(?:,|$)") // "CN=(.*?),"
			.and().httpBasic() // Request header => Authorization: Basic Base64(username:password)
			.and()
			// /oauth2/authorization/clientId => start code grant workflow, pick client to
			// do external auth redirect
			// /login/oauth2/code/* => finish code grant workflow, wrap code in token for
			// client to send for verify
			.oauth2Login()// .defaultSuccessUrl("/")
//		    	.loginPage("/login/oauth2")
//		        .authorizationEndpoint()
			// .loginProcessingUrl("/login/oauth2/verify")//.defaultSuccessUrl("/").failureUrl("/login/oauth2?error")
//		.and()
//			.oauth2Client(oauth2 -> oauth2
//				.clientRegistrationRepository(this.clientRegistrationRepository())
//				.authorizedClientRepository(this.authorizedClientRepository())
//				.authorizationRequestRepository(this.authorizationRequestRepository())
//				.authenticationConverter(this.authenticationConverter())
//				.authenticationManager(this.authenticationManager())
//			)
			.and().logout().deleteCookies("JSESSIONID").invalidateHttpSession(true).permitAll()
			// .logoutUrl("/logout").logoutSuccessUrl("/login?logout").clearAuthentication(true)
			.and().csrf().requireCsrfProtectionMatcher(new AntPathRequestMatcher("/ui/**")).csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and().csrf().disable()
			// Enable OpenID Connect 1.0
//			.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults())
			// Accept access tokens for User Info and/or Client Registration
//			.and()
//			.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
//			.oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken)
			// Login HTTP => HTTPS port mapping
//			.exceptionHandling((exceptions) -> exceptions.authenticationEntryPoint(entryPoint))
//			.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
			.apply(new OAuth2AuthorizationServerConfigurer());
		;

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
			final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
			final RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
			final RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
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
//			.clientIdIssuedAt(Instant.now())
			.clientId("internal-oauth2-login")
//			.clientName("internal-oauth2-login")
			.clientSecret("{noop}secret")
//			.clientSecretExpiresAt(null)
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.redirectUri("https://127.0.0.1:8443/login/oauth2/code/internal-oauth2-login").redirectUri("https://127.0.0.1:8443/oauth2/token").scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE)
			.scope("message.read").scope("message.write")
//			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//			.tokenSettings(TokenSettings.builder().authorizationCodeTimeToLive(Duration.ofMinutes(5)).build())
			.build();

		final InMemoryRegisteredClientRepository inMemoryRegisteredClientRepository = new InMemoryRegisteredClientRepository(registeredClient);
//		inMemoryRegisteredClientRepository.save(registeredClient);
		return inMemoryRegisteredClientRepository;
	}

	// https://docs.spring.io/spring-authorization-server/docs/current/reference/html/configuration-model.html#configuring-authorization-server-settings
	// @Import(OAuth2AuthorizationServerConfiguration.class) automatically registers
	// an AuthorizationServerSettings @Bean, if not already provided.
	// If the issuer identifier is not configured in
	// AuthorizationServerSettings.builder().issuer(String), it is resolved from the
	// current request.
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
//		return AuthorizationServerSettings.builder()
//			.authorizationEndpoint("/oauth2/authorize")
//			.tokenEndpoint("/oauth2/token")
//			.jwkSetEndpoint("/oauth2/jwks")
//			.tokenRevocationEndpoint("/oauth2/revoke")
//			.tokenIntrospectionEndpoint("/oauth2/introspect")
//			.oidcClientRegistrationEndpoint("/connect/register")
//			.oidcUserInfoEndpoint("/userinfo")
//			.build();
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

//	@Bean
//	public ProviderSettings providerSettings() {
//	    return ProviderSettings.builder()
//	      .issuer("http://auth-server:9000")
//	      .build();
//	}

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

//	@ConfigurationProperties("rest.ssl")
//	@Data
//	public class SecureRestTemplateProperties {
//	  String trustStore;
//	  char[] trustStorePassword;
//	  String protocol = "TLSv1.2";
//	}	

	@Bean
	public RestTemplate restTemplate(RestTemplateBuilder builder) throws Exception {
		final SSLContext sslContext = SSLContextBuilder
			.create()
			.loadTrustMaterial(TrustAllStrategy.INSTANCE)
			.build();
		final SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(
			sslContext,
			new String[] { "TLSv1.2", "TLSv1.3" },
			null,
			NoopHostnameVerifier.INSTANCE//HttpsSupport.getDefaultHostnameVerifier()
		);
        final HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
	    	.setSSLSocketFactory(sslConnectionSocketFactory)
            .build();
                    
	    final CloseableHttpClient httpClient = HttpClientBuilder
	    	.create()
	    	.setConnectionManager(cm)
	    	.build();

//	    final HttpGet httpGet = new HttpGet("https://www.google.com/");
//	    final CloseableHttpResponse httpResponse = httpClient.execute(httpGet);
//		final int responseCode = httpResponse.getCode();
//		System.out.println("responseCode: " + responseCode);
//		final HttpEntity httpEntity = httpResponse.getEntity();
//	    final InputStream content = httpEntity.getContent();
//		final Scanner sc = new Scanner(content);
//		while (sc.hasNext()) {
//			System.out.println(sc.nextLine());
//		}
	      
	    final ClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
		return new RestTemplate(requestFactory);
//		return builder.build();
	}
}