package com.github.justincranford.spring.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.TimeValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import jakarta.servlet.http.HttpServletRequest;

@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityFilterChainConfig {
    private Logger logger = LoggerFactory.getLogger(SecurityFilterChainConfig.class);

    public static final String ROLE_OPS_ADMIN      = "ROLE_OPS_ADMIN";
    public static final String ROLE_OPS_USER_ADMIN = "ROLE_OPS_USER_ADMIN";
    public static final String ROLE_OPS_USER       = "ROLE_OPS_USER";
    public static final String ROLE_APP_ADMIN      = "ROLE_APP_ADMIN";
    public static final String ROLE_APP_USER_ADMIN = "ROLE_APP_USER_ADMIN";
    public static final String ROLE_APP_USER       = "ROLE_APP_USER";
    public static final String OAUTH2_USER         = "OAUTH2_USER";
    public static final String OIDC_USER           = "OIDC_USER";

    @Value(value="${server.port}")
    public int serverPort;

    @Value(value="${server.ssl.enabled:false}")
    public boolean serverSslEnabled;

    @Value(value="${server.ssl.auto-generate-certificates:false}")
    public boolean serverSslAutoGenerateCertificates;

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(
        final HttpSecurity http,
        final PasswordEncoder passwordEncoder,
        final ApplicationEventPublisher applicationEventPublisher,
        final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> oauth2AccessTokenResponseClient,
        final OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService
//        final OAuth2AuthorizationRequestResolver oauth2AuthorizationRequestResolverWithPkce
    ) throws Exception {
        applicationEventPublisher.publishEvent(new EventsConfig.Event<>("defaultSecurityFilterChain started"));

        // https://docs.spring.io/spring-authorization-server/docs/current/reference/html/configuration-model.html
        final OAuth2AuthorizationServerConfigurer oauth2AuthorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer()
        .clientAuthentication(clientAuthentication ->
            clientAuthentication.authenticationProviders(
                (authenticationProviders) -> authenticationProviders.forEach(
                    (authenticationProvider) -> {
                        if (authenticationProvider instanceof ClientSecretAuthenticationProvider p) {
                            p.setPasswordEncoder(passwordEncoder);
                        }
                    }
                )
            )
        )
        .oidc(oidc -> Customizer.withDefaults())
        ;
//            .userInfoEndpoint(userInfoEndpoint ->
//                userInfoEndpoint
//                    .userInfoRequestConverter(userInfoRequestConverter) 
//                    .userInfoRequestConverters(userInfoRequestConvertersConsumer) 
//                    .authenticationProvider(authenticationProvider) 
//                    .authenticationProviders(authenticationProvidersConsumer) 
//                    .userInfoResponseHandler(userInfoResponseHandler) 
//                    .errorResponseHandler(errorResponseHandler) 
//                    .userInfoMapper(userInfoMapper) 
//            )
//        );
        http.apply(oauth2AuthorizationServerConfigurer);

        final HttpSecurity builder = http
            .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests.requestMatchers(PathRequest.toH2Console()).hasAnyAuthority(ROLE_OPS_ADMIN, ROLE_APP_ADMIN) // Default path: /h2-console
            .requestMatchers("/api/uptime", "/api/profile").hasAnyAuthority(ROLE_OPS_ADMIN, ROLE_OPS_USER, ROLE_OPS_USER_ADMIN, ROLE_APP_ADMIN, ROLE_APP_USER_ADMIN, ROLE_APP_USER, OAUTH2_USER, OIDC_USER)
            .requestMatchers("/api/ops/**").hasAnyAuthority(ROLE_OPS_ADMIN, ROLE_OPS_USER, ROLE_OPS_USER_ADMIN)
            .requestMatchers("/api/app/**").hasAnyAuthority(ROLE_APP_ADMIN, ROLE_APP_USER_ADMIN, ROLE_APP_USER, OAUTH2_USER, OIDC_USER)
            .requestMatchers("/", "/index", "/login", "/error").permitAll().anyRequest().authenticated())
//            .requestMatchers("/**").permitAll().anyRequest().authenticated())
        .formLogin().permitAll()
//      .and().x509().subjectPrincipalRegex("CN=(.*?)(?:,|$)") // "CN=(.*?),"
        .and().httpBasic()
        .and().oauth2Login()
            .tokenEndpoint(tokenEndpoint -> {
                try {
                    tokenEndpoint.accessTokenResponseClient(oauth2AccessTokenResponseClient);
                } catch (Exception e) {
                    this.logger.error(e.getMessage(), e);
                }
            })
//          .authorizationEndpoint()
//              .authorizationRedirectStrategy(
//                  null
//              )
//          .authorizationRequestResolver(
//              oauth2AuthorizationRequestResolverWithPkce(oauth2AuthorizationRequestResolverWithPkce)
//          )
            .userInfoEndpoint(userInfoEndpoint -> {
                try {
                    userInfoEndpoint.userService(oauth2UserService);
                } catch (Exception e) {
                    this.logger.error(e.getMessage(), e);
                }
            })
        .and().logout().deleteCookies("JSESSIONID").invalidateHttpSession(true).permitAll()
        .and().csrf().requireCsrfProtectionMatcher(new AntPathRequestMatcher("/ui/**")).csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and().csrf().disable()
        ;

        // See https://docs.spring.io/spring-security/reference/servlet/architecture.html#servlet-security-filters
        // OAuth2AuthorizationRequestRedirectFilter (authz client redirects to authz server, adds state)
        //  #DefaultRedirectStrategy
        //   DefaultOAuth2AuthorizationRequestResolver
        //   HttpSessionOAuth2AuthorizationRequestRepository
        //  #HttpSessionRequestCache
        // OAuth2LoginAuthenticationFilter (authz server redirects to authz client, adds code)
        //   ClientRegistrationRepository
        //   OAuth2AuthorizedClientRepository
        //   HttpSessionOAuth2AuthorizationRequestRepository
        //  #Converter<OAuth2LoginAuthenticationToken, OAuth2AuthenticationToken>
        // OAuth2AuthorizationCodeGrantFilter
		//   ClientRegistrationRepository
		//   OAuth2AuthorizedClientRepository
		//   AuthenticationManager authenticationManager;
		//   HttpSessionOAuth2AuthorizationRequestRepository
		//   WebAuthenticationDetailsSource
		//  #DefaultRedirectStrategy
		//  #HttpSessionRequestCache

        final DefaultSecurityFilterChain defaultSecurityFilterChain = builder.build();
        applicationEventPublisher.publishEvent(new EventsConfig.Event<>("defaultSecurityFilterChain started"));
        return defaultSecurityFilterChain;
    }

    // spring security core
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    // spring security core
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
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
            final RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID("1").build();
            return new ImmutableJWKSet<>(new JWKSet(rsaKey));
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    // spring security oauth2 core
    @Bean
    public JwtDecoderFactory<ClientRegistration> jwtDecoderFactory(final RestTemplate restTemplate) {
    	return new MyJwtDecoderFactory(restTemplate);
    }

    public class MyJwtDecoderFactory implements JwtDecoderFactory<ClientRegistration> {
        private final Map<String, JwtDecoder> jwtDecoders;
    	private final RestTemplate restTemplate;
    	public MyJwtDecoderFactory(final RestTemplate restTemplate) {
    		this.jwtDecoders = new ConcurrentHashMap<>();
    		this.restTemplate = restTemplate;
    	}
        @Override
        public JwtDecoder createDecoder(final ClientRegistration clientRegistration) {
			final String clientRegistrationJwkSetUri = clientRegistration.getProviderDetails().getJwkSetUri();
            final List<SignatureAlgorithm> signatureAlgorithms = Arrays.asList(SignatureAlgorithm.values());
            return this.jwtDecoders.computeIfAbsent(clientRegistration.getRegistrationId(),
                    (r) -> NimbusJwtDecoder
                            .withJwkSetUri(clientRegistrationJwkSetUri)
                            .restOperations(this.restTemplate)
                            .jwsAlgorithms(algorithms -> algorithms.addAll(signatureAlgorithms))
                            .build());
        }
    }

    // spring security oauth2 authorization client
    // not used?
//    @Bean
//    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
//    	return new HttpSessionOAuth2AuthorizationRequestRepository();
//    }

    // spring security oauth2 authorization client
    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository() {
    	return new HttpSessionOAuth2AuthorizedClientRepository(); // or AuthenticatedPrincipalOAuth2AuthorizedClientRepository?
    }

    // OAuth2ClientRegistrationRepositoryConfiguration creates this bean
    // spring security oauth2 authorization client
//    @Bean
//    public ClientRegistrationRepository clientRegistrationRepository(ClientRegistration... registrations) {
//    	return new InMemoryClientRegistrationRepository(registrations); // cannot be empty
//    }

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
        final ClientRegistrationRepository clientRegistrationRepository,
        final OAuth2AuthorizedClientRepository authorizedClientRepository
    ) {
    	final OAuth2AuthorizedClientProvider authorizedClientProvider =
			OAuth2AuthorizedClientProviderBuilder.builder()
					.authorizationCode()
					.refreshToken()
					.clientCredentials()
//					.password()
					.build();

    	final DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientRepository);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
        // Assuming the `username` and `password` are supplied as `HttpServletRequest` parameters,
        // map the `HttpServletRequest` parameters to `OAuth2AuthorizationContext.getAttributes()`
        authorizedClientManager.setContextAttributesMapper(authorizeRequest -> {
            Map<String, Object> contextAttributes = Collections.emptyMap();
            HttpServletRequest servletRequest = authorizeRequest.getAttribute(HttpServletRequest.class.getName());
            String username = servletRequest.getParameter(OAuth2ParameterNames.USERNAME);
            String password = servletRequest.getParameter(OAuth2ParameterNames.PASSWORD);
            if (StringUtils.hasText(username) && StringUtils.hasText(password)) {
                contextAttributes = new HashMap<>();
                // `PasswordOAuth2AuthorizedClientProvider` requires both attributes
                contextAttributes.put(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, username);
                contextAttributes.put(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, password);
            }
            return contextAttributes;
        });
        return authorizedClientManager;
    }

    // spring security oauth2 authorization client
    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService(final RestTemplate restTemplate) throws Exception {
        final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
        delegate.setRestOperations(restTemplate);
        return request -> delegate.loadUser(request);
    }

    // spring security oauth2 authorization client
    @Bean
    public RestTemplate restTemplate(final HttpClient httpsClient) throws Exception {
        // https://docs.spring.io/spring-security/reference/servlet/oauth2/client/authorization-grants.html#oauth2Client-client-creds-grant
        final RestTemplate restTemplate = new RestTemplate(); // use default converters
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        restTemplate.setRequestFactory(new HttpComponentsClientHttpRequestFactory(httpsClient));
        return restTemplate;
    }

    // spring security oauth2 authorization client
    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient(final HttpClient httpsClient) throws Exception {
        final RestTemplate restTemplate = new RestTemplate(Arrays.asList(new FormHttpMessageConverter(), new OAuth2AccessTokenResponseHttpMessageConverter()));
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        restTemplate.setRequestFactory(new HttpComponentsClientHttpRequestFactory(httpsClient));

        final DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
        accessTokenResponseClient.setRestOperations(restTemplate); 
        return accessTokenResponseClient;
    }

    // spring security oauth2 authorization server
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        final boolean useHttps = (this.serverSslEnabled || this.serverSslAutoGenerateCertificates);
        final RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("internal-oauth2-login")
            .clientName("Internal OAuth2 Login")
            .clientSecret("{noop}secret")
            .clientIdIssuedAt(Instant.now())
            .clientSecretExpiresAt(null)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .redirectUri((useHttps ? "https" : "http") + "://127.0.0.1:" + this.serverPort + "/login/oauth2/code/internal-oauth2-login")
            .scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE)
            .scope("message.read").scope("message.write")
//          .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()) // TODO jwkSetUrl, isRequireProofKey
            .tokenSettings(
                TokenSettings.builder()                              // Defaults below:
                .authorizationCodeTimeToLive(Duration.ofMinutes(2))  // Duration.ofMinutes(5)
                .accessTokenTimeToLive(Duration.ofDays(7))           // Duration.ofMinutes(5)
                .refreshTokenTimeToLive(Duration.ofDays(30))         // Duration.ofMinutes(60)
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED) // OAuth2TokenFormat.SELF_CONTAINED
                .reuseRefreshTokens(false)                           // true
                .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256) // RS256
                .build()
            ).build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    // spring security oauth2 authorization server
    // https://docs.spring.io/spring-authorization-server/docs/current/reference/html/configuration-model.html#configuring-authorization-server-settings
    // @Import(OAuth2AuthorizationServerConfiguration.class) automatically registers an AuthorizationServerSettings @Bean, if not already provided.
    // If the issuer identifier is not configured in AuthorizationServerSettings.builder().issuer(String), it is resolved from the current request.
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
//      return AuthorizationServerSettings.builder().build();
        return AuthorizationServerSettings.builder() // TODO: Issuer URL?
            .authorizationEndpoint("/oauth2/authorize")
            .tokenEndpoint("/oauth2/token")
            .jwkSetEndpoint("/oauth2/jwks")
            .tokenRevocationEndpoint("/oauth2/revoke")
            .tokenIntrospectionEndpoint("/oauth2/introspect")
//          .oidcClientRegistrationEndpoint("/connect/register")
//          .oidcUserInfoEndpoint("/userinfo")
            .build();
    }
    
    // spring security oauth2 authorization server
    @Bean
    public OAuth2AuthorizationService authorizationService(final OAuth2Authorization... authorizations) {
        return new InMemoryOAuth2AuthorizationService(authorizations);
    }

    // spring security oauth2 authorization server
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(final OAuth2AuthorizationConsent... authorizationConsents) {
        return new InMemoryOAuth2AuthorizationConsentService(authorizationConsents);
    }

    // https://docs.spring.io/spring-security/reference/servlet/oauth2/login/advanced.html#oauth2login-advanced-userinfo-endpoint

//    @Bean
//    public OAuth2AuthorizationRequestResolver oauth2AuthorizationRequestResolverWithPkce(final ClientRegistrationRepository clientRegistrationRepository) throws Exception {
//        final ServerWebExchangeMatcher authorizationRequestMatcher = new PathPatternParserServerWebExchangeMatcher("/login/oauth2/authorization/{registrationId}");
//        final OAuth2AuthorizationRequestResolver oauth2AuthorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
//        oauth2AuthorizationRequestResolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
//        return oauth2AuthorizationRequestResolver;
//    }

//    TODO: Add OIDC support in the future?
//    private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
//        final OidcUserService delegate = new OidcUserService();
//
//        return (userRequest) -> {
//            // Delegate to the default implementation for loading a user
//            OidcUser oidcUser = delegate.loadUser(userRequest);
//
//            OAuth2AccessToken accessToken = userRequest.getAccessToken();
//            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
//
//            // TODO
//            // 1) Fetch the authority information from the protected resource using accessToken
//            // 2) Map the authority information to one or more GrantedAuthority's and add it to mappedAuthorities
//
//            // 3) Create a copy of oidcUser but use the mappedAuthorities instead
//            oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
//            return oidcUser;
//        };
//    }

    // TODO
    // @Bean webServerStartStop
    // @Bean webServerGracefulShutdown

    @Bean
	public HttpClient httpsClient() throws Exception {
		final SSLContext sslContext = SSLContextBuilder
            .create()
            .loadTrustMaterial(TrustAllStrategy.INSTANCE) // TODO: Use root CA cert generated by TlsServletWebServerFactoryConfig
            .build();
        final SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(
            sslContext,
            new String[] { "TLSv1.2", "TLSv1.3" },
            null,
            NoopHostnameVerifier.INSTANCE // TODO: HttpsSupport.getDefaultHostnameVerifier()
        );
        final HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
            .setSSLSocketFactory(sslConnectionSocketFactory)
            .setMaxConnTotal(25) // default: 25
            .setMaxConnPerRoute(5) // default: 5
            .setConnectionTimeToLive(TimeValue.ofMinutes(10)) // default: -1 milliseconds
            .build();
        final CloseableHttpClient httpClient = HttpClientBuilder
            .create()
            .setConnectionManager(cm)
            .build();
		return httpClient;
	}
}