package com.github.justincranford.spring.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityFilterChainConfig {
    @SuppressWarnings("unused")
	private Logger logger = LoggerFactory.getLogger(SecurityFilterChainConfig.class);

    public static final String ROLE_OPS_ADMIN      = "ROLE_OPS_ADMIN";
    public static final String ROLE_OPS_USER       = "ROLE_OPS_USER";
    public static final String ROLE_APP_ADMIN      = "ROLE_APP_ADMIN";
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
        final ApplicationEventPublisher applicationEventPublisher
    ) throws Exception {
        applicationEventPublisher.publishEvent(new EventsConfig.Event<>("defaultSecurityFilterChain started"));

        final HttpSecurity builder = http
            .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests.requestMatchers(PathRequest.toH2Console()).hasAnyAuthority(ROLE_OPS_ADMIN, ROLE_APP_ADMIN) // Default path: /h2-console
            .requestMatchers("/api/ops/**").hasAnyAuthority(ROLE_OPS_ADMIN, ROLE_OPS_USER)
            .requestMatchers("/api/app/**").hasAnyAuthority(ROLE_APP_ADMIN, ROLE_APP_USER, OAUTH2_USER, OIDC_USER)
            .requestMatchers("/", "/index", "/login", "/error").permitAll()
            .anyRequest().authenticated())
        .formLogin().permitAll()
//      .and().x509().subjectPrincipalRegex("CN=(.*?)(?:,|$)") // "CN=(.*?),"
        .and().httpBasic()
        .and().logout().logoutSuccessUrl("/").deleteCookies("JSESSIONID").invalidateHttpSession(true).permitAll()
        .and().csrf().requireCsrfProtectionMatcher(new AntPathRequestMatcher("/ui/**")).csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and().csrf().disable()
        ;

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
}