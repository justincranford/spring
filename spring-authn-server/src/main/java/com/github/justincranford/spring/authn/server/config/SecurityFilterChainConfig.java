package com.github.justincranford.spring.authn.server.config;

import static com.github.justincranford.spring.authn.server.model.SimpleGrantedAuthorityNames.OAUTH2_USER;
import static com.github.justincranford.spring.authn.server.model.SimpleGrantedAuthorityNames.OIDC_USER;
import static com.github.justincranford.spring.authn.server.model.SimpleGrantedAuthorityNames.ROLE_APP_ADMIN;
import static com.github.justincranford.spring.authn.server.model.SimpleGrantedAuthorityNames.ROLE_APP_USER;
import static com.github.justincranford.spring.authn.server.model.SimpleGrantedAuthorityNames.ROLE_OPS_ADMIN;
import static com.github.justincranford.spring.authn.server.model.SimpleGrantedAuthorityNames.ROLE_OPS_USER;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.github.justincranford.spring.util.config.EventsConfig;

@Configuration
@EnableWebSecurity
public class SecurityFilterChainConfig {
    @SuppressWarnings("unused")
	private Logger logger = LoggerFactory.getLogger(SecurityFilterChainConfig.class);

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(
        final HttpSecurity http,
        final PasswordEncoder passwordEncoder,
        final ApplicationEventPublisher applicationEventPublisher
    ) throws Exception {
        applicationEventPublisher.publishEvent(new EventsConfig.Event<>("defaultSecurityFilterChain started"));

        final HttpSecurity builder = http
            .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests.requestMatchers(PathRequest.toH2Console()).hasAnyAuthority(ROLE_OPS_ADMIN, ROLE_APP_ADMIN) // Default path: /h2-console
            .requestMatchers("/api/user**").hasAnyAuthority(ROLE_OPS_ADMIN, ROLE_OPS_USER, ROLE_APP_ADMIN, ROLE_APP_USER, OAUTH2_USER, OIDC_USER)
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
}