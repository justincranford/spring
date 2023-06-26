package com.github.justincranford.spring.authz.client;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Profile;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
@Profile({"default"})
@EnableJpaRepositories({"com.github.justincranford.spring.*"})
@ComponentScan({"com.github.justincranford.spring.*"})
@EntityScan({"com.github.justincranford.spring.*"})
@ConfigurationPropertiesScan({"com.github.justincranford.spring.*"})
@EnableMethodSecurity
public class SpringAuthzClient {
	public static void main(final String[] args) {
		SpringApplication.run(SpringAuthzClient.class, args);
    }
}
