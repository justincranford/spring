package com.github.justincranford.spring.authn.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Profile;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@Profile({"default"})
@EnableJpaRepositories("com.github.justincranford.spring.*")
@ComponentScan(basePackages={"com.github.justincranford.spring.*"})
@EntityScan("com.github.justincranford.spring.*")
@ConfigurationPropertiesScan({"com.github.justincranford.spring.*"})
public class SpringAuthnServer {
	public static void main(final String[] args) {
		SpringApplication.run(SpringAuthnServer.class, args);
    }
}
