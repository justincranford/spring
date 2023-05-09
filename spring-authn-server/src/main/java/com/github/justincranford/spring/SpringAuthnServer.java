package com.github.justincranford.spring;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.transaction.annotation.Transactional;

import com.github.justincranford.spring.model.AppUserCrudRepositoryInit;
import com.github.justincranford.spring.model.OpsUserCrudRepositoryInit;

@SpringBootApplication
@Profile({"default"})
public class SpringAuthnServer implements CommandLineRunner {
	private Logger logger = LoggerFactory.getLogger(SpringAuthnServer.class);

	@Autowired Environment               environment;
	@Autowired OpsUserCrudRepositoryInit opsUserCrudRepositoryInit;
	@Autowired AppUserCrudRepositoryInit appUserCrudRepositoryInit;

	public static void main(final String[] args) {
		SpringApplication.run(SpringAuthnServer.class, args);
    }

	// A call to this CommandLineRunner.run is triggered after SpringApplication.run() is started 
	@Transactional
	@Override
	public void run(final String... args) throws Exception {
		logger.info("Active profiles: {}", this.environment.getActiveProfiles().toString());
		// populate default users in DB
		this.opsUserCrudRepositoryInit.run();
		this.appUserCrudRepositoryInit.run();
    }
}
