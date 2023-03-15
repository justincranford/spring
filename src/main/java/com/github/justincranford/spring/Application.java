package com.github.justincranford.spring;

import java.time.Clock;
import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.transaction.annotation.Transactional;

import com.github.justincranford.spring.model.user.Uptime;
import com.github.justincranford.spring.model.user.app.AppUserCrudRepositoryInit;
import com.github.justincranford.spring.model.user.ops.OpsUserCrudRepositoryInit;

//@EnableTransactionManagement // JTA
//@EnableJpaRepositories("com.github.justincranford.spring.model")
//@EntityScan("com.github.justincranford.spring.model")
@SpringBootApplication // = @Configuration(@Component) + @EnableAutoConfiguration + @EnableWebMvc + @ComponentScan
//@ComponentScan(basePackages={"com.github.justincranford.spring.config","com.github.justincranford.spring.controller"}) // TODO Causes tests to fail
@Profile({"default"}) // TODO "production" doesn't work due to missing servletWebServerFactory() bean
public class Application implements CommandLineRunner {
	private Logger logger = LoggerFactory.getLogger(Application.class);

	@Autowired Environment               environment;
	@Autowired OpsUserCrudRepositoryInit opsUserCrudRepositoryInit;
	@Autowired AppUserCrudRepositoryInit appUserCrudRepositoryInit;

	public static void main(final String[] args) {
		SpringApplication.run(Application.class, args);
//        final SpringApplication application = new SpringApplication(Application.class);
//        application.setBannerMode(Banner.Mode.OFF);
//        application.run(args);
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

    @Bean
    public Uptime.Factory uptimeFactory() {
		return new Uptime.Factory(Instant.now(Clock.systemUTC()));
    }

//	@Bean
//	public PlatformTransactionManager transactionManager(final DataSource dataSource, final LocalContainerEntityManagerFactoryBean entityManagerFactory) {
//		switch (TRANSACTION_MANAGER) {
//		case JTA: {
//			final JtaTransactionManager jtaTransactionManager = new JtaTransactionManager();
//			// TODO Specify either userTransaction or 'transactionManager
//			// <jee:jndi-lookup id="dataSource" jndi-name="jdbc/jpetstore"/>
//			return jtaTransactionManager;
//		}
//		case DSTM: {
//			return new DataSourceTransactionManager(dataSource);
//		}
//		case JDBC: {
//			return new JdbcTransactionManager(dataSource);
//		}
//		case HTM: {
//			final HibernateTransactionManager hibernateTransactionManager = new HibernateTransactionManager();
////			hibernateTransactionManager.setSessionFactory(sessionFactory().getObject());
//			hibernateTransactionManager.setDataSource(dataSource);
//			return hibernateTransactionManager;
//		}
//		case JPA: {
//			final JpaTransactionManager jpaTransactionManager = new JpaTransactionManager();
//			jpaTransactionManager.setEntityManagerFactory(entityManagerFactory.getObject());
//			jpaTransactionManager.setDataSource(dataSource);
//			return jpaTransactionManager;
//		}
//		default:
//			throw new RuntimeException("No TransactionManager selected");
//		}
//	}
//
//	private static final TransactionManager TRANSACTION_MANAGER = TransactionManager.JPA;
//
//	enum TransactionManager {
//		JTA, // TODO
//		DSTM, // WORKS
//		JDBC, // WORKS
//		HTM, // TODO
//		JPA // WORKS
//	};

	// Mutually exclusive: entityManagerFactory() vs sessionFactory()
//	@Bean
//	public LocalContainerEntityManagerFactoryBean entityManagerFactory(
//		final DataSource dataSource,
//		JpaVendorAdapter jpaVendorAdapter
//	) {
//		final LocalContainerEntityManagerFactoryBean emf = new LocalContainerEntityManagerFactoryBean();
//		emf.setDataSource(dataSource);
//		emf.setPackagesToScan("com.github.justincranford.spring");
//		emf.setJpaVendorAdapter(jpaVendorAdapter);
////		emf.setJpaProperties(this.getHibernateProperties());
//		return emf;
//	}

	// Mutually exclusive: entityManagerFactory() vs sessionFactory()
//	@Bean
//	public LocalSessionFactoryBean sessionFactory(final DataSource dataSource) {
//		final LocalSessionFactoryBean sf = new LocalSessionFactoryBean();
//		sf.setDataSource(dataSource);
////		sf.setMappingResources("schema.hbm.xml");
//		sf.setHibernateProperties(getHibernateProperties());
//		return sf;
//	}

//	@Bean
//	public WebMvcConfigurer corsConfigurer() {
//		return new WebMvcConfigurer() {
//			@Override
//			public void addCorsMappings(CorsRegistry registry) {
//				registry.addMapping("/api").allowedOrigins("https://localhost:8443");
//			}
//		};
//	}
}
