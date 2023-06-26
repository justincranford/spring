package com.github.justincranford.spring.authz.client;

import javax.net.ssl.SSLContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;

import com.github.justincranford.spring.util.config.TlsConfig.TlsSettings;

@SpringBootTest(classes={SpringAuthzClient.class}, webEnvironment=WebEnvironment.RANDOM_PORT, properties={"spring.main.allow-bean-definition-overriding=true"})
@TestPropertySource(properties = {"management.port=0"})
@ComponentScan(basePackages={"com.github.justincranford.spring"})
@ContextConfiguration
//@ActiveProfiles(profiles = { "default","test" })
public class AbstractIT extends com.github.justincranford.spring.AbstractIT {
	@Autowired(required=false) protected SSLContext         clientSslContext;
	@Autowired                 protected TlsSettings        tlsSettings;
}
