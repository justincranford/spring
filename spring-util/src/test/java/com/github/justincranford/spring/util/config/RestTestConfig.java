package com.github.justincranford.spring.util.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;

@Lazy
@TestConfiguration
//@Profile("!default")
public class RestTestConfig {
	@Bean
	public String baseUrl(
		@Value(value="${server.ssl.enabled:false}")                    final boolean serverSslEnabled,
	    @Value(value="${server.ssl.auto-generate-certificates:false}") final boolean serverSslAutoGenerateCertificates,
	    @Value(value="${server.address}")                              final String  serverAddress,
	    @LocalServerPort                                               final int     localServerPort
	) throws Exception {
	    final boolean useHttps = serverSslEnabled || serverSslAutoGenerateCertificates;
	    final String baseUrl = (useHttps ? "https" : "http") + "://" + serverAddress + ":" + localServerPort;
		return baseUrl;
	}
}